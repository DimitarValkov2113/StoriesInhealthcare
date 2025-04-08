require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const { Pinecone } = require('@pinecone-database/pinecone');
const OpenAI = require('openai');
const cors = require('cors');
const { query, validationResult } = require('express-validator');
const winston = require('winston');

// Constants
const PORT = process.env.PORT || 5002;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const STORY_TABLE = 'Stories';
const PINECONE_INDEX_NAME = 'stories';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Fallback for local dev
const SEARCH_TOP_K = 10;

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'search-service.log' }),
  ],
});

// Custom Error Classes
class UnauthorizedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UnauthorizedError';
    this.status = 401;
  }
}

class BadRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BadRequestError';
    this.status = 400;
  }
}

class DatabaseError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'DatabaseError';
    this.status = 500;
    this.cause = cause;
  }
}

class EmbeddingError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'EmbeddingError';
    this.status = 500;
    this.cause = cause;
  }
}

class VectorSearchError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'VectorSearchError';
    this.status = 500;
    this.cause = cause;
  }
}

// Dependency Injection
const createDynamoDBClient = (config = {}) => {
  AWS.config.update({
    region: AWS_REGION,
    accessKeyId: config.accessKeyId || process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: config.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
  });
  return new AWS.DynamoDB.DocumentClient();
};

const createPineconeClient = (apiKey = process.env.PINECONE_API_KEY) => {
  return new Pinecone({ apiKey });
};

const createOpenAIClient = (apiKey = process.env.OPENAI_API_KEY) => {
  return new OpenAI({ apiKey });
};

// Data Access Layer
const dataAccess = (dynamoDB, pineconeIndex, openai) => ({
  /**
   * Generates an embedding vector for the given text using OpenAI.
   * @param {string} text - Text to embed.
   * @returns {Promise<number[]>} - Embedding vector.
   */
  generateEmbedding: async (text) => {
    try {
      const response = await openai.embeddings.create({
        model: 'text-embedding-ada-002',
        input: text,
      });
      return response.data[0].embedding;
    } catch (error) {
      throw new EmbeddingError('Failed to generate embedding', error);
    }
  },

  /**
   * Queries Pinecone for similar stories based on a vector.
   * @param {number[]} vector - Query vector.
   * @param {number} topK - Number of matches to return.
   * @returns {Promise<object[]>} - Array of Pinecone match objects.
   */
  querySimilarStories: async (vector, topK = SEARCH_TOP_K) => {
    try {
      const response = await pineconeIndex.query({
        vector,
        topK,
        includeMetadata: true,
      });
      return response.matches;
    } catch (error) {
      throw new VectorSearchError('Failed to query Pinecone index', error);
    }
  },

  /**
   * Fetches a story by ID from DynamoDB.
   * @param {string} storyId - The story ID.
   * @returns {Promise<object>} - The story object.
   */
  getStoryById: async (storyId) => {
    const params = {
      TableName: STORY_TABLE,
      Key: { storyId },
    };
    try {
      const { Item } = await dynamoDB.get(params).promise();
      if (!Item) throw new DatabaseError(`Story with ID ${storyId} not found`);
      return Item;
    } catch (error) {
      throw new DatabaseError(`Failed to fetch story ${storyId}`, error);
    }
  },
});

// Service Layer
const searchService = (dataAccess) => ({
  /**
   * Searches for stories based on a query string.
   * @param {string} query - The search query.
   * @returns {Promise<object[]>} - Array of search results with story details.
   */
  searchStories: async (query) => {
    try {
      // Generate embedding for the query
      const queryVector = await dataAccess.generateEmbedding(query);
      logger.info('Generated embedding for query', { query });

      // Query Pinecone for similar stories
      const pineconeMatches = await dataAccess.querySimilarStories(queryVector);
      const storyIds = pineconeMatches.map((match) => match.id);
      logger.info('Queried Pinecone', { storyIds });

      // Fetch story details from DynamoDB
      const storyPromises = storyIds.map((storyId) => dataAccess.getStoryById(storyId));
      const stories = await Promise.all(storyPromises);

      // Combine Pinecone metadata and DynamoDB data
      const results = stories.map((story, index) => {
        const pineconeMatch = pineconeMatches[index];
        return {
          storyId: story.storyId,
          title: pineconeMatch.metadata.title,
          userId: pineconeMatch.metadata.userId,
          tags: pineconeMatch.metadata.tags?.split(',') || [],
          timestamp: pineconeMatch.metadata.timestamp,
          content: story.content,
        };
      });

      logger.info('Search completed', { query, resultCount: results.length });
      return results;
    } catch (error) {
      logger.error('Search failed', { query, error });
      throw error;
    }
  },
});

// Middleware
const authenticate = (secret = JWT_SECRET) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new UnauthorizedError('Access Denied: No token provided'));
  }
  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, secret);
    logger.info('User authenticated', { userId: req.user.userId });
    next();
  } catch (error) {
    logger.warn('Invalid token', { error });
    next(new UnauthorizedError('Invalid or expired token'));
  }
};

const validateSearchQuery = [
  query('query').trim().notEmpty().withMessage('Query parameter is required'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return next(new BadRequestError(errors.array()[0].msg));
    }
    next();
  },
];

// Error Handling Middleware
const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  logger.error(`${req.method} ${req.url} failed`, { status, message, stack: err.stack });
  res.status(status).json({ error: message });
};

// Route Handlers
const createSearchRoutes = (searchService) => {
  const router = express.Router();

  router.get('/health', authenticate(), (req, res) => {
    res.json({ status: 'Search Service is running' });
  });

  router.get('/search', validateSearchQuery, async (req, res, next) => {
    const { query } = req.query;
    try {
      const results = await searchService.searchStories(query);
      res.json({ results });
    } catch (error) {
      next(error);
    }
  });

  return router;
};

// Application Setup
const initializeApp = ({
  dynamoDBClient = createDynamoDBClient(),
  pineconeClient = createPineconeClient(),
  openaiClient = createOpenAIClient(),
} = {}) => {
  const app = express();
  const pineconeIndex = pineconeClient.Index(PINECONE_INDEX_NAME);
  const dbLayer = dataAccess(dynamoDBClient, pineconeIndex, openaiClient);
  const serviceLayer = searchService(dbLayer);
  const searchRoutes = createSearchRoutes(serviceLayer);

  app.use(express.json());
  app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
  app.use('/api', searchRoutes); // Mount under /api for versioning
  app.use(errorHandler);

  return app;
};

// Start Server
const startServer = async () => {
  const app = initializeApp();
  app.listen(PORT, () => {
    logger.info(`Search Service running on port ${PORT}`);
  });
};

// Graceful Shutdown
const shutdown = () => {
  logger.info('Shutting down Search Service');
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

module.exports = { initializeApp, searchService, dataAccess }; // For testing