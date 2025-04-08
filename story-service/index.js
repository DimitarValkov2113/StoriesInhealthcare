require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const leoProfanity = require('leo-profanity');
const { Pinecone } = require('@pinecone-database/pinecone');
const OpenAI = require('openai');
const { body, validationResult } = require('express-validator');
const winston = require('winston');

// Constants
const PORT = process.env.PORT || 3000;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const STORY_TABLE = 'Stories';
const PINECONE_INDEX_NAME = 'stories';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const STORY_RATE_LIMIT = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 stories per window
};

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'story-service.log' }),
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

class VectorStoreError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'VectorStoreError';
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
   * Creates a story in DynamoDB.
   * @param {object} story - The story object to store.
   * @returns {Promise<object>} - The created story.
   */
  createStory: async (story) => {
    const params = {
      TableName: STORY_TABLE,
      Item: story,
      ConditionExpression: 'attribute_not_exists(storyId)',
    };
    try {
      await dynamoDB.put(params).promise();
      return story;
    } catch (error) {
      throw new DatabaseError('Failed to create story', error);
    }
  },

  /**
   * Fetches stories by user ID from DynamoDB using the userId-index GSI.
   * @param {string} userId - The user's ID.
   * @returns {Promise<object[]>} - Array of user stories.
   */
  getUserStories: async (userId) => {
    const params = {
      TableName: STORY_TABLE,
      IndexName: 'userId-index', // Use the GSI
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
    };
    try {
      const { Items } = await dynamoDB.query(params).promise();
      return Items || [];
    } catch (error) {
      throw new DatabaseError(`Failed to fetch stories for user ${userId} via GSI`, error);
    }
  },

  /**
   * Fetches public, non-flagged stories from DynamoDB using the isFlagged-index GSI.
   * @returns {Promise<object[]>} - Array of public stories.
   */
  getPublicStories: async () => {
    const params = {
      TableName: STORY_TABLE,
      IndexName: 'isFlagged-index', // Use the GSI
      KeyConditionExpression: 'isFlagged = :value',
      ExpressionAttributeValues: { ':value': 0 }, // 0 = not flagged
    };
    try {
      const { Items } = await dynamoDB.query(params).promise();
      return Items || [];
    } catch (error) {
      throw new DatabaseError('Failed to fetch public stories via GSI', error);
    }
  },

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
   * Upserts a vector into Pinecone.
   * @param {object} vectorData - Vector data with id, values, and metadata.
   * @returns {Promise<void>}
   */
  upsertVector: async (vectorData) => {
    try {
      await pineconeIndex.upsert([vectorData]);
    } catch (error) {
      throw new VectorStoreError('Failed to upsert vector to Pinecone', error);
    }
  },

  /**
   * Queries Pinecone for similar stories.
   * @param {number[]} vector - Query vector.
   * @param {number} topK - Number of matches to return.
   * @returns {Promise<object>} - Pinecone query response.
   */
  querySimilarStories: async (vector, topK = 10) => {
    try {
      return await pineconeIndex.query({
        vector,
        topK,
        includeMetadata: true,
      });
    } catch (error) {
      throw new VectorStoreError('Failed to query Pinecone', error);
    }
  },
});

// Service Layer
const storyService = (dataAccess, uuidGenerator = uuidv4) => ({
  /**
   * Creates a new story with profanity check and vector storage.
   * @param {string} userId - The user's ID.
   * @param {string} title - Story title.
   * @param {string} content - Story content.
   * @param {string[]} tags - Story tags.
   * @returns {Promise<object>} - Created story details.
   */
  createStory: async (userId, title, content, tags = []) => {
    const storyId = uuidGenerator();
    const timestamp = new Date().toISOString();

    const isFlagged = leoProfanity.check(title) || leoProfanity.check(content);
    const story = {
      storyId,
      userId,
      title,
      content,
      tags,
      shares: 0,
      timestamp,
      isFlagged,
      likes: 0,
    };

    const vector = await dataAccess.generateEmbedding(`${title} ${content}`);
    await Promise.all([
      dataAccess.createStory(story),
      dataAccess.upsertVector({
        id: storyId,
        values: vector,
        metadata: { title, userId, tags: tags.join(','), timestamp },
      }),
    ]);

    return { storyId, isFlagged };
  },

  getUserStories: async (userId) => {
    const stories = await dataAccess.getUserStories(userId);
    return stories.map((item) => ({ ...item, isPost: true }));
  },

  getPublicStories: () => dataAccess.getPublicStories(),

  getSimilarStories: (vector) => dataAccess.querySimilarStories(vector),

  generateEmbedding: (text) => dataAccess.generateEmbedding(text),
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

const validateStoryInput = [
  body('title').trim().notEmpty().withMessage('Title is required'),
  body('content').trim().notEmpty().withMessage('Content is required'),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return next(new BadRequestError(errors.array()[0].msg));
    }
    next();
  },
];

const storyLimiter = rateLimit({
  windowMs: STORY_RATE_LIMIT.windowMs,
  max: STORY_RATE_LIMIT.max,
  message: 'Too many stories created. Try again later.',
});

// Error Handling Middleware
const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  logger.error(`${req.method} ${req.url} failed`, { status, message, stack: err.stack });
  res.status(status).json({ error: message });
};

// Route Handlers
const createStoryRoutes = (storyService) => {
  const router = express.Router();

  router.post('/stories', authenticate(), storyLimiter, validateStoryInput, async (req, res, next) => {
    const { title, content, tags } = req.body;
    try {
      const { storyId, isFlagged } = await storyService.createStory(req.user.userId, title, content, tags);
      logger.info('Story created', { storyId, userId: req.user.userId, isFlagged });
      res.status(201).json({ message: 'Story created', storyId, isFlagged });
    } catch (error) {
      next(error);
    }
  });

  router.get('/stories/user', authenticate(), async (req, res, next) => {
    try {
      const stories = await storyService.getUserStories(req.user.userId);
      logger.info('Fetched user stories via GSI', { userId: req.user.userId, count: stories.length });
      res.json(stories);
    } catch (error) {
      next(error);
    }
  });

  router.get('/stories/public', async (req, res, next) => {
    try {
      const stories = await storyService.getPublicStories();
      logger.info('Fetched public stories via GSI', { count: stories.length });
      res.json(stories);
    } catch (error) {
      next(error);
    }
  });

  router.post('/stories/similar', async (req, res, next) => {
    const { vector } = req.body;
    if (!vector) return next(new BadRequestError('Vector is required'));
    try {
      const response = await storyService.getSimilarStories(vector);
      res.json(response);
    } catch (error) {
      next(error);
    }
  });

  router.post('/embeddings', async (req, res, next) => {
    const { text } = req.body;
    if (!text) return next(new BadRequestError('Text is required'));
    try {
      const vector = await storyService.generateEmbedding(text);
      res.json({ vector });
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
  const serviceLayer = storyService(dbLayer);
  const storyRoutes = createStoryRoutes(serviceLayer);

  app.use(express.json());
  app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
  app.use('/api', storyRoutes); // Mount under /api for versioning
  app.use(errorHandler);

  return app;
};

// Start Server
const startServer = async () => {
  const app = initializeApp();
  app.listen(PORT, () => {
    logger.info(`Story Service running on port ${PORT}`);
  });
};

// Graceful Shutdown
const shutdown = () => {
  logger.info('Shutting down Story Service');
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

module.exports = { initializeApp, storyService, dataAccess }; // For testing