require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const { Pinecone } = require('@pinecone-database/pinecone');
const OpenAI = require('openai');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const winston = require('winston');

// Constants
const PORT = process.env.PORT || 4002;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const STORY_TABLE = 'Stories';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Fallback for local dev
const PINECONE_INDEX_NAME = 'stories';
const FEED_TOP_STORIES = 45;
const FEED_RANDOM_STORIES = 5;

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'feed-service.log' }),
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
   * Fetches stories for a given user from DynamoDB using the userId-index GSI.
   * @param {string} userId - The user's ID.
   * @returns {Promise<object[]>} - Array of user stories.
   */
  getUserStories: async (userId) => {
    const params = {
      TableName: STORY_TABLE,
      IndexName: 'userId-index', // Use the userId-index GSI
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
   * Fetches all public, non-flagged stories from DynamoDB using the isFlagged-index GSI.
   * @returns {Promise<object[]>} - Array of public, non-flagged stories.
   */
  getPublicStories: async () => {
    const params = {
      TableName: STORY_TABLE,
      IndexName: 'isFlagged-index', // Use the isFlagged-index GSI
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
   * Queries Pinecone for similar stories based on a vector.
   * @param {number[]} vector - Query vector.
   * @param {number} topK - Number of matches to return.
   * @returns {Promise<string[]>} - Array of similar story IDs.
   */
  querySimilarStories: async (vector, topK = 10) => {
    try {
      const response = await pineconeIndex.query({
        vector,
        topK,
        includeMetadata: true,
      });
      return response.matches.map((match) => match.id);
    } catch (error) {
      throw new VectorSearchError('Failed to query Pinecone index', error);
    }
  },
});

// Service Layer
const feedService = (dataAccess) => ({
  /**
   * Generates a personalized feed for a user.
   * @param {string} userId - The user's ID.
   * @returns {Promise<object[]>} - Sorted and randomized feed of stories.
   */
  generateFeed: async (userId) => {
    try {
      // Fetch user stories for personalization
      const userStories = await dataAccess.getUserStories(userId);
      logger.info('Fetched user stories via GSI', { userId, count: userStories.length });
      const userContent = userStories.map((s) => `${s.title} ${s.content}`).join(' ') || 'default user interest';
      const queryVector = await dataAccess.generateEmbedding(userContent);

      // Fetch public, non-flagged stories
      const publicStories = await dataAccess.getPublicStories();
      logger.info('Fetched public stories via GSI', { count: publicStories.length });

      // Get similar story IDs from Pinecone
      const similarStoryIds = await dataAccess.querySimilarStories(queryVector);
      logger.info('Queried similar stories', { userId, similarCount: similarStoryIds.length });

      // Score stories
      const scoredStories = publicStories.map((story) => {
        const daysSincePost = (Date.now() - new Date(story.timestamp)) / (1000 * 60 * 60 * 24);
        const recency = Math.max(0, 1 - daysSincePost / 30) * 0.4; // 40% weight
        const likes = (story.likes || 0) * 0.3; // 30% weight
        const similarity = similarStoryIds.includes(story.storyId) ? 0.2 : 0; // 20% weight
        const shares = (story.shares || 0) * 0.1; // 10% weight
        const score = recency + likes + similarity + shares;
        return { ...story, score };
      });

      // Sort and select feed
      const sortedStories = scoredStories.sort((a, b) => b.score - a.score);
      const topStories = sortedStories.slice(0, FEED_TOP_STORIES);
      const remainingStories = sortedStories.slice(FEED_TOP_STORIES);
      const randomStories = remainingStories
        .sort(() => Math.random() - 0.5)
        .slice(0, FEED_RANDOM_STORIES);

      return [...topStories, ...randomStories];
    } catch (error) {
      logger.error('Feed generation failed', { userId, error });
      throw error; // Re-throw to be handled by error middleware
    }
  },
});

// Middleware
const authMiddleware = (secret = JWT_SECRET) => (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return next(new UnauthorizedError('Unauthorized: No token provided'));
  }
  try {
    req.user = jwt.verify(token, secret);
    logger.info('User authenticated', { userId: req.user.userId });
    next();
  } catch (error) {
    logger.warn('Invalid token', { error });
    next(new UnauthorizedError('Invalid or expired token'));
  }
};

// Error Handling Middleware
const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  logger.error(`${req.method} ${req.url} failed`, { status, message, stack: err.stack });
  res.status(status).json({ error: message });
};

// Route Handlers
const createFeedRoutes = (feedService) => {
  const router = express.Router();

  router.post('/feed', authMiddleware(), async (req, res, next) => {
    try {
      const feed = await feedService.generateFeed(req.user.userId);
      logger.info('Feed generated', { userId: req.user.userId, feedSize: feed.length });
      res.json(feed);
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
  const serviceLayer = feedService(dbLayer);
  const feedRoutes = createFeedRoutes(serviceLayer);

  app.use(express.json());
  app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
  app.use('/api', feedRoutes); // Mount under /api for versioning
  app.use(errorHandler);

  return app;
};

// Start Server
const startServer = async () => {
  const app = initializeApp();
  app.listen(PORT, () => {
    logger.info(`Feed Service running on port ${PORT}`);
  });
};

// Graceful Shutdown
const shutdown = () => {
  logger.info('Shutting down Feed Service');
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

module.exports = { initializeApp, feedService, dataAccess }; // For testing