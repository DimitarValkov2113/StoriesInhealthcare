require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const winston = require('winston');

// Constants
const PORT = process.env.PORT || 4004;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const DIARY_TABLE = 'Diaries';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'; // Fallback for local dev

// Logger Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'diary-service.log' }),
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

// Dependency Injection for DynamoDB Client
const createDynamoDBClient = (config = {}) => {
  AWS.config.update({
    region: AWS_REGION,
    accessKeyId: config.accessKeyId || process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: config.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
  });
  return new AWS.DynamoDB.DocumentClient();
};

// Data Access Layer
const dataAccess = (dynamoDB) => ({
  /**
   * Creates a new diary entry in DynamoDB.
   * @param {object} diary - The diary object to store.
   * @returns {Promise<object>} - The created diary.
   */
  createDiary: async (diary) => {
    const params = {
      TableName: DIARY_TABLE,
      Item: diary,
      ConditionExpression: 'attribute_not_exists(diaryId)',
    };
    try {
      await dynamoDB.put(params).promise();
      return diary;
    } catch (error) {
      logger.error('Failed to create diary', { error });
      throw new DatabaseError('Unable to create diary', error);
    }
  },

  /**
   * Fetches diaries for a given user.
   * @param {string} userId - The user ID to query diaries for.
   * @returns {Promise<object[]>} - Array of diary entries.
   */
  getUserDiaries: async (userId) => {
    const params = {
      TableName: DIARY_TABLE,
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
    };
    try {
      const { Items } = await dynamoDB.query(params).promise();
      return Items || [];
    } catch (error) {
      logger.error('Failed to fetch diaries', { userId, error });
      throw new DatabaseError('Unable to fetch diaries', error);
    }
  },
});

// Service Layer
const diaryService = (dataAccess, uuidGenerator = uuidv4) => ({
  createDiary: async (userId, content, isPublic = false) => {
    const diary = {
      diaryId: uuidGenerator(),
      userId,
      content,
      isPublic,
      timestamp: new Date().toISOString(),
    };
    return dataAccess.createDiary(diary);
  },

  getUserDiaries: (userId) => dataAccess.getUserDiaries(userId),
});

// Middleware
const authenticate = (secret = JWT_SECRET) => (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return next(new UnauthorizedError('Access Denied: No token provided'));
  }
  try {
    req.user = jwt.verify(token, secret);
    logger.info('User authenticated', { userId: req.user.userId });
    next();
  } catch (error) {
    logger.warn('Invalid token', { error });
    next(new UnauthorizedError('Invalid Token'));
  }
};

const validateDiaryInput = [
  body('content').trim().notEmpty().withMessage('Content is required'),
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
const createDiaryRoutes = (diaryService) => {
  const router = express.Router();

  router.post('/diaries', authenticate(), validateDiaryInput, async (req, res, next) => {
    const { content, isPublic } = req.body;
    try {
      const diary = await diaryService.createDiary(req.user.userId, content, isPublic);
      logger.info('Diary created', { diaryId: diary.diaryId, userId: req.user.userId });
      res.status(201).json(diary);
    } catch (error) {
      next(error);
    }
  });

  router.get('/diaries', authenticate(), async (req, res, next) => {
    try {
      const diaries = await diaryService.getUserDiaries(req.user.userId);
      res.json(diaries);
    } catch (error) {
      next(error);
    }
  });

  return router;
};

// Application Setup
const initializeApp = (dynamoDBClient = createDynamoDBClient()) => {
  const app = express();
  const dbLayer = dataAccess(dynamoDBClient);
  const serviceLayer = diaryService(dbLayer);
  const diaryRoutes = createDiaryRoutes(serviceLayer);

  app.use(express.json());
  app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
  app.use('/api', diaryRoutes); // Mount under /api for versioning
  app.use(errorHandler);

  return app;
};

// Start Server
const startServer = async () => {
  const app = initializeApp();
  app.listen(PORT, () => {
    logger.info(`Diary Service running on port ${PORT}`);
  });
};

// Graceful Shutdown
const shutdown = () => {
  logger.info('Shutting down Diary Service');
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

startServer().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});

module.exports = { initializeApp, diaryService, dataAccess }; // For testing