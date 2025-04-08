require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const authenticate = require('./authenticate');

// Constants
const PORT = process.env.PORT || 3001;
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const TABLES = {
  USERS: 'Users',
  STORIES: 'Stories',
};

// Custom Error Classes
class ForbiddenError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ForbiddenError';
    this.status = 403;
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

class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotFoundError';
    this.status = 404;
  }
}

class ConflictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConflictError';
    this.status = 409;
  }
}

// Dependency Injection for DynamoDB Client
const createDynamoDBClient = () => {
  AWS.config.update({
    region: AWS_REGION,
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  });
  return new AWS.DynamoDB.DocumentClient();
};

// Data Access Layer
const dataAccess = (dynamoDB) => ({
  getFlaggedItems: async (tableName, indexName) => {
    const queryParams = {
      TableName: tableName,
      IndexName: indexName,
      KeyConditionExpression: 'isFlagged = :flagged',
      ExpressionAttributeValues: { ':flagged': 1 },
    };
    const scanParams = {
      TableName: tableName,
      FilterExpression: 'isFlagged = :flagged',
      ExpressionAttributeValues: { ':flagged': 1 },
    };

    try {
      const { Items } = await dynamoDB.query(queryParams).promise();
      return Items || [];
    } catch (error) {
      if (error.code === 'ResourceNotFoundException') {
        const { Items } = await dynamoDB.scan(scanParams).promise();
        return Items || [];
      }
      throw new DatabaseError(`Failed to query ${tableName}`, error);
    }
  },

  getItemById: async (tableName, id) => {
    const params = {
      TableName: tableName,
      Key: { id },
    };
    try {
      const { Item } = await dynamoDB.get(params).promise();
      if (!Item) throw new NotFoundError(`Item with id ${id} not found in ${tableName}`);
      return Item;
    } catch (error) {
      if (error instanceof NotFoundError) throw error;
      throw new DatabaseError(`Failed to fetch item from ${tableName}`, error);
    }
  },

  banItem: async (tableName, id) => {
    const item = await dataAccess(dynamoDB).getItemById(tableName, id);
    if (item.banned === 1) {
      throw new ConflictError(`Item with id ${id} in ${tableName} is already banned`);
    }

    const params = {
      TableName: tableName,
      Key: { id },
      UpdateExpression: 'SET banned = :banned',
      ExpressionAttributeValues: { ':banned': 1 },
      ReturnValues: 'ALL_NEW',
    };

    try {
      const { Attributes } = await dynamoDB.update(params).promise();
      return Attributes;
    } catch (error) {
      throw new DatabaseError(`Failed to ban item in ${tableName}`, error);
    }
  },
});

// Service Layer
const adminService = (dataAccess) => ({
  getFlaggedUsers: () => dataAccess.getFlaggedItems(TABLES.USERS, 'isFlagged-index'),
  getFlaggedStories: () => dataAccess.getFlaggedItems(TABLES.STORIES, 'isFlagged-index'),
  banUser: (id) => dataAccess.banItem(TABLES.USERS, id),
  banStory: (id) => dataAccess.banItem(TABLES.STORIES, id),
});

// Middleware
const isAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return next(new ForbiddenError('Access Denied: Admins only'));
  }
  next();
};

// Error Handling Middleware
const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  console.error(`[${new Date().toISOString()}] ${err.name}: ${message}`, err.stack);
  res.status(status).json({ error: message });
};

// Route Handlers
const createAdminRoutes = (adminService) => {
  const router = express.Router();

  router.get('/flagged-users', authenticate, isAdmin, async (req, res, next) => {
    try {
      const users = await adminService.getFlaggedUsers();
      res.json(users);
    } catch (error) {
      next(error);
    }
  });

  router.get('/flagged-stories', authenticate, isAdmin, async (req, res, next) => {
    try {
      const stories = await adminService.getFlaggedStories();
      res.json(stories);
    } catch (error) {
      next(error);
    }
  });

  router.post('/ban-user', authenticate, isAdmin, async (req, res, next) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'User ID is required' });

    try {
      const bannedUser = await adminService.banUser(id);
      res.json({ message: `User ${id} banned successfully`, user: bannedUser });
    } catch (error) {
      next(error);
    }
  });

  router.post('/ban-story', authenticate, isAdmin, async (req, res, next) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'Story ID is required' });

    try {
      const bannedStory = await adminService.banStory(id);
      res.json({ message: `Story ${id} banned successfully`, story: bannedStory });
    } catch (error) {
      next(error);
    }
  });

  return router;
};

// Application Setup
const initializeApp = () => {
  const app = express();
  const dynamoDB = createDynamoDBClient();
  const dbLayer = dataAccess(dynamoDB);
  const serviceLayer = adminService(dbLayer);
  const adminRoutes = createAdminRoutes(serviceLayer);

  app.use(express.json());
  app.use('/admin', adminRoutes);
  app.use(errorHandler);

  return app;
};

// Start Server
const startServer = async () => {
  const app = initializeApp();
  app.listen(PORT, () => {
    console.log(`Ban Service running on port ${PORT}`);
  });
};

startServer().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});