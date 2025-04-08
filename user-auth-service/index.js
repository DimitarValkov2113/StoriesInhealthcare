require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const AWS = require("aws-sdk");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
const port = process.env.PORT;
app.use(cors());
app.use(bodyParser.json());

// Rate Limiter to Prevent Brute-Force Attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 5 login attempts per window
  message: "Too many login attempts. Please try again later.",
});

// Configure AWS SDK for DynamoDB
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const dynamoDB = new AWS.DynamoDB.DocumentClient();
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

// Middleware for admin checks
const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: "Admins only" });
  }
  next();
};

// User Registration
app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Check if user exists
    const checkUser = await dynamoDB
      .query({
        TableName: "Users",
        IndexName: "email-index",
        KeyConditionExpression: "Email = :email",
        ExpressionAttributeValues: { ":email": email },
      })
      .promise();

    if (checkUser.Items.length > 0) {
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash the password
    const passwordHash = await bcrypt.hash(password, 10);
    const user_Id = uuidv4();

    // Save user with 'flagged' and 'banned' default as false
    await dynamoDB
      .put({
        TableName: "Users",
        Item: { 'userId ' : user_Id, username : username, password_hash: passwordHash, Email : email, flagged: false, banned: false, isAdmin: false },
      })
      .promise();

    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// User Login
app.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Fetch user from DB
    const data = await dynamoDB
      .query({
        TableName: "Users",
        IndexName: "email-index",
        KeyConditionExpression: "Email = :email",
        ExpressionAttributeValues: { ":email": email },
      })
      .promise();

    const user = data.Items[0];
    if (!user) return res.status(404).json({ error: "User not found" });

    // Check if user is flagged or banned
    if (user.banned) return res.status(403).json({ error: "Your account is banned" });

    // Compare password
    const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordCorrect) return res.status(401).json({ error: "Invalid credentials" });

    // Generate JWT
    const token = jwt.sign(
      { userId: user.userId, username: user.username, email: user.email, isAdmin: user.isAdmin },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// Flag a user (Admin only)
app.post("/admin/flag-user", authMiddleware, adminMiddleware, async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    const params = {
      TableName: "Users",
      Key: { userId },
      UpdateExpression: "set flagged = :flagged",
      ExpressionAttributeValues: {
        ":flagged": true,
      },
    };

    await dynamoDB.update(params).promise();
    res.status(200).json({ message: "User flagged successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// Ban a user (Admin only)
app.post("/admin/ban-user", authMiddleware, adminMiddleware, async (req, res) => {
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    const params = {
      TableName: "Users",
      Key: { userId },
      UpdateExpression: "set banned = :banned",
      ExpressionAttributeValues: {
        ":banned": true,
      },
    };

    await dynamoDB.update(params).promise();
    res.status(200).json({ message: "User banned successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error. Please try again." });
  }
});

// Get User Info (Protected)
app.get("/user", authMiddleware, async (req, res) => {
  try {
    const params = {
      TableName: "Users",
      Key: { userId: req.user.userId },
    };

    const data = await dynamoDB.get(params).promise();
    if (!data.Item) return res.status(404).json({ error: "User not found" });

    const { password_hash, ...userData } = data.Item;
    res.status(200).json(userData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.status(200).json({ message: "Logout successful" });
});

// Start Server
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
