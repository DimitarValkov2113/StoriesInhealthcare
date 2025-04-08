// analytics-service/index.js
const express = require("express");
const app = express();

app.use(express.json());

// Health check route
app.get("/health", (req, res) => {
  res.json({ status: "Analytics Service is running" });
});

// Placeholder for analytics endpoint
app.post("/track", (req, res) => {
  console.log("Tracking data:", req.body);
  res.json({ message: "Data received" });
});

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Analytics Service running on port ${PORT}`));
