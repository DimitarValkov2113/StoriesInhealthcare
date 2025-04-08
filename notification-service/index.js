// notification-service/index.js
const express = require("express");
const app = express();

app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ status: "Notification Service is running" });
});

// Placeholder for sending a notification
app.post("/notify", (req, res) => {
  console.log("Sending notification:", req.body);
  res.json({ message: "Notification sent" });
});

const PORT = process.env.PORT || 5005;
app.listen(PORT, () => console.log(`Notification Service running on port ${PORT}`));
