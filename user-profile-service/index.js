// user-profile-service/index.js
const express = require("express");
const app = express();

app.use(express.json());

app.get("/health", (req, res) => {
  res.json({ status: "User Profile Service is running" });
});

// Placeholder for getting user profile
app.get("/profile/:id", (req, res) => {
  res.json({ profile: `User profile for ID: ${req.params.id}` });
});

const PORT = process.env.PORT || 5004;
app.listen(PORT, () => console.log(`User Profile Service running on port ${PORT}`));
