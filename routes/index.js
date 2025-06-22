const express = require("express");
const router = express.Router();

// Import auth routes
const { router: authRouter, authenticateToken } = require("./auth");

// Mount auth routes
router.use("/auth", authRouter);

// Test endpoint
router.get("/test", (req, res) => {
  res.json({
    success: true,
    message: "API Routes đang hoạt động",
    timestamp: new Date().toISOString(),
  });
});

// Protected test endpoint
router.get("/protected-test", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Protected endpoint đang hoạt động",
    user: req.user,
    timestamp: new Date().toISOString(),
  });
});

// Export router và middleware
module.exports = router;
module.exports.authenticateToken = authenticateToken;
