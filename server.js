require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { initializeDatabase } = require("./config/database");

// Import routes
const apiRoutes = require("./routes");

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());

// CORS config
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production" ? process.env.FRONTEND_URL : true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: "Quá nhiều requests từ IP này, vui lòng thử lại sau.",
});
app.use(limiter);

// Body parsing middleware
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// API Routes - Tất cả routes sẽ có prefix /api
app.use("/api", apiRoutes);

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Server đang hoạt động",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    port: PORT,
    version: "1.0.0",
  });
});

// API Documentation endpoint
app.get("/", (req, res) => {
  res.json({
    message: "API Node.js Authentication Server",
    version: "1.0.0",
    environment: process.env.NODE_ENV || "development",
    documentation: {
      health: "GET /health",
      endpoints: {
        auth: {
          register: "POST /api/auth/register",
          login: "POST /api/auth/login",
          profile: "GET /api/auth/profile",
          refresh: "POST /api/auth/refresh",
          logout: "POST /api/auth/logout",
        },
      },
    },
  });
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error("Global Error Handler:", {
    error: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  res.status(err.status || 500).json({
    error: true,
    message: err.message || "Đã xảy ra lỗi server",
    ...(process.env.NODE_ENV === "development" && {
      stack: err.stack,
      url: req.originalUrl,
      method: req.method,
    }),
  });
});

// 404 handler - Phải đặt cuối cùng
app.use("*", (req, res) => {
  res.status(404).json({
    error: true,
    message: "Endpoint không tồn tại",
    requestedPath: req.originalUrl,
    method: req.method,
    availableEndpoints: {
      health: "GET /health",
      documentation: "GET /",
      auth: "GET|POST /api/auth/*",
    },
  });
});

// Initialize database and start server
const startServer = async () => {
  try {
    await initializeDatabase();
    console.log("✅ Database initialized successfully");

    app.listen(PORT, () => {
      console.log(`🚀 Server đang chạy trên port ${PORT}`);
      console.log(`📍 URL: http://localhost:${PORT}`);
      console.log(`🏥 Health check: http://localhost:${PORT}/health`);
      console.log(`📚 API Documentation: http://localhost:${PORT}/`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`🔐 Available routes:`);
      console.log(`   - Auth: /api/auth/*`);
    });
  } catch (error) {
    console.error("❌ Lỗi khi khởi động server:", error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down gracefully");
  process.exit(0);
});

process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down gracefully");
  process.exit(0);
});
