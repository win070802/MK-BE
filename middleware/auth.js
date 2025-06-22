const jwt = require('jsonwebtoken');
const { query } = require('../config/database');

// API Key authentication middleware
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.header('x-api-key') || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({
      error: true,
      message: 'API key là bắt buộc'
    });
  }
  
  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({
      error: true,
      message: 'API key không hợp lệ'
    });
  }
  
  next();
};

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
      return res.status(401).json({
        error: true,
        message: 'Access token là bắt buộc'
      });
    }
    
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if user still exists and is active
    const result = await query(
      'SELECT id, email, username, is_active FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({
        error: true,
        message: 'Người dùng không tồn tại'
      });
    }
    
    const user = result.rows[0];
    
    if (!user.is_active) {
      return res.status(401).json({
        error: true,
        message: 'Tài khoản đã bị vô hiệu hóa'
      });
    }
    
    // Add user info to request object
    req.user = {
      userId: user.id,
      email: user.email,
      username: user.username
    };
    
    next();
    
  } catch (error) {
    console.error('Token verification error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: true,
        message: 'Token đã hết hạn'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: true,
        message: 'Token không hợp lệ'
      });
    }
    
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi xác thực token'
    });
  }
};

// Optional authentication middleware (không bắt buộc phải có token)
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      req.user = null;
      return next();
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const result = await query(
      'SELECT id, email, username, is_active FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (result.rows.length > 0 && result.rows[0].is_active) {
      req.user = {
        userId: result.rows[0].id,
        email: result.rows[0].email,
        username: result.rows[0].username
      };
    } else {
      req.user = null;
    }
    
    next();
    
  } catch (error) {
    console.error('Optional auth error:', error);
    req.user = null;
    next();
  }
};

// Middleware to require admin role
const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      error: true,
      message: "Token không hợp lệ",
    });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: true,
      message: "Không có quyền truy cập",
    });
  }

  next();
};

// Rate limiting per user
const createUserRateLimit = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  const requests = new Map();
  
  return (req, res, next) => {
    const userId = req.user?.userId || req.ip;
    const now = Date.now();
    const windowStart = now - windowMs;
    
    if (!requests.has(userId)) {
      requests.set(userId, []);
    }
    
    const userRequests = requests.get(userId);
    
    // Remove old requests outside the window
    const validRequests = userRequests.filter(time => time > windowStart);
    requests.set(userId, validRequests);
    
    if (validRequests.length >= maxRequests) {
      return res.status(429).json({
        error: true,
        message: 'Quá nhiều requests, vui lòng thử lại sau'
      });
    }
    
    validRequests.push(now);
    next();
  };
};

module.exports = {
  authenticateApiKey,
  authenticateToken,
  optionalAuth,
  requireAdmin,
  createUserRateLimit
};