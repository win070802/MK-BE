const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const useragent = require("express-useragent");

const { 
  query, 
  run, 
  revokeAllUserSessions, 
  createUserSession, 
  validateSession 
} = require("../config/database");

const router = express.Router();

// Middleware để parse user agent
router.use(useragent.express());

// Rate limiting cho auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: {
    error: true,
    message: "Quá nhiều lần thử đăng nhập, vui lòng thử lại sau 15 phút"
  },
});

// Rate limiting cho register
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // Limit each IP to 3 registration attempts per hour
  message: {
    error: true,
    message: "Quá nhiều lần đăng ký, vui lòng thử lại sau 1 giờ"
  },
});

// Validation helper
const validateInput = (data, type) => {
  const errors = [];

  if (type === "register") {
    if (!data.email || !validator.isEmail(data.email)) {
      errors.push("Email không hợp lệ");
    }
    if (!data.username || data.username.length < 3 || data.username.length > 30) {
      errors.push("Username phải có từ 3-30 ký tự");
    }
    if (!/^[a-zA-Z0-9_]+$/.test(data.username)) {
      errors.push("Username chỉ được chứa chữ cái, số và dấu gạch dưới");
    }
    if (!data.password || data.password.length < 8) {
      errors.push("Mật khẩu phải có ít nhất 8 ký tự");
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(data.password)) {
      errors.push("Mật khẩu phải chứa ít nhất 1 chữ hoa, 1 chữ thường và 1 chữ số");
    }
    if (!data.full_name || data.full_name.trim().length < 2) {
      errors.push("Họ tên phải có ít nhất 2 ký tự");
    }
    if (data.phone && !validator.isMobilePhone(data.phone, 'vi-VN')) {
      errors.push("Số điện thoại không hợp lệ");
    }
  }

  if (type === "login") {
    if (!data.identifier) {
      errors.push("Email hoặc username không được để trống");
    }
    if (!data.password) {
      errors.push("Mật khẩu không được để trống");
    }
  }

  return errors;
};

// Generate JWT tokens
const generateTokens = (user, sessionId) => {
  const payload = {
    userId: user.id,
    email: user.email,
    username: user.username,
    role: user.role || 'user',
    sessionId: sessionId
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  });

  const refreshToken = jwt.sign(
    { ...payload, type: 'refresh' }, 
    process.env.JWT_REFRESH_SECRET, 
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
    }
  );

  return { accessToken, refreshToken };
};

// Helper function để extract device info
const extractDeviceInfo = (req) => {
  const ua = req.useragent;
  return {
    deviceType: ua.isMobile ? 'mobile' : ua.isTablet ? 'tablet' : 'web',
    deviceName: ua.source.match(/\(([^)]+)\)/)?.[1] || 'Unknown Device',
    browser: ua.browser || 'Unknown',
    os: ua.os || 'Unknown',
    ipAddress: req.ip || req.connection.remoteAddress || 'Unknown',
    userAgent: req.get('User-Agent') || 'Unknown'
  };
};

// Log login attempt
const logLoginAttempt = async (req, emailOrUsername, success) => {
  try {
    await run(
      "INSERT INTO user_login_attempts (ip_address, email_or_username, success, user_agent) VALUES (?, ?, ?, ?)",
      [req.ip, emailOrUsername, success ? 1 : 0, req.get('User-Agent')]
    );
  } catch (error) {
    console.error("Error logging login attempt:", error);
  }
};

// POST /api/auth/register
router.post("/register", registerLimiter, async (req, res) => {
  try {
    const { email, username, password, full_name, phone, address, city } = req.body;

    // Validate input
    const errors = validateInput(req.body, "register");
    if (errors.length > 0) {
      return res.status(400).json({
        error: true,
        message: "Dữ liệu không hợp lệ",
        errors,
      });
    }

    // Check if user already exists
    const existingUser = await query(
      "SELECT id FROM users WHERE email = ? OR username = ? OR phone = ?",
      [email.toLowerCase(), username.toLowerCase(), phone]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: true,
        message: "Email, username hoặc số điện thoại đã tồn tại",
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Insert new user
    const result = await run(
      `INSERT INTO users (email, username, password_hash, full_name, phone, address, city, verification_token) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?) 
       RETURNING id, email, username, full_name, role, created_at`,
      [
        email.toLowerCase(),
        username.toLowerCase(),
        passwordHash,
        full_name.trim(),
        phone || null,
        address || null,
        city || null,
        verificationToken
      ]
    );

    // Get the created user
    const userResult = await query(
      "SELECT id, email, username, full_name, role, created_at FROM users WHERE id = ?",
      [result.lastID]
    );

    const newUser = userResult.rows[0];

    // Generate session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    
    // Generate JWT tokens
    const { accessToken, refreshToken } = generateTokens(newUser, sessionToken);

    // Get device info
    const deviceInfo = extractDeviceInfo(req);

    // Create user session (single session - revoke all previous sessions)
    await revokeAllUserSessions(newUser.id);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    await createUserSession(newUser.id, {
      sessionToken,
      refreshToken,
      expiresAt: expiresAt.toISOString(),
      ...deviceInfo
    });

    return res.status(201).json({
      success: true,
      message: "Đăng ký thành công",
      data: {
        user: {
          id: newUser.id,
          email: newUser.email,
          username: newUser.username,
          full_name: newUser.full_name,
          role: newUser.role,
          created_at: newUser.created_at,
        },
        tokens: {
          accessToken,
          refreshToken,
          tokenType: 'Bearer'
        },
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    
    if (error.code === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({
        error: true,
        message: "Email, username hoặc số điện thoại đã tồn tại",
      });
    }
    
    return res.status(500).json({
      error: true,
      message: "Lỗi server khi đăng ký",
    });
  }
});

// POST /api/auth/login
router.post("/login", authLimiter, async (req, res) => {
  try {
    const { identifier, password, remember_me = false } = req.body;

    // Validate input
    const errors = validateInput(req.body, "login");
    if (errors.length > 0) {
      await logLoginAttempt(req, identifier, false);
      return res.status(400).json({
        error: true,
        message: "Dữ liệu không hợp lệ",
        errors,
      });
    }

    // Find user by email or username
    const result = await query(
      "SELECT * FROM users WHERE email = ? OR username = ?",
      [identifier.toLowerCase(), identifier.toLowerCase()]
    );

    if (result.rows.length === 0) {
      await logLoginAttempt(req, identifier, false);
      return res.status(401).json({
        error: true,
        message: "Email/username hoặc mật khẩu không đúng",
      });
    }

    const user = result.rows[0];

    // Check if user is active
    if (!user.is_active) {
      await logLoginAttempt(req, identifier, false);
      return res.status(401).json({
        error: true,
        message: "Tài khoản đã bị vô hiệu hóa",
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      await logLoginAttempt(req, identifier, false);
      return res.status(401).json({
        error: true,
        message: "Email/username hoặc mật khẩu không đúng",
      });
    }

    // Log successful login attempt
    await logLoginAttempt(req, identifier, true);

    // Update last login and activity
    await run(
      "UPDATE users SET last_login = datetime('now'), last_activity = datetime('now') WHERE id = ?",
      [user.id]
    );

    // SINGLE SESSION: Revoke all existing sessions
    await revokeAllUserSessions(user.id);

    // Generate new session token
    const sessionToken = crypto.randomBytes(32).toString('hex');
    
    // Generate JWT tokens
    const { accessToken, refreshToken } = generateTokens(user, sessionToken);

    // Get device info
    const deviceInfo = extractDeviceInfo(req);

    // Create new session
    const expiresAt = new Date(Date.now() + (remember_me ? 30 : 7) * 24 * 60 * 60 * 1000);
    
    await createUserSession(user.id, {
      sessionToken,
      refreshToken,
      expiresAt: expiresAt.toISOString(),
      ...deviceInfo
    });

    return res.json({
      success: true,
      message: "Đăng nhập thành công",
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          full_name: user.full_name,
          role: user.role,
          avatar_url: user.avatar_url,
          is_verified: user.is_verified,
          last_login: new Date().toISOString(),
        },
        tokens: {
          accessToken,
          refreshToken,
          tokenType: 'Bearer',
          expiresIn: process.env.JWT_EXPIRES_IN || "1h"
        },
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      error: true,
      message: "Lỗi server khi đăng nhập",
    });
  }
});

// Middleware để authenticate Bearer token
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;

    if (!token) {
      return res.status(401).json({
        error: true,
        message: "Access token không được cung cấp",
      });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Validate session in database
    const session = await validateSession(decoded.sessionId);
    
    if (!session) {
      return res.status(401).json({
        error: true,
        message: "Session không hợp lệ hoặc đã hết hạn",
      });
    }

    // Attach user info to request
    req.user = {
      userId: session.user_id,
      email: session.email,
      username: session.username,
      role: session.role,
      sessionId: decoded.sessionId
    };

    next();
  } catch (error) {
    console.error("Auth token error:", error);
    return res.status(401).json({
      error: true,
      message: "Token không hợp lệ",
    });
  }
};

// GET /api/auth/profile
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, email, username, full_name, phone, avatar_url, address, city, district, ward, 
              role, is_verified, is_seller_verified, shop_name, seller_rating, seller_reviews_count,
              created_at, last_login, last_activity 
       FROM users WHERE id = ?`,
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: "Người dùng không tồn tại",
      });
    }

    return res.json({
      success: true,
      data: {
        user: result.rows[0],
      },
    });
  } catch (error) {
    console.error("Profile error:", error);
    return res.status(500).json({
      error: true,
      message: "Lỗi server khi lấy thông tin profile",
    });
  }
});

// POST /api/auth/refresh
router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        error: true,
        message: "Refresh token không được cung cấp",
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    if (decoded.type !== 'refresh') {
      return res.status(401).json({
        error: true,
        message: "Token không hợp lệ",
      });
    }

    // Check if session exists and is active
    const sessionResult = await query(
      `SELECT us.*, u.id as user_id, u.email, u.username, u.role 
       FROM user_sessions us 
       JOIN users u ON us.user_id = u.id 
       WHERE us.refresh_token = ? AND us.is_active = 1 AND us.expires_at > datetime('now') AND u.is_active = 1`,
      [refreshToken]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(401).json({
        error: true,
        message: "Refresh token không hợp lệ hoặc đã hết hạn",
      });
    }

    const session = sessionResult.rows[0];
    const user = {
      id: session.user_id,
      email: session.email,
      username: session.username,
      role: session.role
    };

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user, session.session_token);

    // Update session with new refresh token
    await run(
      "UPDATE user_sessions SET refresh_token = ?, last_used = datetime('now') WHERE id = ?",
      [newRefreshToken, session.id]
    );

    return res.json({
      success: true,
      message: "Token đã được làm mới",
      data: {
        tokens: {
          accessToken,
          refreshToken: newRefreshToken,
          tokenType: 'Bearer',
          expiresIn: process.env.JWT_EXPIRES_IN || "1h"
        },
      },
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    return res.status(401).json({
      error: true,
      message: "Refresh token không hợp lệ",
    });
  }
});

// POST /api/auth/logout
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    // Revoke current session
    await run(
      "UPDATE user_sessions SET is_active = 0 WHERE session_token = ? AND user_id = ?",
      [req.user.sessionId, req.user.userId]
    );

    return res.json({
      success: true,
      message: "Đăng xuất thành công",
    });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({
      error: true,
      message: "Lỗi server khi đăng xuất",
    });
  }
});

// GET /api/auth/sessions - List all active sessions (for user to manage)
router.get("/sessions", authenticateToken, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, device_type, device_name, browser, os, ip_address, 
              created_at, last_used, session_token 
       FROM user_sessions 
       WHERE user_id = ? AND is_active = 1 AND expires_at > datetime('now')
       ORDER BY last_used DESC`,
      [req.user.userId]
    );

    const sessions = result.rows.map(session => ({
      ...session,
      is_current: session.session_token === req.user.sessionId
    }));

    return res.json({
      success: true,
      data: {
        sessions
      },
    });
  } catch (error) {
    console.error("Sessions error:", error);
    return res.status(500).json({
      error: true,
      message: "Lỗi server khi lấy danh sách sessions",
    });
  }
});

module.exports = { router, authenticateToken };