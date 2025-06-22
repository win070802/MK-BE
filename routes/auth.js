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
  validateSession,
  parseUserAgent,
} = require("../config/database");

const router = express.Router();

// Middleware để parse user agent
router.use(useragent.express());

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per IP per window
  message: {
    error: "Quá nhiều lần thử đăng nhập. Vui lòng thử lại sau 15 phút.",
    code: "TOO_MANY_ATTEMPTS"
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations per IP per hour
  message: {
    error: "Quá nhiều lần đăng ký. Vui lòng thử lại sau 1 giờ.",
    code: "TOO_MANY_REGISTRATIONS"
  },
});

// Helper functions
const generateTokens = (userId) => {
  const sessionToken = jwt.sign(
    { userId, type: 'session' },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  const refreshToken = jwt.sign(
    { userId, type: 'refresh' },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: '30d' }
  );
  
  return { sessionToken, refreshToken };
};

const logLoginAttempt = async (ipAddress, emailOrUsername, success, userAgent) => {
  try {
    await run(
      `INSERT INTO user_login_attempts 
       (ip_address, email_or_username, success, user_agent) 
       VALUES ($1, $2, $3, $4)`,
      [ipAddress, emailOrUsername, success, userAgent]
    );
  } catch (error) {
    console.error("Error logging login attempt:", error);
  }
};

const validatePassword = (password) => {
  if (password.length < 8) {
    return "Mật khẩu phải có ít nhất 8 ký tự";
  }
  if (!/(?=.*[a-z])/.test(password)) {
    return "Mật khẩu phải có ít nhất 1 chữ thường";
  }
  if (!/(?=.*[A-Z])/.test(password)) {
    return "Mật khẩu phải có ít nhất 1 chữ hoa";
  }
  if (!/(?=.*\d)/.test(password)) {
    return "Mật khẩu phải có ít nhất 1 số";
  }
  if (!/(?=.*[@$!%*?&])/.test(password)) {
    return "Mật khẩu phải có ít nhất 1 ký tự đặc biệt";
  }
  return null;
};

// ĐĂNG KÝ
router.post("/register", registerLimiter, async (req, res) => {
  try {
    const {
      email,
      username,
      password,
      confirmPassword,
      fullName,
      phone,
      address,
      city,
      district,
      ward,
      postalCode
    } = req.body;

    // Validation
    if (!email || !username || !password || !confirmPassword || !fullName) {
      return res.status(400).json({
        success: false,
        error: "Vui lòng điền đầy đủ thông tin bắt buộc",
        code: "MISSING_REQUIRED_FIELDS"
      });
    }

    // Validate email
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        error: "Email không hợp lệ",
        code: "INVALID_EMAIL"
      });
    }

    // Validate username
    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({
        success: false,
        error: "Tên đăng nhập phải từ 3-50 ký tự",
        code: "INVALID_USERNAME_LENGTH"
      });
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({
        success: false,
        error: "Tên đăng nhập chỉ được chứa chữ cái, số và dấu gạch dưới",
        code: "INVALID_USERNAME_FORMAT"
      });
    }

    // Validate password
    const passwordError = validatePassword(password);
    if (passwordError) {
      return res.status(400).json({
        success: false,
        error: passwordError,
        code: "INVALID_PASSWORD"
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        error: "Mật khẩu xác nhận không khớp",
        code: "PASSWORD_MISMATCH"
      });
    }

    // Validate phone if provided
    if (phone && !validator.isMobilePhone(phone, 'vi-VN')) {
      return res.status(400).json({
        success: false,
        error: "Số điện thoại không hợp lệ",
        code: "INVALID_PHONE"
      });
    }

    // Check if email or username already exists
    const existingUser = await query(
      "SELECT email, username FROM users WHERE email = $1 OR username = $2",
      [email.toLowerCase(), username.toLowerCase()]
    );

    if (existingUser.rows.length > 0) {
      const existing = existingUser.rows[0];
      if (existing.email === email.toLowerCase()) {
        return res.status(409).json({
          success: false,
          error: "Email đã được sử dụng",
          code: "EMAIL_EXISTS"
        });
      }
      if (existing.username === username.toLowerCase()) {
        return res.status(409).json({
          success: false,
          error: "Tên đăng nhập đã được sử dụng",
          code: "USERNAME_EXISTS"
        });
      }
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');

    // Create user
    const result = await query(
      `INSERT INTO users 
       (email, username, password_hash, full_name, phone, address, city, district, ward, postal_code, verification_token)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, email, username, full_name, role, created_at`,
      [
        email.toLowerCase(),
        username.toLowerCase(),
        passwordHash,
        fullName,
        phone || null,
        address || null,
        city || null,
        district || null,
        ward || null,
        postalCode || null,
        verificationToken
      ]
    );

    const newUser = result.rows[0];

    // Generate tokens
    const { sessionToken, refreshToken } = generateTokens(newUser.id);

    // Parse user agent
    const userAgentData = parseUserAgent(req.headers['user-agent']);
    const ipAddress = req.ip || req.connection.remoteAddress;

    // Create session
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await createUserSession(newUser.id, {
      sessionToken,
      refreshToken,
      expiresAt,
      deviceType: userAgentData.isMobile ? 'mobile' : userAgentData.isTablet ? 'tablet' : 'web',
      deviceName: userAgentData.platform,
      browser: userAgentData.browser,
      os: userAgentData.os,
      ipAddress,
      userAgent: req.headers['user-agent']
    });

    // Update last login
    await run(
      "UPDATE users SET last_login = NOW(), last_activity = NOW() WHERE id = $1",
      [newUser.id]
    );

    // Log successful registration
    await logLoginAttempt(ipAddress, email, true, req.headers['user-agent']);

    res.status(201).json({
      success: true,
      message: "Đăng ký thành công",
      data: {
        user: {
          id: newUser.id,
          email: newUser.email,
          username: newUser.username,
          fullName: newUser.full_name,
          role: newUser.role,
          createdAt: newUser.created_at
        },
        tokens: {
          sessionToken,
          refreshToken,
          expiresAt
        }
      }
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      success: false,
      error: "Đã xảy ra lỗi trong quá trình đăng ký",
      code: "INTERNAL_ERROR"
    });
  }
});

// ĐĂNG NHẬP
router.post("/login", authLimiter, async (req, res) => {
  try {
    const { emailOrUsername, password, rememberMe = false } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    // Validation
    if (!emailOrUsername || !password) {
      return res.status(400).json({
        success: false,
        error: "Vui lòng nhập email/tên đăng nhập và mật khẩu",
        code: "MISSING_CREDENTIALS"
      });
    }

    // Find user by email or username
    const userResult = await query(
      `SELECT id, email, username, password_hash, full_name, role, is_active, is_verified, 
              phone, avatar_url, shop_name, seller_rating, last_login
       FROM users 
       WHERE (email = $1 OR username = $1) AND is_active = TRUE`,
      [emailOrUsername.toLowerCase()]
    );

    if (userResult.rows.length === 0) {
      await logLoginAttempt(ipAddress, emailOrUsername, false, userAgent);
      return res.status(401).json({
        success: false,
        error: "Email/tên đăng nhập hoặc mật khẩu không chính xác",
        code: "INVALID_CREDENTIALS"
      });
    }

    const user = userResult.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      await logLoginAttempt(ipAddress, emailOrUsername, false, userAgent);
      return res.status(401).json({
        success: false,
        error: "Email/tên đăng nhập hoặc mật khẩu không chính xác",
        code: "INVALID_CREDENTIALS"
      });
    }

    // Check if account is active
    if (!user.is_active) {
      await logLoginAttempt(ipAddress, emailOrUsername, false, userAgent);
      return res.status(403).json({
        success: false,
        error: "Tài khoản đã bị vô hiệu hóa",
        code: "ACCOUNT_DISABLED"
      });
    }

    // Revoke all existing sessions (single session login)
    await revokeAllUserSessions(user.id);

    // Generate new tokens
    const { sessionToken, refreshToken } = generateTokens(user.id);

    // Parse user agent
    const userAgentData = parseUserAgent(userAgent);

    // Create new session
    const expiresAt = new Date(Date.now() + (rememberMe ? 30 : 7) * 24 * 60 * 60 * 1000);
    await createUserSession(user.id, {
      sessionToken,
      refreshToken,
      expiresAt,
      deviceType: userAgentData.isMobile ? 'mobile' : userAgentData.isTablet ? 'tablet' : 'web',
      deviceName: userAgentData.platform,
      browser: userAgentData.browser,
      os: userAgentData.os,
      ipAddress,
      userAgent
    });

    // Update last login and activity
    await run(
      "UPDATE users SET last_login = NOW(), last_activity = NOW() WHERE id = $1",
      [user.id]
    );

    // Log successful login
    await logLoginAttempt(ipAddress, emailOrUsername, true, userAgent);

    res.json({
      success: true,
      message: "Đăng nhập thành công",
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          fullName: user.full_name,
          role: user.role,
          isVerified: user.is_verified,
          phone: user.phone,
          avatarUrl: user.avatar_url,
          shopName: user.shop_name,
          sellerRating: user.seller_rating,
          lastLogin: user.last_login
        },
        tokens: {
          sessionToken,
          refreshToken,
          expiresAt
        }
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Đã xảy ra lỗi trong quá trình đăng nhập",
      code: "INTERNAL_ERROR"
    });
  }
});

// ĐĂNG XUẤT
router.post("/logout", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: "Token không hợp lệ",
        code: "INVALID_TOKEN"
      });
    }

    const token = authHeader.substring(7);
    const session = await validateSession(token);

    if (session) {
      // Revoke current session
      await run(
        "UPDATE user_sessions SET is_active = FALSE WHERE session_token = $1",
        [token]
      );
    }

    res.json({
      success: true,
      message: "Đăng xuất thành công"
    });

  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({
      success: false,
      error: "Đã xảy ra lỗi trong quá trình đăng xuất",
      code: "INTERNAL_ERROR"
    });
  }
});

// REFRESH TOKEN
router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: "Refresh token không được cung cấp",
        code: "MISSING_REFRESH_TOKEN"
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Find session with refresh token
    const sessionResult = await query(
      `SELECT us.*, u.id as user_id, u.email, u.username, u.role, u.is_active
       FROM user_sessions us
       JOIN users u ON us.user_id = u.id
       WHERE us.refresh_token = $1 AND us.is_active = TRUE AND us.expires_at > NOW() AND u.is_active = TRUE`,
      [refreshToken]
    );

    if (sessionResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: "Refresh token không hợp lệ",
        code: "INVALID_REFRESH_TOKEN"
      });
    }

    const session = sessionResult.rows[0];

    // Generate new tokens
    const { sessionToken: newSessionToken, refreshToken: newRefreshToken } = generateTokens(session.user_id);

    // Update session with new tokens
    const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await run(
      `UPDATE user_sessions 
       SET session_token = $1, refresh_token = $2, expires_at = $3, last_used = NOW()
       WHERE id = $4`,
      [newSessionToken, newRefreshToken, newExpiresAt, session.id]
    );

    res.json({
      success: true,
      message: "Token đã được làm mới",
      data: {
        tokens: {
          sessionToken: newSessionToken,
          refreshToken: newRefreshToken,
          expiresAt: newExpiresAt
        }
      }
    });

  } catch (error) {
    console.error("Token refresh error:", error);
    res.status(401).json({
      success: false,
      error: "Refresh token không hợp lệ",
      code: "INVALID_REFRESH_TOKEN"
    });
  }
});

// MIDDLEWARE AUTHENTICATION
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: "Token không được cung cấp",
        code: "MISSING_TOKEN"
      });
    }

    const token = authHeader.substring(7);
    const session = await validateSession(token);

    if (!session) {
      return res.status(401).json({
        success: false,
        error: "Token không hợp lệ hoặc đã hết hạn",
        code: "INVALID_TOKEN"
      });
    }

    // Add user info to request
    req.user = {
      id: session.user_id,
      email: session.email,
      username: session.username,
      role: session.role
    };

    next();
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(401).json({
      success: false,
      error: "Token không hợp lệ",
      code: "INVALID_TOKEN"
    });
  }
};

// GET USER PROFILE
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const userResult = await query(
      `SELECT id, email, username, full_name, phone, avatar_url, address, city, district, ward, postal_code,
              role, is_verified, is_seller_verified, shop_name, shop_description, seller_rating, seller_reviews_count,
              total_orders, total_spent, created_at, last_login
       FROM users 
       WHERE id = $1 AND is_active = TRUE`,
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Người dùng không tồn tại",
        code: "USER_NOT_FOUND"
      });
    }

    const user = userResult.rows[0];

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          fullName: user.full_name,
          phone: user.phone,
          avatarUrl: user.avatar_url,
          address: user.address,
          city: user.city,
          district: user.district,
          ward: user.ward,
          postalCode: user.postal_code,
          role: user.role,
          isVerified: user.is_verified,
          isSellerVerified: user.is_seller_verified,
          shopName: user.shop_name,
          shopDescription: user.shop_description,
          sellerRating: user.seller_rating,
          sellerReviewsCount: user.seller_reviews_count,
          totalOrders: user.total_orders,
          totalSpent: user.total_spent,
          createdAt: user.created_at,
          lastLogin: user.last_login
        }
      }
    });

  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({
      success: false,
      error: "Đã xảy ra lỗi khi lấy thông tin người dùng",
      code: "INTERNAL_ERROR"
    });
  }
});

module.exports = { router, authenticateToken };