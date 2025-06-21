const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const rateLimit = require("express-rate-limit");

const { query } = require("../config/database");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

// Rate limiting cho auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  message: "Quá nhiều lần thử đăng nhập, vui lòng thử lại sau 15 phút",
});

// Validation helper
const validateInput = (data, type) => {
  const errors = [];

  if (type === "register") {
    if (!data.email || !validator.isEmail(data.email)) {
      errors.push("Email không hợp lệ");
    }
    if (!data.username || data.username.length < 3) {
      errors.push("Username phải có ít nhất 3 ký tự");
    }
    if (!data.password || data.password.length < 6) {
      errors.push("Mật khẩu phải có ít nhất 6 ký tự");
    }
    if (!data.full_name || data.full_name.trim().length < 2) {
      errors.push("Họ tên không hợp lệ");
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
const generateTokens = (user) => {
  const payload = {
    userId: user.id,
    email: user.email,
    username: user.username,
  };

  const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  });

  const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  });

  return { accessToken, refreshToken };
};

// POST /api/auth/register
router.post("/register", async (req, res) => {
  try {
    const { email, username, password, full_name } = req.body;

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
      "SELECT id FROM users WHERE email = $1 OR username = $2",
      [email.toLowerCase(), username.toLowerCase()]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: true,
        message: "Email hoặc username đã tồn tại",
      });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const result = await query(
      `INSERT INTO users (email, username, password_hash, full_name) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, email, username, full_name, created_at`,
      [
        email.toLowerCase(),
        username.toLowerCase(),
        passwordHash,
        full_name.trim(),
      ]
    );

    const newUser = result.rows[0];

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(newUser);

    // Store refresh token in database
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [newUser.id, refreshToken, expiresAt]
    );

    // IMPORTANT: Return response and end the function here
    return res.status(201).json({
      success: true,
      message: "Đăng ký thành công",
      data: {
        user: {
          id: newUser.id,
          email: newUser.email,
          username: newUser.username,
          full_name: newUser.full_name,
          created_at: newUser.created_at,
        },
        tokens: {
          accessToken,
          refreshToken,
        },
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    
    // Check for specific database errors
    if (error.code === '23505') { // Unique constraint violation
      return res.status(409).json({
        error: true,
        message: "Email hoặc username đã tồn tại",
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
    const { identifier, password } = req.body;

    // Validate input
    const errors = validateInput(req.body, "login");
    if (errors.length > 0) {
      return res.status(400).json({
        error: true,
        message: "Dữ liệu không hợp lệ",
        errors,
      });
    }

    // Find user by email or username
    const result = await query(
      "SELECT * FROM users WHERE email = $1 OR username = $1",
      [identifier.toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: true,
        message: "Email/username hoặc mật khẩu không đúng",
      });
    }

    const user = result.rows[0];

    // Check if user is active
    if (!user.is_active) {
      return res.status(401).json({
        error: true,
        message: "Tài khoản đã bị vô hiệu hóa",
      });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({
        error: true,
        message: "Email/username hoặc mật khẩu không đúng",
      });
    }

    // Update last login
    await query(
      "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1",
      [user.id]
    );

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Store refresh token in database
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, refreshToken, expiresAt]
    );

    return res.json({
      success: true,
      message: "Đăng nhập thành công",
      data: {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          full_name: user.full_name,
          last_login: new Date(),
        },
        tokens: {
          accessToken,
          refreshToken,
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

// GET /api/auth/profile
router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const result = await query(
      "SELECT id, email, username, full_name, is_verified, created_at, last_login FROM users WHERE id = $1",
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

    // Check if refresh token exists in database and is not revoked
    const tokenResult = await query(
      "SELECT * FROM refresh_tokens WHERE token = $1 AND is_revoked = false AND expires_at > CURRENT_TIMESTAMP",
      [refreshToken]
    );

    if (tokenResult.rows.length === 0) {
      return res.status(401).json({
        error: true,
        message: "Refresh token không hợp lệ hoặc đã hết hạn",
      });
    }

    // Get user info
    const userResult = await query(
      "SELECT * FROM users WHERE id = $1 AND is_active = true",
      [decoded.userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        error: true,
        message: "Người dùng không tồn tại hoặc đã bị vô hiệu hóa",
      });
    }

    const user = userResult.rows[0];

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

    // Revoke old refresh token
    await query(
      "UPDATE refresh_tokens SET is_revoked = true WHERE token = $1",
      [refreshToken]
    );

    // Store new refresh token
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    await query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, newRefreshToken, expiresAt]
    );

    return res.json({
      success: true,
      message: "Token đã được làm mới",
      data: {
        tokens: {
          accessToken,
          refreshToken: newRefreshToken,
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
    const { refreshToken } = req.body;

    if (refreshToken) {
      // Revoke refresh token
      await query(
        "UPDATE refresh_tokens SET is_revoked = true WHERE token = $1",
        [refreshToken]
      );
    }

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

module.exports = router;