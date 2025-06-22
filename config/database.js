const { Pool } = require('pg');
const useragent = require('express-useragent');
require('dotenv').config();

// Cấu hình kết nối PostgreSQL từ environment variables
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: false } 
    : false,
  // Thêm các options để tăng độ ổn định
  max: 20, // Số lượng connection tối đa trong pool
  idleTimeoutMillis: 30000, // Thời gian timeout cho idle connections
  connectionTimeoutMillis: 2000, // Thời gian timeout cho việc tạo connection
  // Retry logic
  retryDelay: 1000,
  maxRetries: 3,
});

// Event listeners để debug connection issues
pool.on('connect', (client) => {
  console.log('✅ New client connected to PostgreSQL');
});

pool.on('error', (err, client) => {
  console.error('❌ Unexpected error on idle client', err);
});

pool.on('acquire', (client) => {
  console.log('🔗 Client acquired from pool');
});

pool.on('release', (client) => {
  console.log('🔓 Client released back to pool');
});

console.log("✅ Connected to PostgreSQL database");

const initializeDatabase = async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) UNIQUE,
        avatar_url TEXT,
        
        -- Address information
        address TEXT,
        city VARCHAR(100),
        district VARCHAR(100),
        ward VARCHAR(100),
        postal_code VARCHAR(20),
        
        -- User role and status
        role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator', 'seller')),
        is_active BOOLEAN DEFAULT TRUE,
        is_verified BOOLEAN DEFAULT FALSE,
        is_seller_verified BOOLEAN DEFAULT FALSE,
        
        -- Account verification
        email_verified_at TIMESTAMP,
        phone_verified_at TIMESTAMP,
        verification_token TEXT,
        
        -- Security
        two_factor_enabled BOOLEAN DEFAULT FALSE,
        two_factor_secret TEXT,
        
        -- Seller specific fields
        shop_name VARCHAR(255),
        shop_description TEXT,
        tax_id VARCHAR(50),
        bank_account VARCHAR(50),
        bank_name VARCHAR(100),
        
        -- Statistics
        total_orders INTEGER DEFAULT 0,
        total_spent DECIMAL(12,2) DEFAULT 0.00,
        seller_rating DECIMAL(3,2) DEFAULT 0.00,
        seller_reviews_count INTEGER DEFAULT 0,
        
        -- Timestamps
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        last_activity TIMESTAMP
      )
    `);

    // Create user_sessions table
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        refresh_token TEXT UNIQUE NOT NULL,
        
        -- Device information
        device_type VARCHAR(20), -- 'web', 'mobile', 'tablet'
        device_name VARCHAR(100),
        browser VARCHAR(50),
        os VARCHAR(50),
        ip_address INET,
        user_agent TEXT,
        
        -- Session status
        is_active BOOLEAN DEFAULT TRUE,
        expires_at TIMESTAMP NOT NULL,
        last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        -- Timestamps
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create password_reset_tokens table
    await client.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Create user_login_attempts table for security
    await client.query(`
      CREATE TABLE IF NOT EXISTS user_login_attempts (
        id SERIAL PRIMARY KEY,
        ip_address INET NOT NULL,
        email_or_username VARCHAR(255),
        success BOOLEAN DEFAULT FALSE,
        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_agent TEXT
      )
    `);

    // Create indexes for better performance
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON user_login_attempts(ip_address)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON user_login_attempts(email_or_username)`);

    // Create trigger for updating updated_at timestamp
    await client.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    await client.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at 
        BEFORE UPDATE ON users 
        FOR EACH ROW 
        EXECUTE FUNCTION update_updated_at_column();
    `);

    await client.query('COMMIT');
    console.log("✅ Database tables and indexes initialized successfully");
  } catch (error) {
    await client.query('ROLLBACK');
    console.error("❌ Error initializing database:", error);
    throw error;
  } finally {
    client.release();
  }
};

const query = async (text, params = []) => {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log("Query executed:", { 
      text: text.substring(0, 100) + (text.length > 100 ? '...' : ''), 
      duration, 
      rows: result.rows?.length || 0 
    });
    return { rows: result.rows, rowCount: result.rowCount };
  } catch (error) {
    const duration = Date.now() - start;
    console.error("Database query error:", error);
    console.error("Query:", text);
    console.error("Params:", params);
    throw error;
  }
};

const run = async (text, params = []) => {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log("Query executed:", { 
      text: text.substring(0, 100) + (text.length > 100 ? '...' : ''), 
      duration, 
      changes: result.rowCount,
      lastID: result.rows[0]?.id || null
    });
    return { rowCount: result.rowCount, lastID: result.rows[0]?.id || null };
  } catch (error) {
    const duration = Date.now() - start;
    console.error("Database run error:", error);
    console.error("Query:", text);
    console.error("Params:", params);
    throw error;
  }
};

const getClient = async () => {
  return await pool.connect();
};

// Helper function để clean up expired sessions
const cleanupExpiredSessions = async () => {
  try {
    const result = await run(
      "DELETE FROM user_sessions WHERE expires_at < NOW() OR is_active = FALSE"
    );
    if (result.rowCount > 0) {
      console.log(`🧹 Cleaned up ${result.rowCount} expired sessions`);
    }
  } catch (error) {
    console.error("Error cleaning up expired sessions:", error);
  }
};

// Helper function để revoke tất cả sessions của user (single session login)
const revokeAllUserSessions = async (userId) => {
  try {
    await run(
      "UPDATE user_sessions SET is_active = FALSE WHERE user_id = $1 AND is_active = TRUE",
      [userId]
    );
    console.log(`🔒 Revoked all active sessions for user ${userId}`);
  } catch (error) {
    console.error("Error revoking user sessions:", error);
    throw error;
  }
};

// Helper function để parse user agent
const parseUserAgent = (userAgentString) => {
  const ua = useragent.parse(userAgentString || '');
  return {
    browser: ua.browser || 'Unknown',
    os: ua.os || 'Unknown',
    platform: ua.platform || 'Unknown',
    isMobile: ua.isMobile,
    isDesktop: ua.isDesktop,
    isTablet: ua.isTablet
  };
};

// Helper function để tạo session mới
const createUserSession = async (userId, sessionData) => {
  const {
    sessionToken,
    refreshToken,
    expiresAt,
    deviceType = 'web',
    deviceName = 'Unknown',
    browser = 'Unknown',
    os = 'Unknown',
    ipAddress,
    userAgent
  } = sessionData;

  // Parse user agent nếu có
  let parsedUA = { browser, os };
  if (userAgent) {
    parsedUA = parseUserAgent(userAgent);
  }

  try {
    const result = await query(
      `INSERT INTO user_sessions 
       (user_id, session_token, refresh_token, expires_at, device_type, device_name, browser, os, ip_address, user_agent) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [userId, sessionToken, refreshToken, expiresAt, deviceType, deviceName, parsedUA.browser, parsedUA.os, ipAddress, userAgent]
    );
    
    console.log(`✅ Created new session for user ${userId}`);
    return result.rows[0].id;
  } catch (error) {
    console.error("Error creating user session:", error);
    throw error;
  }
};

// Helper function để validate session
const validateSession = async (sessionToken) => {
  try {
    const result = await query(
      `SELECT us.*, u.id as user_id, u.email, u.username, u.role, u.is_active 
       FROM user_sessions us 
       JOIN users u ON us.user_id = u.id 
       WHERE us.session_token = $1 AND us.is_active = TRUE AND us.expires_at > NOW() AND u.is_active = TRUE`,
      [sessionToken]
    );

    if (result.rows.length === 0) {
      return null;
    }

    // Update last_used timestamp
    await run(
      "UPDATE user_sessions SET last_used = NOW() WHERE session_token = $1",
      [sessionToken]
    );

    return result.rows[0];
  } catch (error) {
    console.error("Error validating session:", error);
    return null;
  }
};

// Helper function để refresh token
const refreshUserSession = async (refreshToken) => {
  try {
    const result = await query(
      `SELECT us.*, u.id as user_id, u.email, u.username, u.role, u.is_active 
       FROM user_sessions us 
       JOIN users u ON us.user_id = u.id 
       WHERE us.refresh_token = $1 AND us.is_active = TRUE AND us.expires_at > NOW() AND u.is_active = TRUE`,
      [refreshToken]
    );

    return result.rows.length > 0 ? result.rows[0] : null;
  } catch (error) {
    console.error("Error refreshing session:", error);
    return null;
  }
};

// Helper function để update session tokens
const updateSessionTokens = async (sessionId, newSessionToken, newRefreshToken, newExpiresAt) => {
  try {
    await run(
      `UPDATE user_sessions 
       SET session_token = $1, refresh_token = $2, expires_at = $3, last_used = NOW() 
       WHERE id = $4`,
      [newSessionToken, newRefreshToken, newExpiresAt, sessionId]
    );
    console.log(`✅ Updated session tokens for session ${sessionId}`);
  } catch (error) {
    console.error("Error updating session tokens:", error);
    throw error;
  }
};

// Auto cleanup expired sessions every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// Check database connection and list tables
const checkConnection = async () => {
  try {
    const result = await query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    );
    console.log("📋 Tables in database:", result.rows.map(r => r.table_name));
  } catch (error) {
    console.error("❌ Error fetching tables:", error);
  }
};

// Initialize connection check
checkConnection();

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Closing database connection pool...');
  await pool.end();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Closing database connection pool...');
  await pool.end();
  process.exit(0);
});

module.exports = {
  pool,
  query,
  run,
  getClient,
  initializeDatabase,
  cleanupExpiredSessions,
  revokeAllUserSessions,
  createUserSession,
  validateSession,
  refreshUserSession,
  updateSessionTokens,
  parseUserAgent,
};