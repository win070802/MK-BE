const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Cấu hình kết nối SQLite
const dbPath = path.join(__dirname, '../database.sqlite');
const db = new sqlite3.Database(dbPath);
console.log("✅ Connected to SQLite database");

const initializeDatabase = async () => {
  return new Promise((resolve, reject) => {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        phone TEXT UNIQUE,
        avatar_url TEXT,
        
        -- Address information
        address TEXT,
        city TEXT,
        district TEXT,
        ward TEXT,
        postal_code TEXT,
        
        -- User role and status
        role TEXT DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator', 'seller')),
        is_active INTEGER DEFAULT 1,
        is_verified INTEGER DEFAULT 0,
        is_seller_verified INTEGER DEFAULT 0,
        
        -- Account verification
        email_verified_at DATETIME,
        phone_verified_at DATETIME,
        verification_token TEXT,
        
        -- Security
        two_factor_enabled INTEGER DEFAULT 0,
        two_factor_secret TEXT,
        
        -- Seller specific fields
        shop_name TEXT,
        shop_description TEXT,
        tax_id TEXT,
        bank_account TEXT,
        bank_name TEXT,
        
        -- Statistics
        total_orders INTEGER DEFAULT 0,
        total_spent DECIMAL(12,2) DEFAULT 0.00,
        seller_rating DECIMAL(3,2) DEFAULT 0.00,
        seller_reviews_count INTEGER DEFAULT 0,
        
        -- Timestamps
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        last_activity DATETIME
      )
    `, (err) => {
      if (err) {
        console.error("❌ Error creating users table:", err);
        reject(err);
        return;
      }

      // Create user_sessions table thay vì refresh_tokens để quản lý session tốt hơn
      db.run(`
        CREATE TABLE IF NOT EXISTS user_sessions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          session_token TEXT UNIQUE NOT NULL,
          refresh_token TEXT UNIQUE NOT NULL,
          
          -- Device information
          device_type TEXT, -- 'web', 'mobile', 'tablet'
          device_name TEXT,
          browser TEXT,
          os TEXT,
          ip_address TEXT,
          user_agent TEXT,
          
          -- Session status
          is_active INTEGER DEFAULT 1,
          expires_at DATETIME NOT NULL,
          last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
          
          -- Timestamps
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `, (err) => {
        if (err) {
          console.error("❌ Error creating user_sessions table:", err);
          reject(err);
          return;
        }

        // Create password_reset_tokens table
        db.run(`
          CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            used_at DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
          )
        `, (err) => {
          if (err) {
            console.error("❌ Error creating password_reset_tokens table:", err);
            reject(err);
            return;
          }

          // Create user_login_attempts table for security
          db.run(`
            CREATE TABLE IF NOT EXISTS user_login_attempts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ip_address TEXT NOT NULL,
              email_or_username TEXT,
              success INTEGER DEFAULT 0,
              attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              user_agent TEXT
            )
          `, (err) => {
            if (err) {
              console.error("❌ Error creating user_login_attempts table:", err);
              reject(err);
              return;
            }

            // Create indexes for better performance
            db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`, (err) => {
              if (err) console.error("❌ Error creating email index:", err);
            });

            db.run(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`, (err) => {
              if (err) console.error("❌ Error creating username index:", err);
            });

            db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)`, (err) => {
              if (err) console.error("❌ Error creating sessions user_id index:", err);
            });

            db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token)`, (err) => {
              if (err) console.error("❌ Error creating sessions token index:", err);
            });

            console.log("✅ Database tables and indexes initialized successfully");
            resolve();
          });
        });
      });
    });
  });
};

const query = async (text, params = []) => {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    db.all(text, params, (err, rows) => {
      const duration = Date.now() - start;
      if (err) {
        console.error("Database query error:", err);
        console.error("Query:", text);
        console.error("Params:", params);
        reject(err);
      } else {
        console.log("Query executed:", { 
          text: text.substring(0, 100) + (text.length > 100 ? '...' : ''), 
          duration, 
          rows: rows?.length || 0 
        });
        resolve({ rows, rowCount: rows?.length || 0 });
      }
    });
  });
};

const run = async (text, params = []) => {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    db.run(text, params, function(err) {
      const duration = Date.now() - start;
      if (err) {
        console.error("Database run error:", err);
        console.error("Query:", text);
        console.error("Params:", params);
        reject(err);
      } else {
        console.log("Query executed:", { 
          text: text.substring(0, 100) + (text.length > 100 ? '...' : ''), 
          duration, 
          changes: this.changes,
          lastID: this.lastID
        });
        resolve({ rowCount: this.changes, lastID: this.lastID });
      }
    });
  });
};

const getClient = async () => {
  return db;
};

// Helper function để clean up expired sessions
const cleanupExpiredSessions = async () => {
  try {
    const result = await run(
      "DELETE FROM user_sessions WHERE expires_at < datetime('now') OR is_active = 0"
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
      "UPDATE user_sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1",
      [userId]
    );
    console.log(`🔒 Revoked all active sessions for user ${userId}`);
  } catch (error) {
    console.error("Error revoking user sessions:", error);
    throw error;
  }
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

  try {
    const result = await run(
      `INSERT INTO user_sessions 
       (user_id, session_token, refresh_token, expires_at, device_type, device_name, browser, os, ip_address, user_agent) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, sessionToken, refreshToken, expiresAt, deviceType, deviceName, browser, os, ipAddress, userAgent]
    );
    
    console.log(`✅ Created new session for user ${userId}`);
    return result.lastID;
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
       WHERE us.session_token = ? AND us.is_active = 1 AND us.expires_at > datetime('now') AND u.is_active = 1`,
      [sessionToken]
    );

    if (result.rows.length === 0) {
      return null;
    }

    // Update last_used timestamp
    await run(
      "UPDATE user_sessions SET last_used = datetime('now') WHERE session_token = ?",
      [sessionToken]
    );

    return result.rows[0];
  } catch (error) {
    console.error("Error validating session:", error);
    return null;
  }
};

// Auto cleanup expired sessions every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

module.exports = {
  db,
  query,
  run,
  getClient,
  initializeDatabase,
  cleanupExpiredSessions,
  revokeAllUserSessions,
  createUserSession,
  validateSession,
};