const express = require('express');
const { query } = require('../config/database');
const { authenticateToken, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// GET /api/users - Get all users (admin only)
router.get('/', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await query(
      `SELECT id, email, username, full_name, role, is_active, is_verified, 
       created_at, last_login 
       FROM users 
       ORDER BY created_at DESC`
    );

    return res.json({
      success: true,
      data: {
        users: result.rows,
        total: result.rows.length,
      },
    });
  } catch (error) {
    console.error('Get users error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi lấy danh sách users'
    });
  }
});

// GET /api/users/:id - Get user by ID (admin only)
router.get('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await query(
      `SELECT id, email, username, full_name, role, is_active, is_verified, 
       created_at, last_login 
       FROM users 
       WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: 'Người dùng không tồn tại'
      });
    }

    return res.json({
      success: true,
      data: {
        user: result.rows[0],
      },
    });
  } catch (error) {
    console.error('Get user error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi lấy thông tin user'
    });
  }
});

// PUT /api/users/:id - Update user (admin only)
router.put('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, role, is_active, is_verified } = req.body;

    // Validate role
    if (role && !['user', 'admin'].includes(role)) {
      return res.status(400).json({
        error: true,
        message: 'Role không hợp lệ'
      });
    }

    const result = await query(
      `UPDATE users 
       SET full_name = COALESCE($1, full_name),
           role = COALESCE($2, role),
           is_active = COALESCE($3, is_active),
           is_verified = COALESCE($4, is_verified),
           updated_at = CURRENT_TIMESTAMP
       WHERE id = $5
       RETURNING id, email, username, full_name, role, is_active, is_verified, created_at, last_login`,
      [full_name, role, is_active, is_verified, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: 'Người dùng không tồn tại'
      });
    }

    return res.json({
      success: true,
      message: 'Cập nhật user thành công',
      data: {
        user: result.rows[0],
      },
    });
  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi cập nhật user'
    });
  }
});

// DELETE /api/users/:id - Delete user (admin only)
router.delete('/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent admin from deleting themselves
    if (parseInt(id) === req.user.userId) {
      return res.status(400).json({
        error: true,
        message: 'Không thể xóa tài khoản của chính mình'
      });
    }

    const result = await query(
      'DELETE FROM users WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: 'Người dùng không tồn tại'
      });
    }

    return res.json({
      success: true,
      message: 'Xóa user thành công'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi xóa user'
    });
  }
});

module.exports = router;