const express = require('express');
const { query } = require('../config/database');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// GET /api/users - Lấy danh sách users (admin only)
router.get('/', authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let whereClause = '';
    let queryParams = [limit, offset];
    
    if (search) {
      whereClause = 'WHERE username ILIKE $3 OR email ILIKE $3 OR full_name ILIKE $3';
      queryParams.push(`%${search}%`);
    }

    const result = await query(
      `SELECT id, email, username, full_name, is_active, is_verified, created_at, last_login 
       FROM users 
       ${whereClause}
       ORDER BY created_at DESC 
       LIMIT $1 OFFSET $2`,
      queryParams
    );

    // Count total users
    const countResult = await query(
      `SELECT COUNT(*) as total FROM users ${whereClause}`,
      search ? [`%${search}%`] : []
    );

    const total = parseInt(countResult.rows[0].total);
    const totalPages = Math.ceil(total / limit);

    return res.json({
      success: true,
      data: {
        users: result.rows,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi lấy danh sách users'
    });
  }
});

// GET /api/users/:id - Lấy thông tin user theo ID
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await query(
      'SELECT id, email, username, full_name, is_active, is_verified, created_at, last_login FROM users WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: 'User không tồn tại'
      });
    }

    return res.json({
      success: true,
      data: {
        user: result.rows[0]
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi lấy thông tin user'
    });
  }
});

// PUT /api/users/:id - Cập nhật thông tin user
router.put('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { full_name, is_active } = req.body;

    // Chỉ cho phép user cập nhật thông tin của chính mình hoặc admin
    if (req.user.userId !== parseInt(id) && !req.user.isAdmin) {
      return res.status(403).json({
        error: true,
        message: 'Không có quyền cập nhật thông tin user này'
      });
    }

    const result = await query(
      'UPDATE users SET full_name = $1, is_active = $2 WHERE id = $3 RETURNING id, email, username, full_name, is_active',
      [full_name, is_active, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: 'User không tồn tại'
      });
    }

    return res.json({
      success: true,
      message: 'Cập nhật thành công',
      data: {
        user: result.rows[0]
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    return res.status(500).json({
      error: true,
      message: 'Lỗi server khi cập nhật user'
    });
  }
});

// DELETE /api/users/:id - Xóa user (soft delete)
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Chỉ admin mới có thể xóa user
    if (!req.user.isAdmin) {
      return res.status(403).json({
        error: true,
        message: 'Không có quyền xóa user'
      });
    }

    const result = await query(
      'UPDATE users SET is_active = false WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: true,
        message: 'User không tồn tại'
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