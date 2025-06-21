const express = require('express');
const router = express.Router();

// Import individual route modules
const authRoutes = require('./auth');
const usersRoutes = require('./users');
// Mount routes with their respective prefixes
router.use('/auth', authRoutes);
router.use('/users', usersRoutes);

// API info endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'API Routes Available',
    version: '1.0.0',
    routes: {
      auth: '/api/auth',
      users: '/api/users',
    }
  });
});

module.exports = router;