const express = require('express');
const router = express.Router();

// Import individual route modules
const authRoutes = require('./auth');
// Mount routes with their respective prefixes
router.use('/auth', authRoutes);

// API info endpoint
router.get('/', (req, res) => {
  res.json({
    message: 'API Routes Available',
    version: '1.0.0',
    routes: {
      auth: '/api/auth',
    }
  });
});

module.exports = router;