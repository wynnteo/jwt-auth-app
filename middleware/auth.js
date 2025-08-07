const jwt = require('jsonwebtoken');
const User = require('../models/User');
const TokenBlacklist = require('../utils/tokenBlacklist');

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token is missing'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if token is blacklisted
    if (decoded.jti && await TokenBlacklist.isBlacklisted(decoded.jti)) {
      return res.status(401).json({
        success: false,
        message: 'Token has been revoked'
      });
    }
    
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token - user not found'
      });
    }

    // Check if user's tokens were revoked after this token was issued
    const tokenIssuedAt = new Date(decoded.iat * 1000);
    const userUpdatedAt = new Date(user.updated_at);
    
    if (userUpdatedAt > tokenIssuedAt) {
      return res.status(401).json({
        success: false,
        message: 'Token has been revoked'
      });
    }

    req.user = user;
    req.token = token;
    req.tokenDecoded = decoded;
    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Token verification failed'
    });
  }
};

const requireEmailVerification = (req, res, next) => {
  if (!req.user.email_verified) {
    return res.status(403).json({
      success: false,
      message: 'Please verify your email address before accessing this resource'
    });
  }
  next();
};

module.exports = { 
  authenticateToken, 
  requireEmailVerification 
};