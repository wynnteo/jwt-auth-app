const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { sendEmail } = require('../config/email');
const { getEmailVerificationTemplate, getPasswordResetTemplate } = require('../utils/emailTemplates');
const { authenticateToken, requireEmailVerification } = require('../middleware/auth');
const { validateRegistration, validateLogin, validatePasswordReset } = require('../middleware/validation');
const { authLimiter, passwordResetLimiter, emailVerificationLimiter } = require('../middleware/rateLimiter');
const TokenBlacklist = require('../utils/tokenBlacklist');

const router = express.Router();

const generateToken = (userId, expiresIn = process.env.JWT_EXPIRES_IN) => {
  const jti = crypto.randomBytes(16).toString('hex'); // Unique token ID for blacklisting
  
  return {
    token: jwt.sign(
      { userId, jti },
      process.env.JWT_SECRET,
      { expiresIn }
    ),
    jti
  };
};

// User Registration with Email Verification
router.post('/register', authLimiter, validateRegistration, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const user = await User.create({ email, password, name });
    
    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${user.email_verification_token}`;
    const emailHtml = getEmailVerificationTemplate(verificationUrl, user.name);
    
    await sendEmail(
      user.email,
      'Verify Your Email Address',
      emailHtml
    );

    res.status(201).json({
      success: true,
      message: 'User created successfully. Please check your email for verification instructions.',
      user: user.toJSON()
    });

  } catch (error) {
    if (error.message === 'User already exists') {
      return res.status(400).json({
        success: false,
        message: error.message
      });
    }

    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during registration'
    });
  }
});

// Email Verification
router.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    
    const user = await User.findByVerificationToken(token);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired verification token'
      });
    }

    await user.verifyEmail();
    
    // Generate JWT token for immediate login
    const { token: jwtToken } = generateToken(user.id);

    res.json({
      success: true,
      message: 'Email verified successfully',
      token: jwtToken,
      user: user.toJSON()
    });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during email verification'
    });
  }
});

// Resend Email Verification
router.post('/resend-verification', emailVerificationLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.email_verified) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified'
      });
    }

    // Generate new verification token
    const verificationToken = await user.regenerateEmailVerificationToken();
    
    // Send verification email
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
    const emailHtml = getEmailVerificationTemplate(verificationUrl, user.name);
    
    await sendEmail(
      user.email,
      'Verify Your Email Address',
      emailHtml
    );

    res.json({
      success: true,
      message: 'Verification email sent successfully'
    });

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while sending verification email'
    });
  }
});

// User Login
router.post('/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const isPasswordValid = await user.validatePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const { token } = generateToken(user.id);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: user.toJSON(),
      emailVerified: user.email_verified
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during login'
    });
  }
});

// Forgot Password
router.post('/forgot-password', passwordResetLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    const user = await User.findByEmail(email);
    if (!user) {
      // Don't reveal if email exists or not for security
      return res.json({
        success: true,
        message: 'If an account with that email exists, you will receive a password reset email'
      });
    }

    // Generate password reset token
    const resetToken = await user.generatePasswordResetToken();
    
    // Send password reset email
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const emailHtml = getPasswordResetTemplate(resetUrl, user.name);
    
    await sendEmail(
      user.email,
      'Password Reset Request',
      emailHtml
    );

    res.json({
      success: true,
      message: 'If an account with that email exists, you will receive a password reset email'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error while processing password reset request'
    });
  }
});

// Reset Password
router.post('/reset-password', validatePasswordReset, async (req, res) => {
  try {
    const { token, password } = req.body;

    const user = await User.findByPasswordResetToken(token);
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset token'
      });
    }

    await user.resetPassword(password);

    res.json({
      success: true,
      message: 'Password reset successfully'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during password reset'
    });
  }
});

// Get User Profile (requires authentication and email verification)
router.get('/profile', authenticateToken, requireEmailVerification, (req, res) => {
  res.json({
    success: true,
    message: 'Profile retrieved successfully',
    user: req.user.toJSON()
  });
});

// Update User Profile
router.put('/profile', authenticateToken, requireEmailVerification, async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({
        success: false,
        message: 'Name is required'
      });
    }

    await req.user.updateProfile(name);

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: req.user.toJSON()
    });

  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during profile update'
    });
  }
});

// Token Refresh
router.post('/refresh', authenticateToken, (req, res) => {
  try {
    const { token: newToken } = generateToken(req.user.id);

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      token: newToken,
      user: req.user.toJSON()
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during token refresh'
    });
  }
});

// Logout (blacklist current token)
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    if (req.tokenDecoded.jti) {
      const expiresAt = new Date(req.tokenDecoded.exp * 1000);
      await TokenBlacklist.addToBlacklist(req.tokenDecoded.jti, req.user.id, expiresAt);
    }

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during logout'
    });
  }
});

// Logout from all devices (revoke all tokens)
router.post('/logout-all', authenticateToken, async (req, res) => {
  try {
    await TokenBlacklist.revokeAllUserTokens(req.user.id);

    res.json({
      success: true,
      message: 'Logged out from all devices successfully'
    });

  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during logout from all devices'
    });
  }
});

// Change Password (for authenticated users)
router.post('/change-password', authenticateToken, requireEmailVerification, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    // Validate current password
    const isCurrentPasswordValid = await req.user.validatePassword(currentPassword);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Validate new password strength
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (newPassword.length < 8 || !passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character'
      });
    }

    await req.user.resetPassword(newPassword);

    // Revoke all existing tokens for security
    await TokenBlacklist.revokeAllUserTokens(req.user.id);

    res.json({
      success: true,
      message: 'Password changed successfully. Please log in again with your new password.'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error during password change'
    });
  }
});

module.exports = router;