const db = require('../config/database');

class TokenBlacklist {
  static async addToBlacklist(tokenJti, userId, expiresAt) {
    try {
      await db.execute(
        'INSERT INTO token_blacklist (token_jti, user_id, expires_at) VALUES (?, ?, ?)',
        [tokenJti, userId, expiresAt]
      );
    } catch (error) {
      throw error;
    }
  }

  static async isBlacklisted(tokenJti) {
    try {
      const [rows] = await db.execute(
        'SELECT id FROM token_blacklist WHERE token_jti = ? AND expires_at > NOW()',
        [tokenJti]
      );
      return rows.length > 0;
    } catch (error) {
      throw error;
    }
  }

  static async cleanupExpiredTokens() {
    try {
      await db.execute('DELETE FROM token_blacklist WHERE expires_at <= NOW()');
    } catch (error) {
      console.error('Failed to cleanup expired tokens:', error);
    }
  }

  static async revokeAllUserTokens(userId) {
    try {
      // In a production environment, you'd want to track all active tokens
      // For now, we'll just mark this timestamp and check it in middleware
      await db.execute(
        'UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [userId]
      );
    } catch (error) {
      throw error;
    }
  }
}

// Cleanup expired tokens every hour
setInterval(() => {
  TokenBlacklist.cleanupExpiredTokens();
}, 60 * 60 * 1000);

module.exports = TokenBlacklist;