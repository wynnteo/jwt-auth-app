const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../config/database');

class User {
  constructor(userData) {
    this.id = userData.id;
    this.email = userData.email;
    this.password = userData.password;
    this.name = userData.name;
    this.email_verified = userData.email_verified;
    this.email_verification_token = userData.email_verification_token;
    this.email_verification_expires = userData.email_verification_expires;
    this.password_reset_token = userData.password_reset_token;
    this.password_reset_expires = userData.password_reset_expires;
    this.created_at = userData.created_at;
    this.updated_at = userData.updated_at;
  }

  static async create(userData) {
    const { email, password, name } = userData;
    
    try {
      const [existingUser] = await db.execute(
        'SELECT id FROM users WHERE email = ?',
        [email]
      );

      if (existingUser.length > 0) {
        throw new Error('User already exists');
      }

      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      // Generate email verification token
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      const [result] = await db.execute(
        `INSERT INTO users (email, password, name, email_verification_token, email_verification_expires) 
         VALUES (?, ?, ?, ?, ?)`,
        [email, hashedPassword, name, verificationToken, verificationExpires]
      );

      const [newUser] = await db.execute(
        'SELECT * FROM users WHERE id = ?',
        [result.insertId]
      );

      return new User(newUser[0]);
    } catch (error) {
      throw error;
    }
  }

  static async findByEmail(email) {
    try {
      const [users] = await db.execute(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );

      if (users.length === 0) return null;
      return new User(users[0]);
    } catch (error) {
      throw error;
    }
  }

  static async findById(id) {
    try {
      const [users] = await db.execute(
        'SELECT * FROM users WHERE id = ?',
        [id]
      );

      if (users.length === 0) return null;
      return new User(users[0]);
    } catch (error) {
      throw error;
    }
  }

  static async findByVerificationToken(token) {
    try {
      const [users] = await db.execute(
        'SELECT * FROM users WHERE email_verification_token = ? AND email_verification_expires > NOW()',
        [token]
      );

      if (users.length === 0) return null;
      return new User(users[0]);
    } catch (error) {
      throw error;
    }
  }

  static async findByPasswordResetToken(token) {
    try {
      const [users] = await db.execute(
        'SELECT * FROM users WHERE password_reset_token = ? AND password_reset_expires > NOW()',
        [token]
      );

      if (users.length === 0) return null;
      return new User(users[0]);
    } catch (error) {
      throw error;
    }
  }

  async validatePassword(password) {
    return await bcrypt.compare(password, this.password);
  }

  async verifyEmail() {
    try {
      await db.execute(
        'UPDATE users SET email_verified = TRUE, email_verification_token = NULL, email_verification_expires = NULL WHERE id = ?',
        [this.id]
      );
      this.email_verified = true;
      this.email_verification_token = null;
      this.email_verification_expires = null;
    } catch (error) {
      throw error;
    }
  }

  async generatePasswordResetToken() {
    try {
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      await db.execute(
        'UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?',
        [resetToken, resetExpires, this.id]
      );

      this.password_reset_token = resetToken;
      this.password_reset_expires = resetExpires;
      
      return resetToken;
    } catch (error) {
      throw error;
    }
  }

  async resetPassword(newPassword) {
    try {
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      await db.execute(
        'UPDATE users SET password = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?',
        [hashedPassword, this.id]
      );

      this.password = hashedPassword;
      this.password_reset_token = null;
      this.password_reset_expires = null;
    } catch (error) {
      throw error;
    }
  }

  async regenerateEmailVerificationToken() {
    try {
      const verificationToken = crypto.randomBytes(32).toString('hex');
      const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

      await db.execute(
        'UPDATE users SET email_verification_token = ?, email_verification_expires = ? WHERE id = ?',
        [verificationToken, verificationExpires, this.id]
      );

      this.email_verification_token = verificationToken;
      this.email_verification_expires = verificationExpires;
      
      return verificationToken;
    } catch (error) {
      throw error;
    }
  }

  async updateProfile(name) {
    try {
      await db.execute(
        'UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [name, this.id]
      );
      this.name = name;
      return this;
    } catch (error) {
      throw error;
    }
  }

  toJSON() {
    const { password, email_verification_token, password_reset_token, ...userWithoutSensitiveData } = this;
    return userWithoutSensitiveData;
  }
}

module.exports = User;