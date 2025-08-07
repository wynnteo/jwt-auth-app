# JWT Authentication System

A production-ready JWT authentication system built with Node.js, Express, and MySQL. This system includes email verification, password reset, rate limiting, token blacklisting, and comprehensive security features.

## ✨ Features

- **JWT Authentication**: Secure token-based authentication
- **Email Verification**: Account verification via email
- **Password Reset**: Secure password reset functionality
- **Rate Limiting**: Protection against brute force attacks
- **Token Blacklisting**: Logout and token revocation support
- **Security Headers**: Helmet.js for enhanced security
- **Input Validation**: Joi validation for all inputs
- **CORS Protection**: Configurable cross-origin resource sharing
- **MySQL Integration**: Robust database operations
- **Email Templates**: Beautiful HTML email templates
- **Profile Management**: User profile updates
- **Password Strength**: Enforced strong password requirements

## 🚀 Quick Start

### Prerequisites

- Node.js 14+ 
- MySQL 5.7+ or 8.0+
- Gmail account (for email functionality)

### Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd jwt-auth-app
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up MySQL database**
```bash
# Login to MySQL
mysql -u root -p

# Run the database schema
source database/schema.sql
```

4. **Configure environment variables**
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your configuration
```

5. **Configure Gmail for email sending**
   - Enable 2-factor authentication on your Gmail account
   - Generate an App Password: Go to Google Account Settings → Security → 2-Step Verification → App passwords
   - Use the generated app password in your `.env` file

6. **Start the server**
```bash
# Development mode
npm run dev

# Production mode
npm start
```

The server will run on `http://localhost:3000`

## 📁 Project Structure

```
jwt-auth-app/
├── server.js                 # Main application entry point
├── package.json              # Project dependencies
├── .env.example              # Environment variables template
├── .gitignore                # Git ignore rules
├── README.md                 # Project documentation
├── config/
│   ├── database.js          # MySQL database configuration
│   └── email.js             # Email service configuration
├── models/
│   └── User.js              # User model with database operations
├── middleware/
│   ├── auth.js              # JWT authentication middleware
│   ├── rateLimiter.js       # Rate limiting configurations
│   └── validation.js        # Input validation middleware
├── routes/
│   └── auth.js              # Authentication routes
├── utils/
│   ├── tokenBlacklist.js    # Token blacklist management
│   └── emailTemplates.js    # HTML email templates
├── database/
│   └── schema.sql           # Database schema and setup
└── tests/
    └── (test files)         # Unit and integration tests
```

## 🔧 Environment Configuration

Create a `.env` file in the root directory:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-make-it-long-and-random
JWT_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your-database-password
DB_NAME=jwt_auth_db

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-gmail-app-password
FROM_EMAIL=noreply@yourapp.com

# Frontend Configuration
FRONTEND_URL=http://localhost:3000

# CORS Configuration
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

### 🔑 JWT Secret Generation

Generate a secure JWT secret:

```bash
# Using openssl (recommended)
openssl rand -base64 64

# Using Node.js
node -e "console.log(require('crypto').randomBytes(64).toString('base64'));"
```

## 📚 API Documentation

### Base URL
```
http://localhost:3000/api/auth
```

### Endpoints

#### 1. Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com", 
  "password": "SecurePass123!"
}
```

#### 2. Verify Email
```http
POST /api/auth/verify-email/:token
```

#### 3. Resend Verification Email
```http
POST /api/auth/resend-verification
Content-Type: application/json

{
  "email": "john@example.com"
}
```

#### 4. Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### 5. Forgot Password
```http
POST /api/auth/forgot-password
Content-Type: application/json

{
  "email": "john@example.com"
}
```

#### 6. Reset Password
```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "password": "NewSecurePass123!"
}
```

#### 7. Get Profile (Protected)
```http
GET /api/auth/profile
Authorization: Bearer <your-jwt-token>
```

#### 8. Update Profile (Protected)
```http
PUT /api/auth/profile
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "name": "John Smith"
}
```

#### 9. Change Password (Protected)
```http
POST /api/auth/change-password
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "currentPassword": "SecurePass123!",
  "newPassword": "NewSecurePass456!"
}
```

#### 10. Refresh Token (Protected)
```http
POST /api/auth/refresh
Authorization: Bearer <your-jwt-token>
```

#### 11. Logout (Protected)
```http
POST /api/auth/logout
Authorization: Bearer <your-jwt-token>
```

#### 12. Logout All Devices (Protected)
```http
POST /api/auth/logout-all
Authorization: Bearer <your-jwt-token>
```

## 🛡️ Security Features

### Password Requirements
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter  
- At least 1 number
- At least 1 special character (@$!%*?&)

### Rate Limiting
- **General API**: 100 requests per 15 minutes
- **Authentication**: 5 attempts per 15 minutes
- **Password Reset**: 3 attempts per hour
- **Email Verification**: 3 resends per hour

### Token Security
- **Short-lived tokens**: 15 minutes expiration
- **Token blacklisting**: Logout invalidates tokens
- **JTI tracking**: Unique token identifiers
- **Automatic cleanup**: Expired tokens are removed

### Security Headers
- Content Security Policy
- XSS Protection
- Frame Options
- HSTS (in production)

## 🧪 Testing

### Manual Testing with cURL

1. **Register a new user**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

2. **Login**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

3. **Access protected route**
```bash
curl -X GET http://localhost:3000/api/auth/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

4. **Test rate limiting**
```bash
# This will trigger rate limiting after 5 attempts
for i in {1..6}; do
  echo "Attempt $i:"
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"wrong@email.com","password":"wrongpass"}'
  echo -e "\n---"
done
```

### Running Tests
```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch
```

## 🚀 Deployment

### Production Environment Variables

```env
NODE_ENV=production
JWT_SECRET=<64-character-random-string>
DB_HOST=<production-db-host>
DB_USER=<production-db-user>
DB_PASSWORD=<production-db-password>
FRONTEND_URL=https://yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

### Production Checklist

- [ ] Use strong, unique JWT secret (64+ characters)
- [ ] Enable HTTPS
- [ ] Configure proper CORS origins
- [ ] Set up database backups
- [ ] Configure email service (not Gmail for production)
- [ ] Set up monitoring and logging
- [ ] Configure reverse proxy (Nginx/Apache)
- [ ] Set up SSL certificates
- [ ] Configure firewall rules
- [ ] Set up database connection pooling

### Docker Deployment (Optional)

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
```

## 🔍 Troubleshooting

### Common Issues

1. **Email not sending**
   - Check Gmail App Password
   - Verify SMTP settings
   - Check firewall/network restrictions

2. **Database connection failed**
   - Verify MySQL is running
   - Check database credentials
   - Ensure database exists

3. **JWT token invalid**
   - Check JWT_SECRET configuration
   - Verify token format (Bearer token)
   - Check token expiration

4. **Rate limiting too aggressive**
   - Adjust limits in `middleware/rateLimiter.js`
   - Clear rate limit cache (restart server)

5. **CORS errors**
   - Check ALLOWED_ORIGINS configuration
   - Verify frontend URL matches

## 📈 Performance Optimizations

- **Connection Pooling**: MySQL connection pool for efficient database usage
- **Rate Limiting**: Prevents API abuse and protects server resources  
- **Token Cleanup**: Automatic removal of expired blacklisted tokens
- **Indexed Queries**: Database indexes for faster lookups
- **Password Hashing**: Optimized bcrypt rounds for security/performance balance

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Express.js and MySQL
- JWT implementation using jsonwebtoken
- Security powered by bcryptjs and helmet
- Validation using Joi
- Email functionality with nodemailer

## 📞 Support

If you encounter any issues or have questions:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Search existing issues on GitHub
3. Create a new issue with detailed information
4. Provide error logs and environment details

---

**Happy Coding! 🚀**