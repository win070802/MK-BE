# Node.js Authentication API - Railway Deployment

API Node.js với chức năng đăng ký và đăng nhập, được thiết kế để deploy lên Railway với PostgreSQL database.

## 🚀 Tính năng

- ✅ Đăng ký tài khoản với validation
- ✅ Đăng nhập với email/username
- ✅ JWT Authentication (Access Token + Refresh Token)
- ✅ Profile management
- ✅ Rate limiting bảo mật
- ✅ Password hashing với bcrypt
- ✅ PostgreSQL database với connection pooling
- ✅ CORS và Security headers
- ✅ Error handling toàn diện
- ✅ API documentation
- ✅ Sẵn sàng deploy lên Railway

## 📁 Cấu trúc project

```
nodejs-auth-railway/
├── config/
│   └── database.js          # Cấu hình PostgreSQL
├── middleware/
│   └── auth.js              # JWT & API key middleware
├── routes/
│   └── auth.js              # Authentication routes
├── .env.example             # Environment variables template
├── .gitignore              # Git ignore rules
├── .dockerignore           # Docker ignore rules
├── package.json            # Dependencies & scripts
├── railway.json            # Railway deployment config
├── server.js               # Main server file
└── README.md               # Documentation
```

## 🛠️ Cài đặt và Chạy Local

### 1. Clone và cài đặt dependencies

```bash
git clone <your-repo-url>
cd nodejs-auth-railway
npm install
```

### 2. Cấu hình environment variables

Copy file `.env.example` thành `.env` và điền thông tin:

```bash
cp .env.example .env
```

Cập nhật các giá trị trong `.env`:
```env
PORT=3000
NODE_ENV=development
DATABASE_URL=postgresql://username:password@localhost:5432/your_database
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here
API_KEY=your-api-key-here
```

### 3. Chạy ứng dụng

```bash
# Development mode
npm run dev

# Production mode
npm start
```

Server sẽ chạy tại: `http://localhost:3000`

## 🚄 Deploy lên Railway

### 1. Tạo account Railway
- Đăng ký tại [railway.app](https://railway.app)
- Connect với GitHub account

### 2. Tạo PostgreSQL database
1. Tạo new project trên Railway
2. Add PostgreSQL service
3. Copy `DATABASE_URL` từ Variables tab

### 3. Deploy ứng dụng
1. Connect GitHub repository
2. Railway sẽ tự động detect Node.js project
3. Thêm environment variables:

```
NODE_ENV=production
DATABASE_URL=<your_railway_postgresql_url>
JWT_SECRET=<generate_strong_secret>
JWT_REFRESH_SECRET=<generate_strong_refresh_secret>
API_KEY=<your_api_key>
FRONTEND_URL=<your_frontend_domain>
```

### 4. Generate secrets
Tạo JWT secrets mạnh:
```bash
# Tạo JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Tạo JWT_REFRESH_SECRET  
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## 📚 API Documentation

### Base URL
- Local: `http://localhost:3000`
- Railway: `https://your-app-name.railway.app`

### Endpoints

#### 1. Health Check
```http
GET /health
```

#### 2. Đăng ký
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password123",
  "full_name": "Nguyễn Văn A"
}
```

#### 3. Đăng nhập
```http
POST /api/auth/login
Content-Type: application/json

{
  "identifier": "user@example.com", // email hoặc username
  "password": "password123"
}
```

#### 4. Lấy profile (cần token)
```http
GET /api/auth/profile
Authorization: Bearer <access_token>
```

#### 5. Refresh token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh_token>"
}
```

#### 6. Đăng xuất (cần token)
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refreshToken": "<refresh_token>"
}
```

## 🗄️ Database Schema

### Users Table
```sql
users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(255),
  is_active BOOLEAN DEFAULT true,
  is_verified BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP
)
```

### Refresh Tokens Table
```sql
refresh_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(255) UNIQUE NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  is_revoked BOOLEAN DEFAULT false
)
```

## 🔒 Bảo mật

- **Password Hashing**: bcrypt với salt rounds = 12
- **JWT**: Access token (1h) + Refresh token (7d)
- **Rate Limiting**: 5 login attempts / 15 minutes
- **CORS**: Configurable origins
- **Helmet**: Security headers
- **Validation**: Input sanitization
- **SQL Injection**: Parameterized queries

## 🔧 Customization

### Thêm middleware bảo mật
```javascript
const { authenticateApiKey } = require('./middleware/auth');

// Protect route với API key
router.get('/protected', authenticateApiKey, (req, res) => {
  // Your protected route logic
});
```

### Thêm role-based access
```javascript
const { requireAdmin } = require('./middleware/auth');

// Admin only route
router.get('/admin', authenticateToken, requireAdmin, (req, res) => {
  // Admin logic
});
```

## 🐛 Troubleshooting

### Database connection issues
1. Kiểm tra `DATABASE_URL` format đúng
2. Ensure PostgreSQL service đang chạy
3. Check network connectivity

### JWT token issues
1. Verify `JWT_SECRET` đã được set
2. Check token expiration
3. Ensure Bearer token format: `Bearer <token>`

### Railway deployment issues
1. Check build logs trong Railway dashboard
2. Verify environment variables
3. Ensure `PORT` variable được set đúng

## 📞 Support

Nếu có vấn đề, hãy tạo issue trong repository hoặc liên hệ qua email.

## 📄 License

MIT License - see LICENSE file for details.