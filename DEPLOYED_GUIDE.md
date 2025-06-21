# 🚀 Hướng dẫn Deploy lên Railway - Chi tiết

## Bước 1: Chuẩn bị project

### 1.1 Tạo folder project và setup files
```bash
mkdir nodejs-auth-railway
cd nodejs-auth-railway

# Copy tất cả files từ artifact vào folder này
# Hoặc clone từ GitHub repository
```

### 1.2 Cài đặt dependencies
```bash
npm install
```

### 1.3 Test chạy local
```bash
# Tạo file .env từ .env.example
cp .env.example .env

# Cập nhật DATABASE_URL với PostgreSQL local (nếu có)
# Hoặc skip bước này và test trực tiếp trên Railway

npm run dev
```

## Bước 2: Setup Railway Account

### 2.1 Tạo account Railway
1. Truy cập [railway.app](https://railway.app)
2. Sign up với GitHub account
3. Verify email

### 2.2 Install Railway CLI (optional)
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login
```

## Bước 3: Tạo PostgreSQL Database

### 3.1 Tạo new project
1. Click "New Project" trên Railway dashboard
2. Chọn "Empty Project"
3. Đặt tên project: `nodejs-auth-api`

### 3.2 Add PostgreSQL service
1. Click "+" trong project
2. Chọn "Database" → "PostgreSQL"
3. Đợi PostgreSQL deploy xong (2-3 phút)

### 3.3 Lấy DATABASE_URL
1. Click vào PostgreSQL service
2. Vào tab "Variables"
3. Copy giá trị của `DATABASE_URL`
4. Format sẽ giống: `postgresql://postgres:password@host:port/railway`

## Bước 4: Deploy Node.js Application

### 4.1 Connect GitHub repository

**Option A: Deploy từ GitHub**
1. Push code lên GitHub repository
2. Trong Railway project, click "+"
3. Chọn "GitHub Repo"
4. Connect và authorize Railway với GitHub
5. Chọn repository chứa code

**Option B: Deploy từ local với Railway CLI**
```bash
# Trong folder project
railway link
railway up
```

### 4.2 Cấu hình Environment Variables
Trong Railway dashboard → Service → Variables tab, thêm:

```bash
NODE_ENV=production
DATABASE_URL=<your_postgresql_database_url_from_step_3>
JWT_SECRET=<generate_this>
JWT_REFRESH_SECRET=<generate_this>
API_KEY=<your_api_key>
FRONTEND_URL=https://your-frontend-domain.com
```

### 4.3 Generate secure secrets
```bash
# Generate JWT_SECRET (64 bytes hex)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate JWT_REFRESH_SECRET (64 bytes hex) 
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generate API_KEY (32 bytes hex)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy output và paste vào Railway Variables.

## Bước 5: Verify Deployment

### 5.1 Check deployment status
1. Trong Railway dashboard, xem Deployments tab
2. Đợi build & deploy hoàn thành (5-10 phút)
3. Status sẽ chuyển thành "Success"

### 5.2 Get application URL
1. Trong Service settings → Networking
2. Click "Generate Domain"  
3. URL sẽ có dạng: `https://your-app-name.railway.app`

### 5.3 Test API endpoints

**Health check:**
```bash
curl https://your-app-name.railway.app/health
```

**Register user:**
```bash
curl -X POST https://your-app-name.railway.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "username": "testuser", 
    "password": "password123",
    "full_name": "Test User"
  }'
```

**Login:**
```bash
curl -X POST https://your-app-name.railway.app/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "test@example.com",
    "password": "password123"
  }'
```

## Bước 6: Setup Custom Domain (Optional)

### 6.1 Add custom domain
1. Trong Service settings → Networking
2. Click "Custom Domain"
3. Nhập domain của bạn: `api.yourdomain.com`

### 6.2 Configure DNS
1. Trong DNS settings của domain
2. Thêm CNAME record:
   - Name: `api`
   - Value: `your-app-name.railway.app`
3. Đợi DNS propagate (5-60 phút)

## Bước 7: Monitoring và Logs

### 7.1 View logs
1. Railway dashboard → Service → Logs tab
2. Hoặc dùng CLI: `railway logs`

### 7.2 Monitor metrics
1. Railway dashboard → Service → Metrics tab
2. Xem CPU, Memory, Network usage

## Bước 8: CI/CD Setup (GitHub Auto-Deploy)

### 8.1 Automatic deployments
Railway tự động deploy khi push code lên GitHub branch đã connect.

### 8.2 Environment-specific deploys
```bash
# Deploy staging branch to staging service
railway link --service staging
railway up --branch staging

# Deploy main branch to production service  
railway link --service production
railway up --branch main
```

## 🔧 Troubleshooting

### Database connection failed
```bash
# Check PostgreSQL service status
# Verify DATABASE_URL format
# Ensure DATABASE_URL includes correct credentials
```

### Build failed
```bash
# Check Node.js version compatibility in package.json engines
# Verify all dependencies are in package.json
# Check for missing environment variables
```

### App crashed after deploy
```bash
# Check Railway logs for error details
# Verify PORT environment variable (Railway auto-sets this)
# Ensure all required env vars are set
```

### 502 Bad Gateway
```bash
# App might be crashing on startup  
# Check if app is listening on process.env.PORT
# Verify database connection is working
```

## 🏥 Health Monitoring

### Setup health checks
Railway automatically monitors your `/health` endpoint.

### Custom monitoring
```javascript
// Add to server.js for better monitoring
app.get('/metrics', (req, res) => {
  res.json({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: Date.now()
  });
});
```

## 💰 Cost Optimization

### Free tier limits
- Railway Free: $5 credit/month 
- PostgreSQL: ~$5-10/month based on usage
- App hosting: ~$0-5/month based on usage

### Optimize costs
1. Use connection pooling (đã có trong code)
2. Implement proper logging levels
3. Monitor resource usage
4. Consider upgrading to Pro plan for production

## 🔒 Production Security Checklist

- ✅ Strong JWT secrets (64+ bytes)
- ✅ HTTPS enabled (Railway tự động)
- ✅ Environment variables set
- ✅ Rate limiting configured
- ✅ Input validation enabled
- ✅ CORS properly configured
- ✅ API keys secured
- ✅ Database credentials secured
- ✅ Error messages don't leak sensitive info
- ✅ Logging configured properly

Chúc bạn deploy thành công! 🎉