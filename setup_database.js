const { query, initializeDatabase } = require('./config/database');
const bcrypt = require('bcryptjs');

async function setupDatabase() {
  try {
    console.log('🚀 Bắt đầu setup database...');
    
    // Initialize database tables
    await initializeDatabase();
    
    // Thêm cột role nếu chưa có
    console.log('🔧 Kiểm tra và thêm cột role...');
    
    // Kiểm tra xem cột role đã tồn tại chưa
    const checkColumn = await query(`
      PRAGMA table_info(users)
    `);
    
    const hasRoleColumn = checkColumn.rows.some(col => col.name === 'role');
    
    if (!hasRoleColumn) {
      await query(`
        ALTER TABLE users 
        ADD COLUMN role TEXT DEFAULT 'user'
      `);
      console.log('✅ Cột role đã được thêm');
    } else {
      console.log('✅ Cột role đã tồn tại');
    }
    
    // Kiểm tra xem đã có admin chưa
    const adminCheck = await query(`
      SELECT COUNT(*) as count FROM users WHERE role = 'admin'
    `);
    
    if (parseInt(adminCheck.rows[0].count) === 0) {
      console.log('👑 Chưa có admin user, đang tạo...');
      
      // Tạo admin user mặc định
      const adminPassword = 'admin123'; // Mật khẩu mặc định
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      
      const adminUser = await query(`
        INSERT INTO users (email, username, password_hash, full_name, role, is_active, is_verified)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, email, username, full_name, role
      `, [
        'admin@example.com',
        'admin',
        hashedPassword,
        'Administrator',
        'admin',
        true,
        true
      ]);
      
      console.log('✅ Đã tạo admin user:');
      console.log(`   Email: ${adminUser.rows[0].email}`);
      console.log(`   Username: ${adminUser.rows[0].username}`);
      console.log(`   Password: ${adminPassword}`);
      console.log('⚠️  Hãy đổi mật khẩu sau khi đăng nhập!');
    } else {
      console.log('✅ Đã có admin user trong database');
    }
    
    // Hiển thị thống kê
    const userStats = await query(`
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN role = 'admin' THEN 1 END) as admin_users,
        COUNT(CASE WHEN is_active = true THEN 1 END) as active_users
      FROM users
    `);
    
    const stats = userStats.rows[0];
    console.log('\n📊 Thống kê database:');
    console.log(`   Tổng users: ${stats.total_users}`);
    console.log(`   Admin users: ${stats.admin_users}`);
    console.log(`   Active users: ${stats.active_users}`);
    
    console.log('\n🎉 Setup database hoàn tất!');
    
  } catch (error) {
    console.error('❌ Lỗi khi setup database:', error);
  } finally {
    process.exit(0);
  }
}

setupDatabase(); 