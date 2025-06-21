const axios = require('axios');

const BASE_URL = 'http://localhost:3000/api/auth';

// Test data
const testUser = {
  email: 'test@example.com',
  username: 'testuser',
  password: 'password123',
  full_name: 'Test User'
};

const testLogin = {
  identifier: 'test@example.com',
  password: 'password123'
};

async function testRegister() {
  try {
    console.log('🧪 Testing Register API...');
    const response = await axios.post(`${BASE_URL}/register`, testUser);
    console.log('✅ Register successful:', response.data);
    return response.data;
  } catch (error) {
    console.error('❌ Register failed:', {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message
    });
    return null;
  }
}

async function testLogin() {
  try {
    console.log('🧪 Testing Login API...');
    const response = await axios.post(`${BASE_URL}/login`, testLogin);
    console.log('✅ Login successful:', response.data);
    return response.data;
  } catch (error) {
    console.error('❌ Login failed:', {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message
    });
    return null;
  }
}

async function testProfile(accessToken) {
  try {
    console.log('🧪 Testing Profile API...');
    const response = await axios.get(`${BASE_URL}/profile`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    console.log('✅ Profile successful:', response.data);
    return response.data;
  } catch (error) {
    console.error('❌ Profile failed:', {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message
    });
    return null;
  }
}

async function runTests() {
  console.log('🚀 Starting API tests...\n');
  
  // Test register
  const registerResult = await testRegister();
  
  if (registerResult) {
    console.log('\n' + '='.repeat(50) + '\n');
    
    // Test login
    const loginResult = await testLogin();
    
    if (loginResult) {
      console.log('\n' + '='.repeat(50) + '\n');
      
      // Test profile with access token
      await testProfile(loginResult.data.tokens.accessToken);
    }
  }
  
  console.log('\n🏁 Tests completed!');
}

// Run tests
runTests().catch(console.error); 