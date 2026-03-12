const emailVerification = require('./email-verification');

async function test() {
  console.log('=== Test Email Verification ===\n');
  
  // Test valid Gmail
  console.log('--- Test: test@gmail.com ---');
  const result1 = await emailVerification.verify('test@gmail.com');
  console.log(JSON.stringify(result1, null, 2));
  
  // Test disposable email
  console.log('\n--- Test: test@mailinator.com ---');
  const result2 = await emailVerification.verify('test@mailinator.com');
  console.log(JSON.stringify(result2, null, 2));
  
  // Test invalid format
  console.log('\n--- Test: invalid-email ---');
  const result3 = await emailVerification.verify('invalid-email');
  console.log(JSON.stringify(result3, null, 2));
  
  console.log('\n=== Tests Complete ===');
}

test().catch(console.error);
