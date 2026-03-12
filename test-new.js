const emailVerification = require('./email-verification');

async function test() {
  console.log('=== Test New Usage ===\n');
  
  // New usage pattern
  console.log('Check: test@gmail.com');
  const result1 = await emailVerification({ email: 'test@gmail.com', checkMX: true });
  console.log('Valid:', result1.valid);
  
  console.log('\nCheck: user@mailinator.com');
  const result2 = await emailVerification({ email: 'user@mailinator.com', checkMX: true });
  console.log('Valid:', result2.valid);
  
  console.log('\nCheck: invalid-email');
  const result3 = await emailVerification({ email: 'invalid-email', checkMX: true });
  console.log('Valid:', result3.valid);
}

test();
