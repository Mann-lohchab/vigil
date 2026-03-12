const sqlinjection = require('./sql-injection');

async function test() {
  console.log('=== Test SQL Injection Detection ===\n');

  // Test malicious SQL
  console.log('Test 1: OR 1=1');
  const result1 = await sqlinjection({ text: "'; OR 1=1--" });
  console.log('Safe:', result1.safe, '| Detected:', result1.detected);

  // Test UNION SELECT
  console.log('\nTest 2: UNION SELECT');
  const result2 = await sqlinjection({ text: "' UNION SELECT * FROM users--" });
  console.log('Safe:', result2.safe, '| Detected:', result2.detected);

  // Test normal text
  console.log('\nTest 3: Normal text');
  const result3 = await sqlinjection({ text: "Hello World" });
  console.log('Safe:', result3.safe, '| Detected:', result3.detected);

  // Test DROP TABLE
  console.log('\nTest 4: DROP TABLE');
  const result4 = await sqlinjection({ text: "DROP TABLE users" });
  console.log('Safe:', result4.safe, '| Detected:', result4.detected);

  // Test with data object
  console.log('\nTest 5: Data object with injection');
  const result5 = await sqlinjection({ 
    data: { 
      username: "admin", 
      password: "' OR '1'='1" 
    } 
  });
  console.log('Safe:', result5.safe, '| Detected:', result5.detected);

  // Test safe data
  console.log('\nTest 6: Safe data object');
  const result6 = await sqlinjection({ 
    data: { 
      username: "john", 
      email: "john@example.com" 
    } 
  });
  console.log('Safe:', result6.safe, '| Detected:', result6.detected);

  console.log('\n=== Tests Complete ===');
}

test();
