const vigil = require('./index.js');

console.log('=== Test 1: Create middleware ===');
const middleware = vigil({
  mode: 'LIVE',
  by: 'userId',
  refillRate: 5,
  interval: 10,
  capacity: 10
});
console.log('Middleware created - OK');

console.log('\n=== Test 2: Simulate requests ===');
const mockReq = { 
  ip: '127.0.0.1',
  headers: { 'x-user-id': 'user123' },
  connection: { remoteAddress: '127.0.0.1' }
};
const mockRes = {
  set: function(key, val) { console.log('Header:', key, '=', val); },
  status: function(code) { return { json: function(data) { console.log('Response:', code, JSON.stringify(data)); } }; },
  json: function(data) { console.log('JSON:', JSON.stringify(data)); }
};
var mockNext = function() { console.log('Next called'); };

// Test first request
middleware(mockReq, mockRes, mockNext);

// Check rate limit info
const info = vigil.getRateLimitInfo('user123');
console.log('Rate limit info:', JSON.stringify(info));

console.log('\n=== Test 3: Reset functionality ===');
vigil.reset('user123');
const infoAfterReset = vigil.getRateLimitInfo('user123');
console.log('After reset:', infoAfterReset);

console.log('\n=== All tests passed! ===');
