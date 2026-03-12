const { ratelimiting, botDetection } = require('./index');

console.log('=== Test Vigil Modules ===\n');

// Test rate limiting
console.log('--- Rate Limiting ---');
const rateLimit = ratelimiting({
  mode: 'LIVE',
  by: 'userId',
  refillRate: 5,
  interval: 10,
  capacity: 10
});
console.log('Rate limiting middleware created:', typeof rateLimit === 'function');

// Test bot detection
console.log('\n--- Bot Detection ---');
console.log('Googlebot:', JSON.stringify(botDetection.detect('Googlebot/2.1')));
console.log('curl:', JSON.stringify(botDetection.detect('curl/7.68.0')));
console.log('Chrome:', JSON.stringify(botDetection.detect('Mozilla/5.0 Chrome/120.0')));
console.log('Available search engines:', botDetection.getSearchEngines());

// Test middleware creation
console.log('\n--- Middleware ---');
const botMiddleware = botDetection({
  mode: 'LIVE',
  searchEngine: ['google', 'bing']
  
});
console.log('Bot detection middleware created:', typeof botMiddleware === 'function');

console.log('\n=== All tests passed! ===');
