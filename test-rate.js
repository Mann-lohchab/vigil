const ratelimiting = require('./rate-limit');

// Create middleware with IP combination
const middleware = ratelimiting({
  mode: 'LIVE',
  by: 'userId',
  combineIP: true,
  refillRate: 5,
  interval: 10,
  capacity: 10
});

console.log('=== Test: Rate Limit with IP Fallback ===\n');

// First request - user1 from IP 1.2.3.4
const req1 = { 
  ip: '1.2.3.4',
  headers: { 'x-user-id': 'user1' },
  connection: { remoteAddress: '1.2.3.4' }
};
let next1 = false;
const res1 = {
  set: () => {},
  status: () => ({ json: () => {} }),
  json: () => {}
};
middleware(req1, res1, () => { next1 = true; });
console.log('Request 1 (user1 from 1.2.3.4): Allowed =', next1);

// Second request - same IP but different userId - should be blocked
const req2 = { 
  ip: '1.2.3.4',
  headers: { 'x-user-id': 'user2' },
  connection: { remoteAddress: '1.2.3.4' }
};
let blocked2 = false;
const res2 = {
  set: () => {},
  status: (code) => { 
    if (code === 429) blocked2 = true;
    return { json: () => {} };
  },
  json: () => {}
};
middleware(req2, res2, () => {});
console.log('Request 2 (user2 from same IP 1.2.3.4): Blocked =', blocked2);

// Third request - different IP with user1 - should be allowed (different bucket)
const req3 = { 
  ip: '5.6.7.8',
  headers: { 'x-user-id': 'user1' },
  connection: { remoteAddress: '5.6.7.8' }
};
let next3 = false;
const res3 = {
  set: () => {},
  status: () => ({ json: () => {} }),
  json: () => {}
};
middleware(req3, res3, () => { next3 = true; });
console.log('Request 3 (user1 from different IP 5.6.7.8): Allowed =', next3);

console.log('\n=== Test Complete ===');
