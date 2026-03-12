const ratelimiting = require('./rate-limit');

// Test the key generation
const middleware = ratelimiting({
  mode: 'LIVE',
  by: 'userId',
  ipPrimary: true,
  fallbackToIP: true,
  refillRate: 5,
  interval: 10,
  capacity: 10
});

console.log('=== Debug: Rate Limit Key Generation ===\n');

// First request - user1 from IP 1.2.3.4
const req1 = { 
  ip: '1.2.3.4',
  headers: { 'x-user-id': 'user1' },
  connection: { remoteAddress: '1.2.3.4' }
};

let res1 = {
  set: (k, v) => console.log(`Header: ${k}=${v}`),
  status: (code) => { console.log(`Status: ${code}`); return { json: (d) => console.log('JSON:', d) }; },
  json: (d) => console.log('JSON:', d)
};

console.log('Request 1:');
middleware(req1, res1, () => console.log('Next called'));

// Second request - same IP, different userId
const req2 = { 
  ip: '1.2.3.4',
  headers: { 'x-user-id': 'user2' },
  connection: { remoteAddress: '1.2.3.4' }
};

console.log('\nRequest 2:');
let blocked2 = false;
let res2 = {
  set: (k, v) => console.log(`Header: ${k}=${v}`),
  status: (code) => { 
    console.log(`Status: ${code}`);
    if (code === 429) blocked2 = true;
    return { json: (d) => console.log('JSON:', d) }; 
  },
  json: (d) => console.log('JSON:', d)
};
middleware(req2, res2, () => console.log('Next called'));

console.log('\n=== Test Complete ===');
console.log('Blocked:', blocked2);
