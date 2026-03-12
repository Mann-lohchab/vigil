/**
 * Vigil - Rate Limiting Middleware for Express.js
 * 
 * Implements token bucket algorithm for rate limiting
 */

const DEFAULT_OPTIONS = {
  mode: 'LIVE',
  refillRate: 5,
  interval: 10,
  capacity: 10,
  by: 'ip',
  keyGenerator: null,
  // NEW OPTIONS FOR SECURITY
  ipPrimary: true,        // IP is always the primary key (prevent header spoofing)
  fallbackToIP: true,    // Fall back to IP if custom identifier not found
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  handler: null,
  headers: {
    remaining: 'X-RateLimit-Remaining',
    reset: 'X-RateLimit-Reset',
    limit: 'X-RateLimit-Limit'
  },
  disableStart: false,
  storage: {
    type: 'memory'
  }
};

// In-memory storage for rate limit data
const rateLimitStore = new Map();

/**
 * Get the current timestamp in seconds
 */
function getCurrentTimestamp() {
  return Math.floor(Date.now() / 1000);
}

/**
 * Get client IP address
 */
function getClientIP(req) {
  return req.ip || 
         req.connection?.remoteAddress || 
         req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         'unknown';
}

/**
 * Generate a unique key for rate limiting
 * IP is ALWAYS primary to prevent header spoofing
 */
function generateKey(req, options) {
  const identifier = options.by;
  const clientIP = getClientIP(req);
  
  // IP is ALWAYS the primary key (unless using custom keyGenerator)
  if (options.ipPrimary || options.keyGenerator === null) {
    // If identifier is different from 'ip', append it to IP
    if (identifier && identifier !== 'ip' && identifier !== 'ipAddress') {
      let customValue = null;
      
      if (identifier === 'userId') {
        // Try various sources for user ID
        customValue = req.headers['x-user-id'] || 
                     req.body?.userId || 
                     req.query?.userId || 
                     req.user?.id || 
                     null;
      } else if (typeof identifier === 'function') {
        customValue = identifier(req);
      } else if (typeof identifier === 'string') {
        const headerKey = `x-${identifier.toLowerCase().replace('id', '-id')}`;
        customValue = req.headers[headerKey] || req[identifier] || null;
      }
      
      // Only append if custom value exists AND fallbackToIP is false
      // Otherwise, use just IP (more secure)
      if (customValue && !options.fallbackToIP) {
        return `${clientIP}:${customValue}`;
      }
    }
    
    // Default: use IP only (most secure - prevents header spoofing)
    return clientIP;
  }
  
  // If keyGenerator is provided, use it
  if (options.keyGenerator) {
    return options.keyGenerator(req);
  }
  
  // Fallback
  return clientIP;
}

/**
 * Get or create rate limit data for a key
 */
function getRateLimitData(key, options) {
  const now = getCurrentTimestamp();
  
  if (!rateLimitStore.has(key)) {
    rateLimitStore.set(key, {
      tokens: options.capacity,
      lastRefill: now
    });
  }
  
  return rateLimitStore.get(key);
}

/**
 * Refill tokens based on elapsed time
 */
function refillTokens(data, options) {
  const now = getCurrentTimestamp();
  const elapsed = now - data.lastRefill;
  
  if (elapsed > 0) {
    const tokensToAdd = Math.floor(elapsed / options.interval) * options.refillRate;
    data.tokens = Math.min(options.capacity, data.tokens + tokensToAdd);
    data.lastRefill = now;
  }
  
  return data;
}

/**
 * Consume a token from the bucket
 */
function consumeToken(data, options) {
  if (data.tokens >= 1) {
    data.tokens -= 1;
    return true;
  }
  return false;
}

/**
 * Clean up expired entries from the store
 */
function cleanupStore() {
  const now = getCurrentTimestamp();
  const maxAge = 3600; // 1 hour
  
  for (const [key, data] of rateLimitStore.entries()) {
    if (now - data.lastRefill > maxAge) {
      rateLimitStore.delete(key);
    }
  }
}

/**
 * Create rate limiting middleware
 * 
 * @param {Object} options - Rate limiting options
 * @param {string} [options.mode='LIVE'] - Mode: 'LIVE' or 'TEST'
 * @param {string|Function} [options.by='ip'] - Custom identifier: 'ip', 'userId', or function
 * @param {boolean} [options.ipPrimary=true] - IP is always primary key (prevents spoofing)
 * @param {boolean} [options.fallbackToIP=true] - Use IP if custom identifier not found
 * @param {number} [options.refillRate=5] - Number of tokens to add per interval
 * @param {number} [options.interval=10] - Interval in seconds between refills
 * @param {number} [options.capacity=10] - Maximum token capacity
 * @param {Function} [options.keyGenerator] - Custom function to generate rate limit key
 * @param {Function} [options.handler] - Custom handler for rate limit exceeded
 * @param {Object} [options.headers] - Custom header names
 * @param {boolean} [options.disableStart=false] - Disable starting token count at capacity
 * @returns {Function} Express middleware
 */
function ratelimiting(options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  
  // Validate options
  if (opts.refillRate <= 0) {
    throw new Error('refillRate must be a positive number');
  }
  if (opts.interval <= 0) {
    throw new Error('interval must be a positive number');
  }
  if (opts.capacity <= 0) {
    throw new Error('capacity must be a positive number');
  }
  if (!['LIVE', 'TEST'].includes(opts.mode)) {
    throw new Error('mode must be either "LIVE" or "TEST"');
  }

  // Start cleanup interval if not disabled
  if (!opts.disableStart) {
    setInterval(cleanupStore, 60000); // Clean up every minute
  }

  return (req, res, next) => {
    // In TEST mode, skip rate limiting
    if (opts.mode === 'TEST') {
      return next();
    }

    // Generate the rate limit key
    const key = generateKey(req, opts);
    
    // Get and update rate limit data
    let data = getRateLimitData(key, opts);
    data = refillTokens(data, opts);
    
    const remaining = Math.floor(data.tokens);
    const limit = opts.capacity;
    const reset = data.lastRefill + opts.interval;
    
    // Try to consume a token
    const allowed = consumeToken(data, opts);
    
    // Set rate limit headers
    if (opts.headers) {
      res.set(opts.headers.remaining, Math.max(0, remaining).toString());
      res.set(opts.headers.limit, limit.toString());
      res.set(opts.headers.reset, reset.toString());
    }

    if (!allowed) {
      // Rate limit exceeded
      if (opts.handler) {
        return opts.handler(req, res);
      }
      
      return res.status(429).json({
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: opts.interval
      });
    }

    next();
  };
}

/**
 * Reset rate limit for a specific key
 */
ratelimiting.reset = function(key) {
  if (key) {
    rateLimitStore.delete(key);
  } else {
    rateLimitStore.clear();
  }
};

/**
 * Get current rate limit info for a key
 */
ratelimiting.getRateLimitInfo = function(key) {
  const data = rateLimitStore.get(key);
  if (!data) {
    return null;
  }
  return {
    tokens: data.tokens,
    lastRefill: data.lastRefill
  };
};

/**
 * Create a rate limiter with pre-configured options
 */
ratelimiting.create = function(options) {
  return ratelimiting(options);
};

module.exports = ratelimiting;
