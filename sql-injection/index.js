/**
 * Vigil - SQL Injection Protection Module
 * 
 * Detects and blocks SQL injection attempts in user input
 */

// SQL injection patterns to detect
const SQL_PATTERNS = [
  // Common SQL keywords (case insensitive)
  /\b(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|EXECUTE|UNION)\b/i,
  
  // Comment patterns
  /--/,
  /\/\*/,
  /\*\//,
  
  // Tautology patterns (always true)
  /('|")?\s*=\s*('|")?\s*(OR|AND)\b/i,
  /\bOR\s+1\s*=\s*1/i,
  /\bAND\s+1\s*=\s*1/i,
  /\bOR\s+'[^']*'\s*=\s*'[^']*'/i,
  /\bOR\s+\d+\s*=\s*\d+/i,
  
  // UNION-based injection
  /\bUNION\s+(ALL\s+)?SELECT/i,
  
  // Stacked queries
  /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i,
  
  // Information gathering
  /\bINFORMATION_SCHEMA\b/i,
  /\bSYSCAT\b/i,
  /\bSYS\.TABLES\b/i,
  
  // Common injection characters
  /(\b(SELECT|INSERT|UPDATE|DELETE).*\bFROM\b)/i,
  
  // Dangerous functions
  /\bLOAD_FILE\s*\(/i,
  /\bINTO\s+(OUTFILE|DUMPFILE)/i,
  /\bBENCHMARK\s*\(/i,
  /\bSLEEP\s*\(/i,
  /\bWAITFOR\s+(DELAY|LAZY)/i,
  
  // Hex encoding attempts
  /0x[0-9a-fA-F]+/,
  
  // Char encoding attempts
  /CHAR\s*\(\s*\d+\s*\)/i,
  
  // Base64 in SQL
  /FROM_BASE64\s*\(/i,
  /TO_BASE64\s*\(/i,
];

// Suspicious patterns that might indicate SQL injection
const SUSPICIOUS_PATTERNS = [
  /['"](?:\s*(?:OR|AND)\s*['"]?\d)/i,
  /['"][^'"]*['"][^'"]*(?:OR|AND)[^'"]*['"]/i,
  /\x00/,  // Null bytes
  /\r\n/,  // Newlines in input
  /\\x/i,  // Hex escapes
];

const DEFAULT_OPTIONS = {
  mode: 'LIVE',
  checkBody: true,
  checkQuery: true,
  checkParams: true,
  checkHeaders: false,
  patterns: SQL_PATTERNS,
  suspiciousPatterns: SUSPICIOUS_PATTERNS,
  handler: null,
  field: null,
  throwError: false
};

/**
 * Check text for SQL injection patterns
 */
function detectSQLInjection(text) {
  if (!text || typeof text !== 'string') {
    return { detected: false, patterns: [] };
  }

  const detectedPatterns = [];

  // Check against all patterns
  for (const pattern of SQL_PATTERNS) {
    if (pattern.test(text)) {
      detectedPatterns.push({
        pattern: pattern.toString(),
        matched: text.match(pattern)?.[0]
      });
    }
  }

  // Check against suspicious patterns
  for (const pattern of SUSPICIOUS_PATTERNS) {
    if (pattern.test(text)) {
      detectedPatterns.push({
        pattern: pattern.toString(),
        matched: text.match(pattern)?.[0],
        type: 'suspicious'
      });
    }
  }

  return {
    detected: detectedPatterns.length > 0,
    patterns: detectedPatterns
  };
}

/**
 * Scan input data for SQL injection
 */
function scanInput(data, options) {
  const results = [];
  
  if (!data) return results;

  // Handle string input
  if (typeof data === 'string') {
    const result = detectSQLInjection(data);
    if (result.detected) {
      results.push({
        value: data,
        ...result
      });
    }
    return results;
  }

  // Handle object/array input
  if (typeof data === 'object') {
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === 'string') {
        const result = detectSQLInjection(value);
        if (result.detected) {
          results.push({
            field: key,
            value: value,
            ...result
          });
        }
      } else if (typeof value === 'object') {
        // Recursively check nested objects
        const nestedResults = scanInput(value, options);
        results.push(...nestedResults);
      }
    }
  }

  return results;
}

/**
 * Main SQL injection check function
 * 
 * @param {Object} options - Options object
 * @param {string} [options.text] - Text to check
 * @param {Object} [options.data] - Data object to scan
 * @param {boolean} [options.checkBody=true] - Check request body
 * @param {boolean} [options.checkQuery=true] - Check query parameters
 * @returns {Promise<Object>} Check result
 */
async function sqlinjection(options) {
  if (!options || (!options.text && !options.data)) {
    return {
      detected: false,
      safe: true,
      errors: ['No text or data provided']
    };
  }

  const results = {
    detected: false,
    safe: true,
    threats: [],
    errors: []
  };

  // Check text directly
  if (options.text) {
    const result = detectSQLInjection(options.text);
    if (result.detected) {
      results.detected = true;
      results.safe = false;
      results.threats.push({
        type: 'text',
        value: options.text.substring(0, 100), // Truncate for safety
        ...result
      });
    }
  }

  // Check data object
  if (options.data) {
    const scanResults = scanInput(options.data, options);
    if (scanResults.length > 0) {
      results.detected = true;
      results.safe = false;
      results.threats.push(...scanResults);
    }
  }

  return results;
}

/**
 * Create SQL injection middleware for Express
 */
function createMiddleware(options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  // Validate mode
  if (!['LIVE', 'TEST'].includes(opts.mode)) {
    throw new Error('mode must be either "LIVE" or "TEST"');
  }

  return async (req, res, next) => {
    // In TEST mode, skip checking
    if (opts.mode === 'TEST') {
      return next();
    }

    const threats = [];

    // Check request body
    if (opts.checkBody && req.body) {
      const bodyResults = scanInput(req.body, opts);
      threats.push(...bodyResults);
    }

    // Check query parameters
    if (opts.checkQuery && req.query) {
      const queryResults = scanInput(req.query, opts);
      threats.push(...queryResults);
    }

    // Check route params
    if (opts.checkParams && req.params) {
      const paramsResults = scanInput(req.params, opts);
      threats.push(...paramsResults);
    }

    // Check headers (optional - can be verbose)
    if (opts.checkHeaders && req.headers) {
      const headerResults = scanInput(req.headers, opts);
      threats.push(...headerResults);
    }

    if (threats.length > 0) {
      // Attach threat info to request
      req.sqlInjectionDetected = true;
      req.sqlInjectionThreats = threats;

      if (opts.handler) {
        return opts.handler(req, res, threats);
      }

      if (opts.throwError) {
        return res.status(400).json({
          error: 'Potential SQL injection detected',
          threats
        });
      }

      return res.status(400).json({
        error: 'Potential SQL injection detected',
        message: 'Your input contains potentially dangerous characters'
      });
    }

    next();
  };
}

// Export both the middleware and the standalone function
sqlinjection.check = sqlinjection;
sqlinjection.detect = detectSQLInjection;
sqlinjection.middleware = createMiddleware;

module.exports = sqlinjection;
module.exports.default = sqlinjection;
module.exports.middleware = createMiddleware;
module.exports.detect = detectSQLInjection;
