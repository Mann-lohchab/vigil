/**
 * Vigil - Email Verification Module
 * 
 * Verifies email addresses by checking MX DNS records
 */

const dns = require('dns/promises');
const os = require('os');

// Set DNS servers to reliable public DNS
dns.setServers(['8.8.8.8', '8.8.4.4']);

// Common disposable email domains to block
const DISPOSABLE_DOMAINS = [
  'tempmail.com',
  '10minutemail.com',
  'guerrillamail.com',
  'mailinator.com',
  'throwaway.email',
  'fakeinbox.com',
  'yopmail.com',
  'trashmail.com',
  'dispostable.com',
  'maildrop.cc',
  'getnada.com',
  'mohmal.com',
  'tempail.com',
  'emailondeck.com',
  'mintemail.com',
  'sharklasers.com',
  'spam4.me',
  'grr.la',
  'mailnesia.com',
  'tempemailaddress.com'
];

// Reserved/known invalid domains
const RESERVED_DOMAINS = [
  'localhost',
  'example.com',
  'example.org',
  'test.com',
  'invalid'
];

/**
 * Validate email format
 */
function isValidEmailFormat(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Extract domain from email
 */
function extractDomain(email) {
  const parts = email.split('@');
  return parts.length === 2 ? parts[1].toLowerCase() : null;
}

/**
 * Check if domain is a disposable email provider
 */
function isDisposableDomain(domain, disposableList) {
  return disposableList.includes(domain);
}

/**
 * Check if domain is reserved or invalid
 */
function isReservedDomain(domain) {
  return RESERVED_DOMAINS.includes(domain);
}

/**
 * Resolve MX records for a domain
 */
async function resolveMX(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);
    return mxRecords.sort((a, b) => a.priority - b.priority);
  } catch (error) {
    return [];
  }
}

/**
 * Verify email by checking MX records
 */
async function verifyEmail(email, options = {}) {
  const checkMX = options.checkMX !== false;
  const checkDisposable = options.checkDisposable !== false;
  const disposableDomains = options.disposableDomains || DISPOSABLE_DOMAINS;
  const timeout = options.timeout || 5000;

  const result = {
    email,
    valid: false,
    exists: false,
    hasMX: false,
    isDisposable: false,
    isValidFormat: false,
    isReserved: false,
    mxRecords: [],
    errors: []
  };

  // Check format
  if (!isValidEmailFormat(email)) {
    result.errors.push('Invalid email format');
    return result;
  }
  result.isValidFormat = true;

  // Extract domain
  const domain = extractDomain(email);
  if (!domain) {
    result.errors.push('Could not extract domain');
    return result;
  }

  // Check reserved domains
  if (isReservedDomain(domain)) {
    result.isReserved = true;
    result.errors.push('Reserved domain');
    return result;
  }

  // Check disposable domains
  if (checkDisposable && isDisposableDomain(domain, disposableDomains)) {
    result.isDisposable = true;
    result.errors.push('Disposable email domain');
    return result;
  }

  // Check MX records
  if (checkMX) {
    try {
      // Use timeout wrapper
      const mxPromise = resolveMX(domain);
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('DNS timeout')), timeout)
      );
      
      const mxRecords = await Promise.race([mxPromise, timeoutPromise]);
      
      if (mxRecords && mxRecords.length > 0) {
        result.hasMX = true;
        result.exists = true;
        result.valid = true;
        result.mxRecords = mxRecords.map(r => ({
          host: r.exchange,
          priority: r.priority
        }));
      } else {
        result.errors.push('No MX records found');
      }
    } catch (error) {
      result.errors.push('DNS lookup failed: ' + error.message);
    }
  } else {
    // If not checking MX, just verify format
    result.valid = true;
    result.exists = true;
  }

  return result;
}

/**
 * Main email verification function
 * 
 * @param {Object} options - Options object
 * @param {string} options.email - Email address to verify (required)
 * @param {boolean} [options.checkMX=true] - Check MX records
 * @param {boolean} [options.checkDisposable=true] - Check disposable emails
 * @param {string[]} [options.disposableDomains] - Custom disposable domains
 * @param {number} [options.timeout=5000] - DNS timeout in ms
 * @returns {Promise<Object>} Verification result
 * 
 * @example
 * const result = await emailVerification({
 *   email: 'user@example.com',
 *   checkMX: true
 * });
 */
async function emailVerification(options) {
  if (!options || !options.email) {
    return {
      email: options?.email || null,
      valid: false,
      errors: ['Email is required']
    };
  }
  
  return await verifyEmail(options.email, options);
}

/**
 * Get list of disposable domains
 */
emailVerification.getDisposableDomains = function() {
  return [...DISPOSABLE_DOMAINS];
};

/**
 * Add custom disposable domain
 */
emailVerification.addDisposableDomain = function(domain) {
  if (!DISPOSABLE_DOMAINS.includes(domain)) {
    DISPOSABLE_DOMAINS.push(domain);
  }
};

/**
 * Verify email directly (alias)
 */
emailVerification.verify = async function(email, options = {}) {
  return await verifyEmail(email, options);
};

/**
 * Create email verification middleware for Express
 * 
 * This middleware can be used to verify email addresses from request body,
 * query params, or headers. Results are attached to req.emailVerification.
 * 
 * @param {Object} options - Options for email verification middleware
 * @param {string} [options.emailField='email'] - Field name to get email from request (body, query, params)
 * @param {string} [options.source='body'] - Source: 'body', 'query', 'params', or 'header'
 * @param {string} [options.headerName='x-email'] - Header name if source is 'header'
 * @param {boolean} [options.checkMX=true] - Check MX records
 * @param {boolean} [options.checkDisposable=true] - Check disposable emails
 * @param {string[]} [options.disposableDomains] - Custom disposable domains
 * @param {number} [options.timeout=5000] - DNS timeout in ms
 * @param {boolean} [options.blockOnDisposable=true] - Block requests with disposable emails
 * @param {Function} [options.handler] - Custom handler for invalid emails
 * @returns {Function} Express middleware
 */
function createEmailVerificationMiddleware(options = {}) {
  const DEFAULT_MIDDLEWARE_OPTIONS = {
    emailField: 'email',
    source: 'body',
    headerName: 'x-email',
    checkMX: true,
    checkDisposable: true,
    blockOnDisposable: true,
    handler: null
  };
  
  const opts = { ...DEFAULT_MIDDLEWARE_OPTIONS, ...options };
  
  return async (req, res, next) => {
    let email = null;
    
    // Get email from the specified source
    switch (opts.source) {
      case 'body':
        email = req.body?.[opts.emailField];
        break;
      case 'query':
        email = req.query?.[opts.emailField];
        break;
      case 'params':
        email = req.params?.[opts.emailField];
        break;
      case 'header':
        email = req.headers?.[opts.headerName?.toLowerCase()];
        break;
      default:
        email = req.body?.[opts.emailField];
    }
    
    // If no email provided, skip verification but attach null result
    if (!email) {
      req.emailVerification = {
        email: null,
        valid: false,
        errors: ['Email is required']
      };
      return next();
    }
    
    try {
      const result = await verifyEmail(email, {
        checkMX: opts.checkMX,
        checkDisposable: opts.checkDisposable,
        disposableDomains: opts.disposableDomains,
        timeout: opts.timeout
      });
      
      req.emailVerification = result;
      
      // Block if email is invalid or disposable (if configured)
      if (!result.valid || (opts.blockOnDisposable && result.isDisposable)) {
        if (opts.handler) {
          return opts.handler(req, res, result);
        }
        
        return res.status(400).json({
          error: 'Invalid Email',
          message: result.isDisposable 
            ? 'Disposable email addresses are not allowed'
            : 'Email verification failed',
          details: result
        });
      }
      
      next();
    } catch (error) {
      // On error, attach error info and continue
      req.emailVerification = {
        email,
        valid: false,
        errors: [error.message]
      };
      next();
    }
  };
}

// Attach middleware creator to the main function
emailVerification.middleware = createEmailVerificationMiddleware;

module.exports = emailVerification;
