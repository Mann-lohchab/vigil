/**
 * Vigil - Security Middleware for Express.js
 * 
 * A modular security middleware package with rate limiting, 
 * bot detection, and email verification.
 */

const ratelimiting = require('./rate-limit');
const botdetection = require('./bot-detection');
const emailverification = require('./email-verification');

module.exports = {
  ratelimiting,
  botDetection: botdetection,
  emailVerification: emailverification,
  // Aliases for convenience
  rateLimit: ratelimiting,
  botDetect: botdetection,
  emailVerify: emailverification
};
