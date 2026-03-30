/**
 * Brute Force Protection Module
 * Implements account lockout, rate limiting, and suspicious activity detection
 */

const { logger } = require('./security_middleware');

/**
 * Track login attempts per username
 * Structure: { username: { attempts: number, lastAttempt: timestamp, locked: boolean, lockedUntil: timestamp } }
 */
const loginAttempts = new Map();

/**
 * Configuration for brute force protection
 */
const BRUTE_FORCE_CONFIG = {
  MAX_ATTEMPTS: 5,           // Max failed login attempts
  LOCK_TIME_MS: 15 * 60 * 1000,  // 15 minutes lockout
  ATTEMPT_WINDOW_MS: 15 * 60 * 1000,  // 15 minute window
  SUSPICIOUS_THRESHOLD: 10   // Failed attempts = suspicious
};

/**
 * Record a login attempt
 * @param {string} username - Username
 * @param {boolean} success - Whether login was successful
 * @returns {Object} { allowed: boolean, attemptsLeft: number, message: string }
 */
function recordLoginAttempt(username, success = false) {
  if (!username) return { allowed: false, message: 'Invalid username' };
  
  const now = Date.now();
  let attempts = loginAttempts.get(username) || {
    attempts: 0,
    lastAttempt: now,
    locked: false,
    lockedUntil: null,
    successCount: 0
  };
  
  // Check if account is locked
  if (attempts.locked && attempts.lockedUntil > now) {
    const remainingMs = attempts.lockedUntil - now;
    const remainingMin = Math.ceil(remainingMs / 1000 / 60);
    
    logger.warn(`Login attempt on locked account: ${username} (locked for ${remainingMin} more minutes)`);
    
    return {
      allowed: false,
      attemptsLeft: 0,
      message: `Account temporarily locked. Try again in ${remainingMin} minute(s).`,
      lockedUntil: attempts.lockedUntil
    };
  }
  
  // Clear old attempts if outside window
  if (now - attempts.lastAttempt > BRUTE_FORCE_CONFIG.ATTEMPT_WINDOW_MS) {
    attempts = {
      attempts: 0,
      lastAttempt: now,
      locked: false,
      lockedUntil: null,
      successCount: 0
    };
  }
  
  if (success) {
    // Successful login - reset attempts
    attempts.successCount++;
    attempts.attempts = 0;
    attempts.locked = false;
    attempts.lockedUntil = null;
    
    logger.info(`Successful login: ${username}`);
  } else {
    // Failed login - increment attempts
    attempts.attempts++;
    attempts.lastAttempt = now;
    
    // Lock account if threshold exceeded
    if (attempts.attempts >= BRUTE_FORCE_CONFIG.MAX_ATTEMPTS) {
      attempts.locked = true;
      attempts.lockedUntil = now + BRUTE_FORCE_CONFIG.LOCK_TIME_MS;
      
      logger.warn(
        `Account locked due to too many failed attempts: ${username}`,
        { attempts: attempts.attempts }
      );
    }
    
    logger.warn(
      `Failed login attempt: ${username}`,
      { attempt: attempts.attempts, max: BRUTE_FORCE_CONFIG.MAX_ATTEMPTS }
    );
  }
  
  loginAttempts.set(username, attempts);
  
  const attemptsLeft = Math.max(0, BRUTE_FORCE_CONFIG.MAX_ATTEMPTS - attempts.attempts);
  
  if (!success && attemptsLeft === 0) {
    return {
      allowed: false,
      attemptsLeft: 0,
      message: 'Too many failed attempts. Account locked temporarily.',
      lockedUntil: attempts.lockedUntil
    };
  }
  
  return {
    allowed: true,
    attemptsLeft,
    message: success ? 'Login successful' : `Login failed. ${attemptsLeft} attempts remaining.`
  };
}

/**
 * Check if login attempt is allowed
 * @param {string} username - Username
 * @returns {boolean}
 */
function isLoginAllowed(username) {
  if (!username) return false;
  
  const attempts = loginAttempts.get(username);
  if (!attempts) return true;
  
  const now = Date.now();
  
  // Check if locked
  if (attempts.locked && attempts.lockedUntil > now) {
    return false;
  }
  
  // Check if in attempt window
  if (now - attempts.lastAttempt > BRUTE_FORCE_CONFIG.ATTEMPT_WINDOW_MS) {
    return true;
  }
  
  // Check attempt count
  return attempts.attempts < BRUTE_FORCE_CONFIG.MAX_ATTEMPTS;
}

/**
 * Get login attempt info for user
 * @param {string} username - Username
 * @returns {Object} Attempt info
 */
function getLoginAttemptInfo(username) {
  const attempts = loginAttempts.get(username);
  if (!attempts) {
    return { attempts: 0, locked: false, attemptsLeft: BRUTE_FORCE_CONFIG.MAX_ATTEMPTS };
  }
  
  const now = Date.now();
  const isLocked = attempts.locked && attempts.lockedUntil > now;
  
  return {
    attempts: attempts.attempts,
    locked: isLocked,
    attemptsLeft: Math.max(0, BRUTE_FORCE_CONFIG.MAX_ATTEMPTS - attempts.attempts),
    lockedUntil: isLocked ? attempts.lockedUntil : null,
    successCount: attempts.successCount
  };
}

/**
 * Manually unlock an account
 * @param {string} username - Username
 */
function unlockAccount(username) {
  const attempts = loginAttempts.get(username);
  if (attempts) {
    attempts.locked = false;
    attempts.lockedUntil = null;
    attempts.attempts = 0;
    loginAttempts.set(username, attempts);
    logger.info(`Account manually unlocked: ${username}`);
  }
}

/**
 * Clear all attempt records (useful for testing/admin operations)
 */
function clearAllAttempts() {
  loginAttempts.clear();
  logger.info('All login attempt records cleared');
}

/**
 * Detect suspicious activity (multiple failed attempts from multiple sources)
 * @param {string} username - Username
 * @returns {boolean} True if suspicious
 */
function isSuspiciousActivity(username) {
  const attempts = loginAttempts.get(username);
  if (!attempts) return false;
  
  // Flag if attempts exceed suspicious threshold in current window
  return attempts.attempts >= BRUTE_FORCE_CONFIG.SUSPICIOUS_THRESHOLD;
}

/**
 * Middleware to check if login is allowed
 * @returns {Function} Express middleware
 */
function checkBruteForce(req, res, next) {
  const { username } = req.body || {};
  
  if (!isLoginAllowed(username)) {
    const info = getLoginAttemptInfo(username);
    
    logger.warn(`Login attempt blocked due to brute force: ${username}`);
    
    return res.status(429).json({
      error: 'Too many login attempts. Please try again later.',
      retryAfter: info.lockedUntil ? Math.ceil((info.lockedUntil - Date.now()) / 1000) : 300
    });
  }
  
  next();
}

/**
 * Get brute force statistics for admin dashboard
 * @returns {Object} Statistics
 */
function getBruteForceStats() {
  let totalLocked = 0;
  let totalAttempts = 0;
  let suspiciousAccounts = [];
  
  loginAttempts.forEach((attempts, username) => {
    if (attempts.locked) totalLocked++;
    totalAttempts += attempts.attempts;
    
    if (isSuspiciousActivity(username)) {
      suspiciousAccounts.push({
        username,
        attempts: attempts.attempts,
        lastAttempt: attempts.lastAttempt
      });
    }
  });
  
  return {
    totalActiveTracking: loginAttempts.size,
    totalLockedAccounts: totalLocked,
    totalFailedAttempts: totalAttempts,
    suspiciousAccounts
  };
}

module.exports = {
  // Core functions
  recordLoginAttempt,
  isLoginAllowed,
  getLoginAttemptInfo,
  unlockAccount,
  isSuspiciousActivity,
  
  // Configuration
  BRUTE_FORCE_CONFIG,
  
  // Middleware
  checkBruteForce,
  
  // Admin functions
  clearAllAttempts,
  getBruteForceStats
};
