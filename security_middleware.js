const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const winston = require('winston');

const AES_ALGO = 'aes-256-gcm';
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY || '0123456789abcdef0123456789abcdef', 'utf-8');

// Logger configuration with separate audit log
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'security_audit.log'}),
        new winston.transports.File({ filename: 'activity.log' }),
        new winston.transports.Console({ format: winston.format.simple() })
    ]
});

// Audit logger specifically for security events
const auditLogger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'security_audit.log', maxsize: 5242880 }), // 5MB
        new winston.transports.Console({ format: winston.format.simple() })
    ]
});

/**
 * Security event types for tracking
 */
const SECURITY_EVENTS = {
    LOGIN_SUCCESS: 'LOGIN_SUCCESS',
    LOGIN_FAILED: 'LOGIN_FAILED',
    MFA_REQUIRED: 'MFA_REQUIRED',
    MFA_VERIFIED: 'MFA_VERIFIED',
    UNAUTHORIZED_ACCESS: 'UNAUTHORIZED_ACCESS',
    PASSWORD_CHANGED: 'PASSWORD_CHANGED',
    API_KEY_ROTATED: 'API_KEY_ROTATED',
    DEVICE_ACCESSED: 'DEVICE_ACCESSED',
    SUSPICIOUS_ACTIVITY: 'SUSPICIOUS_ACTIVITY',
    SECURITY_LOCK: 'SECURITY_LOCK',
    SESSION_EXPIRED: 'SESSION_EXPIRED'
};

/**
 * Log security event with context
 */
function logSecurityEvent(eventType, details = {}) {
    const event = {
        eventType,
        timestamp: new Date().toISOString(),
        ...details
    };
    
    auditLogger.info(JSON.stringify(event));
}

/**
 * AES-256-GCM Encryption for ESP Communication
 */
function encryptPayload(data, key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(AES_ALGO, key, iv);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return {
        iv: iv.toString('hex'),
        content: encrypted,
        tag: authTag
    };
}

/**
 * AES-256-GCM Decryption for ESP Communication
 */
function decryptPayload(payload, key) {
    const decipher = crypto.createDecipheriv(AES_ALGO, key, Buffer.from(payload.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(payload.tag, 'hex'));
    let decrypted = decipher.update(payload.content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

/**
 * HMAC Generation for message integrity
 */
function generateHMAC(message, secret) {
    return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

/**
 * RBAC Middleware
 */
function authorize(roles = []) {
    if (typeof roles === 'string') roles = [roles];
    return (req, res, next) => {
        if (!req.user || (roles.length && !roles.includes(req.user.role))) {
            logSecurityEvent('UNAUTHORIZED_ACCESS', {
                username: req.user?.username || 'Unknown',
                path: req.path,
                method: req.method,
                ip: req.ip
            });
            logger.warn(`Unauthorized access attempt by ${req.user?.username || 'Unknown'} to ${req.path}`);
            return res.status(403).json({ error: 'Access denied: insufficient permissions' });
        }
        next();
    };
}

/**
 * Password Validation with strong requirements
 */
function validatePassword(password) {
    const minLength = 12;  // Increased from 8 for better security
    const hasUpperCase = /[A-Z]/;
    const hasLowerCase = /[a-z]/;
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/;
    const hasNumber = /[0-9]/;
    
    const validations = {
        minLength: password.length >= minLength,
        hasUpperCase: hasUpperCase.test(password),
        hasLowerCase: hasLowerCase.test(password),
        hasNumber: hasNumber.test(password),
        hasSpecial: hasSpecial.test(password)
    };
    
    const isValid = Object.values(validations).every(v => v);
    
    return {
        isValid,
        validations,
        score: Object.values(validations).filter(v => v).length / Object.keys(validations).length
    };
}

/**
 * Replay Attack Protection (Nonce/Timestamp check)
 */
const usedNonces = new Set();
function verifyNonce(nonce, timestamp) {
    const now = Date.now();
    const threshold = 60000; // 1 minute window
    if (Math.abs(now - timestamp) > threshold) return false;
    if (usedNonces.has(nonce)) return false;
    usedNonces.add(nonce);
    setTimeout(() => usedNonces.delete(nonce), threshold);
    return true;
}

/**
 * Session token validation
 */
function validateSessionToken(token, secret) {
    try {
        return jwt.verify(token, secret);
    } catch (error) {
        logSecurityEvent('SESSION_EXPIRED', {
            error: error.message
        });
        return null;
    }
}

/**
 * Activity logger for tracking user actions
 */
function logActivity(userId, action, resource, resourceId, details = {}) {
    logger.info(JSON.stringify({
        type: 'ACTIVITY',
        userId,
        action,
        resource,
        resourceId,
        timestamp: new Date().toISOString(),
        ...details
    }));
}

/**
 * IP-based rate limiting helper
 */
const ipRequestCounts = new Map();
function checkIpRateLimit(ip, maxRequests = 100, windowMs = 15 * 60 * 1000) {
    const now = Date.now();
    const record = ipRequestCounts.get(ip);
    
    if (!record) {
        ipRequestCounts.set(ip, { count: 1, resetTime: now + windowMs });
        return { allowed: true, remaining: maxRequests - 1 };
    }
    
    if (now > record.resetTime) {
        record.count = 1;
        record.resetTime = now + windowMs;
        return { allowed: true, remaining: maxRequests - 1 };
    }
    
    record.count++;
    const remaining = maxRequests - record.count;
    
    if (record.count > maxRequests) {
        logSecurityEvent('SUSPICIOUS_ACTIVITY', {
            type: 'IP_RATE_LIMIT_EXCEEDED',
            ip,
            attempts: record.count
        });
        return { allowed: false, remaining: 0 };
    }
    
    return { allowed: true, remaining };
}

/**
 * Middleware for IP rate limiting
 */
function ipRateLimitMiddleware(maxRequests = 100, windowMs = 15 * 60 * 1000) {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const check = checkIpRateLimit(ip, maxRequests, windowMs);
        
        res.setHeader('X-RateLimit-Limit', maxRequests);
        res.setHeader('X-RateLimit-Remaining', check.remaining);
        
        if (!check.allowed) {
            return res.status(429).json({
                error: 'Too many requests from your IP address'
            });
        }
        
        next();
    };
}

/**
 * Expose security events for monitoring
 */
function getSecurityEvents() {
    return SECURITY_EVENTS;
}

module.exports = {
    encryptPayload,
    decryptPayload,
    generateHMAC,
    authorize,
    validatePassword,
    verifyNonce,
    validateSessionToken,
    logActivity,
    logSecurityEvent,
    checkIpRateLimit,
    ipRateLimitMiddleware,
    getSecurityEvents,
    logger,
    auditLogger,
    MASTER_KEY,
    SECURITY_EVENTS
};