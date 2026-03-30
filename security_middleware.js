const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const winston = require('winston');

const AES_ALGO = 'aes-256-gcm';
const MASTER_KEY = Buffer.from(process.env.MASTER_KEY || '0123456789abcdef0123456789abcdef', 'utf-8');

// Logger configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.File({ filename: 'security_audit.log' }),
        new winston.transports.Console()
    ]
});

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
            logger.warn(`Unauthorized access attempt by ${req.user?.username || 'Unknown'} to ${req.path}`);
            return res.status(403).json({ error: 'Access denied: insufficient permissions' });
        }
        next();
    };
}

/**
 * Password Validation
 */
function validatePassword(password) {
    const minLength = 8;
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/;
    const hasNumber = /[0-9]/;
    return password.length >= minLength && hasSpecial.test(password) && hasNumber.test(password);
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

module.exports = {
    encryptPayload,
    decryptPayload,
    generateHMAC,
    authorize,
    validatePassword,
    verifyNonce,
    logger,
    MASTER_KEY
};