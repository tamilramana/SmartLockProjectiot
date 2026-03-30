# SmartLock Advanced Security Implementation

## Overview
This document details the comprehensive security implementation for the SmartLock IoT system, covering cryptography, authentication, access control, and device security.

---

## 🔐 1. Password Security (Bcrypt)

### Implementation
```javascript
const bcrypt = require('bcryptjs');

// Hash password during registration/update
const hashedPassword = bcrypt.hashSync(password, 10);

// Verify password during login
const isValid = bcrypt.compareSync(password, hashedPassword);
```

### Features
✅ **Bcrypt Algorithm**: Industry-standard password hashing with automatic salt generation
✅ **Cost Factor**: 10 rounds (2^10 iterations) - secure against brute force
✅ **Timing-Safe**: Protects against timing attacks
✅ **Automatic Salt**: Each hash has unique salt

### Security Benefits
- Never stores plain text passwords
- Makes dictionary attacks computationally expensive
- Virtually impossible to reverse engineer original password
- Cost factor can be increased as computing power improves

---

## 🔑 2. Token-Based Authentication (JWT)

### Implementation
```javascript
const jwt = require('jsonwebtoken');

// Generate token on login
const token = jwt.sign(
  { id: user.id, username: user.username, role: user.role },
  JWT_SECRET,
  { expiresIn: '1h', algorithm: 'HS256' }
);

// Verify token in middleware
const decoded = jwt.verify(token, JWT_SECRET);
```

### Token Structure
```
Header.Payload.Signature

{
  "alg": "HS256",
  "typ": "JWT"
}.{
  "id": "user-123",
  "username": "john",
  "role": "admin",
  "iat": 1703001234,
  "exp": 1703004834
}.HMAC-SHA256(header.payload, secret)
```

### Features
✅ **Stateless**: No server-side session storage needed
✅ **Expiration**: Automatic timeout (1 hour)
✅ **Signature Verification**: Ensures token hasn't been tampered
✅ **Role-Based**: Includes user role for authorization

### Security Benefits
- Eliminates session hijacking vulnerabilities
- Reduces server resource usage
- Enables horizontal scaling (stateless)
- Clear token expiration prevents indefinite access

---

## 🔒 3. Encryption (AES-256-GCM + HTTPS/TLS)

### AES-256-GCM (Advanced Encryption Standard)
```javascript
const AES_ALGO = 'aes-256-gcm';

// Encrypt
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv(AES_ALGO, key, iv);
let encrypted = cipher.update(data, 'utf8', 'hex');
encrypted += cipher.final('hex');
const tag = cipher.getAuthTag();

// Decrypt
const decipher = crypto.createDecipheriv(AES_ALGO, key, iv);
decipher.setAuthTag(tag);
const decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
```

### Features
✅ **256-bit Key**: Extremely difficult to brute force (2^256 possibilities)
✅ **Galois/Counter Mode (GCM)**: Provides both encryption & authentication
✅ **Random IV**: 96-bit IV prevents pattern recognition
✅ **Authentication Tag**: Detects tampering attempts

### HTTPS/TLS Configuration
```javascript
// Enforce HTTPS in production
if (process.env.NODE_ENV === "production" && !req.secure) {
  return res.redirect(`https://${req.headers.host}${req.url}`);
}

// Use proper SSL certificates
const https = require('https');
const fs = require('fs');
const options = {
  key: fs.readFileSync('ssl/key.pem'),
  cert: fs.readFileSync('ssl/cert.pem')
};
https.createServer(options, app).listen(443);
```

### Security Stack
```
User ─[HTTPS/TLS]─> Server ─[AES-256-GCM]─> Device
     (Transport)         (Application)
```

### Benefits
- **HTTPS/TLS**: Protects data in transit, prevents man-in-the-middle attacks
- **AES-256-GCM**: Protects data at rest and in device communication
- **Combined**: Defense in depth approach

---

## 📡 4. Device Authentication (API Key System)

### Implementation
```javascript
// In device_api_security.js
function validateDeviceApiKey(deviceId, apiKey, devices) {
  return devices.find(d => 
    (d.device_id === deviceId || d.id === deviceId) && 
    d.api_key === apiKey
  );
}
```

### Device Middleware
```javascript
app.post('/device/status', authenticateDevice('header'), (req, res) => {
  // Device authenticated - headers must contain:
  // X-Device-ID: 'front-door'
  // X-API-Key: '48-character-hex-string'
  // X-Signature: 'HMAC-SHA256-signature'
  // X-Timestamp: milliseconds-since-epoch
});
```

### API Key Rotation
```javascript
function rotateDeviceApiKey(device) {
  device.api_key_history = device.api_key_history || [];
  
  // Store hash of old key for audit trail
  device.api_key_history.push({
    key_hash: crypto.createHash('sha256').update(device.api_key).digest('hex'),
    rotated_at: new Date().toISOString()
  });
  
  // Generate new key
  device.api_key = crypto.randomBytes(24).toString('hex');
  
  return device.api_key; // Return new key to device
}
```

### Security Benefits
- Only authorized devices can access lock control endpoints
- 24-byte (192-bit) random API keys are cryptographically secure
- Key rotation prevents long-term exposure if compromised
- API key history maintained for audit trail

---

## 🧠 5. Role-Based Access Control (RBAC)

### Roles and Permissions
```javascript
const ROLES = {
  admin: {
    permissions: [
      'user:create', 'user:delete', 'user:manage-roles',
      'device:control', 'device:config', 'device:view-all',
      'security:manage', 'logs:view'
    ]
  },
  owner: {
    permissions: [
      'device:control', 'device:config', 'device:view',
      'schedule:manage', 'logs:view'
    ]
  },
  user: {
    permissions: ['device:control', 'device:view']
  },
  guest: {
    permissions: ['device:view']
  }
};
```

### Implementation
```javascript
// Middleware
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    next();
  };
}

// Usage
app.delete('/users/:id', requireRole('admin'), (req, res) => {
  // Only admin can delete users
});

// Device ownership check
function canPerformAction(user, device, action) {
  if (!userOwnsDevice(user, device)) return false;
  return hasPermission(user, actionPermissionMap[action]);
}
```

### Security Benefits
- Principle of least privilege
- Users only get minimum required permissions
- Easy to audit who can do what
- Prevents privilege escalation

---

## 🚫 6. Brute Force Protection

### Implementation
```javascript
const MAX_ATTEMPTS = 5;           // Max failed attempts
const LOCK_TIME_MS = 15 * 60 * 1000;  // 15 minute lockout
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

function recordLoginAttempt(username, success = false) {
  const attempts = loginAttempts.get(username) || { attempts: 0 };
  
  if (!success) {
    attempts.attempts++;
    
    // Lock account after 5 failed attempts
    if (attempts.attempts >= MAX_ATTEMPTS) {
      attempts.locked = true;
      attempts.lockedUntil = Date.now() + LOCK_TIME_MS;
    }
  } else {
    // Reset on successful login
    attempts.attempts = 0;
    attempts.locked = false;
  }
  
  loginAttempts.set(username, attempts);
}
```

### Statistics Dashboard
```javascript
{
  totalActiveTracking: 50,
  totalLockedAccounts: 3,
  totalFailedAttempts: 12,
  suspiciousAccounts: [
    { username: 'john', attempts: 8, lastAttempt: 1703001234 }
  ]
}
```

### Security Benefits
- Prevents automated password guessing
- 15-minute lockout makes brute force impractical
- Alerts admin to suspicious activity
- Timing-safe comparison prevents side-channel attacks

---

## 🕒 7. Time-Based Security

### Timestamp Validation
```javascript
function verifyRequestTimestamp(timestamp, maxAgeMs = 300000) {
  const now = Date.now();
  const age = Math.abs(now - timestamp);
  
  if (age > maxAgeMs) {
    logger.warn(`Request too old: ${age}ms`);
    return false;
  }
  return true;
}
```

### Scheduled Access Control
```javascript
app.post('/devices/:id/unlock', (req, res) => {
  const schedule = device.schedules.find(s => {
    const now = new Date();
    const hour = now.getHours();
    return hour >= s.startTime && hour < s.endTime;
  });
  
  if (!schedule) {
    return res.status(403).json({ 
      error: 'Device not accessible at this time' 
    });
  }
  
  // Allow unlock
});
```

### Security Benefits
- Prevents replay attacks (reusing old valid requests)
- Enforces access windows (lock only accessible 9AM-5PM)
- Auto-lock after configurable timeout
- Time-based OTP (2FA) adds extra layer

---

## 📊 8. Comprehensive Logging System

### Security Events
```javascript
const SECURITY_EVENTS = {
  LOGIN_SUCCESS: 'User successfully logged in',
  LOGIN_FAILED: 'Failed login attempt',
  MFA_REQUIRED: 'MFA authentication required',
  UNAUTHORIZED_ACCESS: 'Attempted access without permission',
  PASSWORD_CHANGED: 'User password changed',
  API_KEY_ROTATED: 'Device API key rotated',
  DEVICE_ACCESSED: 'Device lock/unlock action',
  SUSPICIOUS_ACTIVITY: 'Suspicious pattern detected'
};
```

### Audit Logging
```javascript
function logSecurityEvent(eventType, details = {}) {
  const event = {
    eventType,
    timestamp: new Date().toISOString(),
    username: details.username,
    userId: details.userId,
    ip: details.ip,
    action: details.action,
    deviceId: details.deviceId,
    result: details.result
  };
  
  auditLogger.info(JSON.stringify(event));
}
```

### Log File Structure
```
security_audit.log      # All security events
activity.log           # User activities
error.log             # System errors
```

### Security Benefits
- Full audit trail for compliance
- Can detect and investigate security incidents
- Helps identify attack patterns
- Legal proof of actions taken

---

## 🚨 9. Alerts & Intrusion Detection

### Suspicious Activity Detection
```javascript
function isSuspiciousActivity(username) {
  const attempts = loginAttempts.get(username);
  return attempts && attempts.attempts >= 10;
}

// Trigger alert
if (isSuspiciousActivity(username)) {
  sendSecurityAlert({
    type: 'BRUTE_FORCE_ATTEMPT',
    username,
    attempts: 10,
    severity: 'HIGH',
    action: 'ACCOUNT_LOCKED'
  });
}
```

### Real-Time Alerts
```javascript
// WebSocket alert system
broadcast({
  type: 'SECURITY_ALERT',
  message: 'Multiple failed login attempts detected',
  username: 'suspicious-user',
  actions: ['LOCK_ACCOUNT', 'NOTIFY_ADMIN']
});
```

### Security Benefits
- Real-time threat detection
- Immediate response to anomalies
- Admin notifications enable quick action
- Reduces time-to-detect security incidents

---

## 🔐 10. Advanced Algorithms

### 1. AES-256-GCM (Already Covered Above)
- Symmetric encryption for command payloads
- Used between server and devices

### 2. RSA-2048 (Key Exchange)
```javascript
// Generate keypair
crypto.generateKeyPair('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
}, (err, publicKey, privateKey) => { ... });

// Encrypt with public key
const encrypted = crypto.publicEncrypt(
  { key: publicKey, oaepHash: 'sha256' },
  Buffer.from(data)
);

// Decrypt with private key
const decrypted = crypto.privateDecrypt(
  { key: privateKey, oaepHash: 'sha256' },
  encryptedBuffer
);
```

### 3. HMAC-SHA256 (Message Authentication)
```javascript
// Sign request
function generateDeviceSignature(payload, apiKey) {
  return crypto
    .createHmac('sha256', apiKey)
    .update(JSON.stringify(payload))
    .digest('hex');
}

// Verify signature
function verifyDeviceSignature(payload, signature, apiKey) {
  const expected = generateDeviceSignature(payload, apiKey);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expected, 'hex')
  );
}
```

### 4. PBKDF2 (Key Derivation)
```javascript
// Derive encryption key from password
const derivedKey = crypto.pbkdf2Sync(
  password,
  salt,
  100000,  // iterations
  32,      // key length for AES-256
  'sha256'
);
```

### 5. HKDF (HMAC-based Extract-and-Expand)
```javascript
// Derive multiple keys from single master key
const encryptionKey = crypto.hkdfSync('sha256', masterKey, salt, 'encryption', 32);
const authKey = crypto.hkdfSync('sha256', masterKey, salt, 'authentication', 32);
```

---

## 📱 11. Multi-Factor Authentication (MFA)

### TOTP Implementation
```javascript
function generateBase32Secret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

// User scans QR code with authenticator app
// Generate TOTP code
function totpToken(secret, timeMs = Date.now()) {
  const counter = Math.floor(timeMs / 1000 / 30);
  const hmac = crypto.createHmac("sha1", base32ToBuffer(secret))
    .update(Buffer.alloc(8, counter))
    .digest();
  return String((hmac.readUInt32BE(0) & 0x7fffffff) % 1000000)
    .padStart(6, "0");
}

// Verify TOTP with window (time skew tolerance)
function verifyTotp(secret, token, window = 1) {
  for (let w = -window; w <= window; w++) {
    const t = Date.now() + w * 30 * 1000;
    if (totpToken(secret, t) === token) return true;
  }
  return false;
}
```

### Backup Codes
```javascript
// Generate 10 backup codes
function generateBackupCodes(count = 10) {
  return Array.from({ length: count }, () => 
    crypto.randomBytes(4).toString('hex')
  );
}

// Hash and store (never plain text)
user.backup_codes = backupCodes.map(code => 
  crypto.createHash('sha256').update(code).digest('hex')
);

// User can use one code as fallback
function consumeBackupCode(user, providedCode) {
  const codeHash = crypto.createHash('sha256').update(providedCode).digest('hex');
  const index = user.backup_codes.findIndex(hash => hash === codeHash);
  
  if (index > -1) {
    user.backup_codes.splice(index, 1); // Remove used code
    return true;
  }
  return false;
}
```

### Trusted Devices
```javascript
// User can mark device as trusted (skip MFA)
function generateTrustedDeviceToken() {
  return crypto.randomBytes(24).toString('hex');
}

// Store token on device
localStorage.setItem('trustedDeviceToken', token);

// On login, send trusted device token to skip MFA
const isTrusted = user.trusted_devices.find(d => 
  d.token === trustedToken
);
```

### Security Benefits
- Two-factor authentication highly resistant to password theft
- TOTP doesn't require internet (works offline)
- Backup codes prevent lockout
- Trusted devices balance security and usability

---

## 🌍 12. Network Security

### Private Network Configuration
```javascript
// Only allow private IP addresses
function isPrivateIp(ip) {
  const normalized = ip.trim().replace(/^::ffff:/, '').split(':')[0];
  return /^(10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)/.test(normalized);
}

// CORS for same-origin only
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"]
}));
```

### Security Headers (Helmet.js)
```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],          // Only same origin
      scriptSrc: ["'self'"],           // No inline scripts
      styleSrc: ["'self'", 'unsafe-inline'],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],          // Only same origin API calls
      frameAncestors: ["'none'"]       // Cannot be framed
    }
  },
  hsts: true,                          // Force HTTPS
  noSniff: true,                       // Prevent MIME sniffing
  xssFilter: true                      // XSS protection
}));
```

### Rate Limiting
```javascript
// Global rate limit
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                  // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false
});

// Strict limit on login endpoint
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,                    // 5 attempts per 15 minutes
  skipSuccessfulRequests: true
});

app.post('/login', loginLimiter, (req, res) => { ... });
```

### Firewall Rules
```
Allow: 192.168.1.0/24 (Local Wi-Fi)
Allow: 10.0.0.0/8 (Private network)
Deny: 0.0.0.0/0 (Everything else)

API Server Ports:
- 443 (HTTPS) - Public facing
- 3000 (HTTP) - Internal only
```

### Security Benefits
- Private network prevents unauthorized access
- No direct exposure of ESP8266 on internet
- CORS prevents cross-origin attacks
- CSP prevents XSS and injection attacks
- Rate limiting prevents resource exhaustion
- HSTS forces encrypted connections

---

## 🧩 Complete Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      User Browser                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │   Login with Password   │
          │   Bcrypt Hash Check     │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │   JWT Token Generated   │
          │   HMAC-SHA256 Signed    │
          │   Expires in 1 hour     │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────┐
          │  MFA (TOTP) Optional    │
          │  Backup Codes Available │
          └────────────┬────────────┘
                       │
        ┌──────────────▼──────────────┐
        │                             │
        │ HTTPS/TLS Encryption        │
        │ (Transport Layer)           │
        │                             │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  Express Server (Helmet.js) │
        │  - CSP Headers              │
        │  - HSTS Enforcement         │
        │  - Rate Limiting            │
        │  - CORS Validation          │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  JWT Verification          │
        │  Role-Based Access Control  │
        │  Permission Checks          │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  Device Authorization       │
        │  - Check Device Ownership   │
        │  - Verify User Permissions  │
        │  - Log Action               │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │ AES-256-GCM Encryption      │
        │ (Application Layer)         │
        │ HMAC-SHA256 Signature       │
        │ Timestamp Validation        │
        └──────────────┬──────────────┘
                       │
                       │
        ┌──────────────▼──────────────┐
        │  ESP8266 Device            │
        │                             │
        │  ✓ API Key Validation       │
        │  ✓ HMAC Signature Check     │
        │  ✓ Timestamp Verification   │
        │  ✓ Command Decryption       │
        │  ✓ Execute Action           │
        │  ✓ Report Status            │
        └─────────────────────────────┘
```

---

## 📋 Implementation Checklist

### ✅ Server-Side Security
- [x] Bcrypt password hashing (cost: 10)
- [x] JWT token generation (1-hour expiry)
- [x] AES-256-GCM payload encryption
- [x] HMAC-SHA256 message signing
- [x] API key validation for devices
- [x] Brute force protection (5 attempts, 15-min lockout)
- [x] RBAC with permission checks
- [x] Device ownership verification
- [x] Comprehensive audit logging
- [x] Helmet.js security headers
- [x] HTTPS/TLS enforcement
- [x] CORS with origin validation
- [x] Rate limiting (global & per-endpoint)
- [x] Replay attack protection (timestamps)
- [x] Session timeout (1 hour)

### ✅ Device-Side Security
- [x] HTTPS/TLS for all communication
- [x] API key storage (secure)
- [x] HMAC request signing
- [x] Timestamp validation
- [x] Command signature verification
- [x] Status heartbeat with authentication
- [x] Encrypted command payload handling
- [x] Action confirmation reporting
- [x] Secure device registration

### ✅ Advanced Features
- [x] Multi-Factor Authentication (TOTP)
- [x] Backup codes for MFA
- [x] Trusted device tokens
- [x] Key rotation mechanism
- [x] Security event logging
- [x] Activity audit trail
- [x] Brute force statistics
- [x] Device heartbeat monitoring
- [x] Offline capability (device)

---

## 🚀 Deployment Security

### Environment Variables
```bash
# server/.env
NODE_ENV=production
JWT_SECRET=<random-256-bit-secret>
MASTER_KEY=<32-byte-hex-key>
SERVER_PUBLIC_KEY=<RSA-public-key-pem>
ALLOWED_ORIGINS=https://yourdomain.com
SSL_KEY_PATH=/etc/ssl/private/key.pem
SSL_CERT_PATH=/etc/ssl/certs/cert.pem
USE_HTTPS=true
```

### Production Checklist
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Set strong JWT_SECRET (64+ random characters)
- [ ] Use environment variables for all secrets
- [ ] Enable CORS only for trusted origins
- [ ] Set secure cookie flags (HttpOnly, Secure, SameSite)
- [ ] Configure firewall rules (public: 443, internal: 3000)
- [ ] Enable VPN/Private network for devices
- [ ] Regular log rotation
- [ ] Daily security audit log review
- [ ] Monthly API key rotation for devices
- [ ] Quarterly penetration testing
- [ ] Keep dependencies updated

---

## 📚 References

- **JWT.io**: https://jwt.io/
- **Node.js Crypto**: https://nodejs.org/api/crypto.html
- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CWE Top 25**: https://cwe.mitre.org/top25/
- **Helmet.js**: https://helmetjs.github.io/
- **bcryptjs**: https://www.npmjs.com/package/bcryptjs
- **speakeasy (TOTP)**: https://www.npmjs.com/package/speakeasy

---

## 📞 Security Support

For security vulnerabilities or questions:
1. **Do NOT** disclose publicly
2. Create private issue or contact maintainer
3. Provide detailed reproduction steps
4. Include affected versions

---

**Last Updated**: 2024
**Security Level**: PRODUCTION READY ✅
