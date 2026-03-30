/**
 * Device API Security Module
 * Handles ESP8266 device authentication, API key validation, and device-to-server communication
 * Uses HMAC signatures and timestamped requests to prevent unauthorized access
 */

const crypto = require('crypto');
const { logger } = require('./security_middleware');

/**
 * Validate device API key
 * @param {string} deviceId - Device identifier
 * @param {string} apiKey - Device's secret API key
 * @param {Object} devicesData - Array of registered devices
 * @returns {Object|null} Device object if valid, null otherwise
 */
function validateDeviceApiKey(deviceId, apiKey, devicesData = []) {
  if (!deviceId || !apiKey) return null;
  
  const device = devicesData.find(d => 
    (d.device_id === deviceId || d.deviceId === deviceId || d.id === deviceId) && 
    d.api_key === apiKey
  );
  
  if (!device) {
    logger.warn(`API key validation failed for device: ${deviceId}`);
    return null;
  }
  
  logger.info(`Device authenticated: ${deviceId}`);
  return device;
}

/**
 * Generate HMAC signature for device requests
 * Used by ESP8266 to sign requests sent to server
 * @param {Object} payload - Request payload
 * @param {string} apiKey - Device's secret API key
 * @returns {string} HMAC-SHA256 signature
 */
function generateDeviceSignature(payload, apiKey) {
  const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return crypto
    .createHmac('sha256', apiKey)
    .update(payloadStr)
    .digest('hex');
}

/**
 * Verify HMAC signature from device
 * @param {Object} payload - Request payload
 * @param {string} signature - Provided HMAC signature
 * @param {string} apiKey - Device's secret API key
 * @returns {boolean} True if signature is valid
 */
function verifyDeviceSignature(payload, signature, apiKey) {
  if (!signature || !apiKey) return false;
  
  const expected = generateDeviceSignature(payload, apiKey);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expected, 'hex')
  );
}

/**
 * Verify request timestamp to prevent replay attacks
 * @param {number} timestamp - Request timestamp in milliseconds
 * @param {number} maxAgeMs - Maximum age of request (default 5 minutes)
 * @returns {boolean} True if timestamp is valid
 */
function verifyRequestTimestamp(timestamp, maxAgeMs = 300000) {
  if (!timestamp) return false;
  
  const now = Date.now();
  const age = Math.abs(now - timestamp);
  
  if (age > maxAgeMs) {
    logger.warn(`Request timestamp out of acceptable range: ${age}ms old`);
    return false;
  }
  
  return true;
}

/**
 * Middleware to authenticate device API requests
 * Validates API key, HMAC signature, and timestamp
 * @param {string} apiKeySource - Where to get API key ('header', 'query', 'body')
 * @returns {Function} Express middleware
 */
function authenticateDevice(apiKeySource = 'header') {
  return (req, res, next) => {
    const deviceData = req.app.locals.deviceData || {};
    const devices = deviceData.devices || [];
    
    let deviceId, apiKey, signature, timestamp;
    
    if (apiKeySource === 'header') {
      apiKey = req.headers['x-api-key'];
      deviceId = req.headers['x-device-id'];
      signature = req.headers['x-signature'];
      timestamp = req.headers['x-timestamp'];
    } else if (apiKeySource === 'query') {
      apiKey = req.query.apiKey;
      deviceId = req.query.deviceId;
      signature = req.query.signature;
      timestamp = req.query.timestamp;
    } else if (apiKeySource === 'body') {
      ({ apiKey, deviceId, signature, timestamp } = req.body || {});
    }
    
    // Convert timestamp to number
    if (timestamp) timestamp = parseInt(timestamp, 10);
    
    // Validate timestamp first
    if (!verifyRequestTimestamp(timestamp)) {
      logger.warn(`Device request with invalid timestamp: ${deviceId}`);
      return res.status(401).json({ error: 'Invalid or expired timestamp' });
    }
    
    // Validate API key
    const device = validateDeviceApiKey(deviceId, apiKey, devices);
    if (!device) {
      logger.warn(`Device authentication failed: ${deviceId}`);
      return res.status(401).json({ error: 'Invalid device credentials' });
    }
    
    // Validate HMAC signature if provided
    if (signature) {
      const payloadForSigning = {
        deviceId,
        timestamp,
        action: req.path,
        method: req.method
      };
      
      if (!verifyDeviceSignature(payloadForSigning, signature, apiKey)) {
        logger.warn(`Device signature verification failed: ${deviceId}`);
        return res.status(401).json({ error: 'Invalid request signature' });
      }
    }
    
    // Attach device to request
    req.device = device;
    next();
  };
}

/**
 * Generate random API key for device (24 bytes hexadecimal)
 * @returns {string} Random API key
 */
function generateApiKey() {
  return crypto.randomBytes(24).toString('hex');
}

/**
 * Rotate device API key (issue new key, mark old as inactive)
 * @param {Object} device - Device object
 * @param {Object} allDevices - Array of all devices
 * @returns {string} New API key
 */
function rotateDeviceApiKey(device, allDevices = []) {
  const newKey = generateApiKey();
  
  // Store old key for reference/audit
  if (!device.api_key_history) {
    device.api_key_history = [];
  }
  
  device.api_key_history.push({
    key_hash: crypto.createHash('sha256').update(device.api_key).digest('hex'),
    rotated_at: new Date().toISOString()
  });
  
  // Keep only last 5 rotations
  if (device.api_key_history.length > 5) {
    device.api_key_history = device.api_key_history.slice(-5);
  }
  
  device.api_key = newKey;
  device.api_key_updated_at = new Date().toISOString();
  
  logger.info(`API key rotated for device: ${device.id}`);
  return newKey;
}

/**
 * Check if device is online/responsive
 * Tracks last heartbeat from device
 * @param {Object} device - Device object
 * @param {number} maxOfflineMs - Max time before considering offline (default 5 minutes)
 * @returns {boolean} True if device is online
 */
function isDeviceOnline(device, maxOfflineMs = 300000) {
  if (!device.last_heartbeat) return false;
  
  const lastHeartbeat = new Date(device.last_heartbeat).getTime();
  const now = Date.now();
  
  return (now - lastHeartbeat) < maxOfflineMs;
}

/**
 * Update device heartbeat to track availability
 * @param {Object} device - Device object
 */
function updateDeviceHeartbeat(device) {
  device.last_heartbeat = new Date().toISOString();
  device.status = 'online';
}

module.exports = {
  // Core functions
  validateDeviceApiKey,
  generateDeviceSignature,
  verifyDeviceSignature,
  verifyRequestTimestamp,
  
  // Middleware
  authenticateDevice,
  
  // Key management
  generateApiKey,
  rotateDeviceApiKey,
  
  // Device status
  isDeviceOnline,
  updateDeviceHeartbeat
};
