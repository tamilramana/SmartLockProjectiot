/**
 * Advanced Cryptography Utilities Module
 * Implements AES-256-GCM, RSA key exchange, HMAC signatures, and more
 */

const crypto = require('crypto');
const { logger } = require('./security_middleware');

/**
 * AES-256-GCM Encryption (for command payload encryption)
 * Industry-standard symmetric encryption with authentication
 */
class AESEncryption {
  constructor(masterKey) {
    this.algorithm = 'aes-256-gcm';
    // Ensure key is 32 bytes for AES-256
    this.key = Buffer.isBuffer(masterKey) 
      ? masterKey 
      : crypto.createHash('sha256').update(String(masterKey)).digest();
      
    if (this.key.length !== 32) {
      throw new Error('Master key must be 32 bytes for AES-256');
    }
  }
  
  /**
   * Encrypt data with AES-256-GCM
   * @param {string|Object} data - Data to encrypt
   * @param {Buffer} additionalData - Optional additional authenticated data
   * @returns {Object} { iv, encrypted, tag, algorithm }
   */
  encrypt(data, additionalData = null) {
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    
    if (additionalData) {
      cipher.setAAD(additionalData);
    }
    
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    let encrypted = cipher.update(dataStr, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    return {
      iv: iv.toString('hex'),
      encrypted,
      tag: tag.toString('hex'),
      algorithm: this.algorithm,
      aad: additionalData ? additionalData.toString('hex') : null
    };
  }
  
  /**
   * Decrypt AES-256-GCM encrypted data
   * @param {Object} encryptedData - { iv, encrypted, tag, aad }
   * @returns {Object|string} Decrypted data
   */
  decrypt(encryptedData) {
    try {
      const decipher = crypto.createDecipheriv(
        this.algorithm,
        this.key,
        Buffer.from(encryptedData.iv, 'hex')
      );
      
      if (encryptedData.aad) {
        decipher.setAAD(Buffer.from(encryptedData.aad, 'hex'));
      }
      
      decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
      
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      // Try to parse as JSON, otherwise return string
      try {
        return JSON.parse(decrypted);
      } catch {
        return decrypted;
      }
    } catch (error) {
      logger.error(`AES decryption failed: ${error.message}`);
      throw new Error('Decryption failed - data may be tampered');
    }
  }
}

/**
 * RSA Key Pair Generation and Usage (for key exchange)
 * Asymmetric encryption for secure key distribution
 */
class RSAEncryption {
  constructor() {
    this.algorithm = 'sha256';
  }
  
  /**
   * Generate RSA key pair (2048-bit)
   * @returns {Object} { publicKey, privateKey }
   */
  generateKeyPair() {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'rsa',
        {
          modulusLength: 2048,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
          }
        },
        (err, publicKey, privateKey) => {
          if (err) reject(err);
          else resolve({ publicKey, privateKey });
        }
      );
    });
  }
  
  /**
   * Encrypt data with RSA public key
   * @param {string|Buffer} data - Data to encrypt
   * @param {string} publicKey - RSA public key (PEM format)
   * @returns {string} Encrypted data (base64)
   */
  encryptWithPublicKey(data, publicKey) {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    
    const encrypted = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: this.algorithm
      },
      buffer
    );
    
    return encrypted.toString('base64');
  }
  
  /**
   * Decrypt data with RSA private key
   * @param {string} encryptedData - Base64 encrypted data
   * @param {string} privateKey - RSA private key (PEM format)
   * @returns {string} Decrypted data
   */
  decryptWithPrivateKey(encryptedData, privateKey) {
    try {
      const decrypted = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: this.algorithm
        },
        Buffer.from(encryptedData, 'base64')
      );
      
      return decrypted.toString('utf8');
    } catch (error) {
      logger.error(`RSA decryption failed: ${error.message}`);
      throw new Error('RSA decryption failed');
    }
  }
}

/**
 * HMAC-based Message Authentication Code
 * Verifies message integrity and authenticity
 */
class HMACSignature {
  /**
   * Generate HMAC signature
   * @param {string|Object} data - Data to sign
   * @param {string|Buffer} secret - Secret key
   * @param {string} algorithm - Hash algorithm (default: sha256)
   * @returns {string} HMAC signature (hex)
   */
  static sign(data, secret, algorithm = 'sha256') {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto
      .createHmac(algorithm, secret)
      .update(dataStr)
      .digest('hex');
  }
  
  /**
   * Verify HMAC signature
   * @param {string|Object} data - Original data
   * @param {string} signature - Provided signature (hex)
   * @param {string|Buffer} secret - Secret key
   * @param {string} algorithm - Hash algorithm (default: sha256)
   * @returns {boolean} True if signature is valid
   */
  static verify(data, signature, secret, algorithm = 'sha256') {
    try {
      const expected = this.sign(data, secret, algorithm);
      return crypto.timingSafeEqual(
        Buffer.from(signature, 'hex'),
        Buffer.from(expected, 'hex')
      );
    } catch (error) {
      return false;
    }
  }
}

/**
 * Secure Hash Functions
 */
class SecureHash {
  /**
   * Create SHA-256 hash
   * @param {string|Buffer} data - Data to hash
   * @returns {string} Hex hash
   */
  static sha256(data) {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto.createHash('sha256').update(dataStr).digest('hex');
  }
  
  /**
   * Create SHA-512 hash (more secure for critical data)
   * @param {string|Buffer} data - Data to hash
   * @returns {string} Hex hash
   */
  static sha512(data) {
    const dataStr = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto.createHash('sha512').update(dataStr).digest('hex');
  }
  
  /**
   * Create bcrypt-style password hash (already handled by bcryptjs)
   * Use this for non-password data that needs strong hashing
   * @param {string} data - Data to hash
   * @param {number} rounds - Salt rounds (default: 10)
   * @returns {Promise<string>} Hash promise
   */
  static async bcrypt(data, rounds = 10) {
    const bcrypt = require('bcryptjs');
    return await bcrypt.hash(data, rounds);
  }
  
  /**
   * Verify bcrypt hash
   * @param {string} data - Original data
   * @param {string} hash - Hash to verify against
   * @returns {Promise<boolean>} Verification result
   */
  static async bcryptVerify(data, hash) {
    const bcrypt = require('bcryptjs');
    return await bcrypt.compare(data, hash);
  }
}

/**
 * Key Derivation Functions
 * Derive secure keys from passwords or master secrets
 */
class KeyDerivation {
  /**
   * PBKDF2 key derivation (password-based)
   * @param {string} password - Password
   * @param {string|Buffer} salt - Salt (default: random 16 bytes)
   * @param {number} keyLength - Desired key length (default: 32 for AES-256)
   * @param {number} iterations - PBKDF2 iterations (default: 100000)
   * @returns {Object} { key, salt }
   */
  static pbkdf2(password, salt = null, keyLength = 32, iterations = 100000) {
    const actualSalt = salt ? (typeof salt === 'string' ? Buffer.from(salt, 'hex') : salt) : crypto.randomBytes(16);
    
    const key = crypto.pbkdf2Sync(
      password,
      actualSalt,
      iterations,
      keyLength,
      'sha256'
    );
    
    return {
      key: key.toString('hex'),
      salt: actualSalt.toString('hex'),
      iterations
    };
  }
  
  /**
   * Derive key from master key using HKDF
   * @param {string|Buffer} masterKey - Master key
   * @param {string} purpose - Key purpose (e.g., 'device-encryption')
   * @param {number} keyLength - Desired key length
   * @returns {Buffer} Derived key
   */
  static hkdf(masterKey, purpose = '', keyLength = 32) {
    const masterKeyBuf = typeof masterKey === 'string' 
      ? Buffer.from(masterKey, 'hex')
      : masterKey;
    
    const salt = Buffer.from(purpose, 'utf8');
    
    return crypto.hkdfSync('sha256', masterKeyBuf, salt, '', keyLength);
  }
}

/**
 * Secure Random Generation
 */
class SecureRandom {
  /**
   * Generate random hex string
   * @param {number} byteLength - Number of random bytes
   * @returns {string} Hex string
   */
  static hex(byteLength = 32) {
    return crypto.randomBytes(byteLength).toString('hex');
  }
  
  /**
   * Generate random bytes
   * @param {number} byteLength - Number of bytes
   * @returns {Buffer} Random buffer
   */
  static bytes(byteLength = 32) {
    return crypto.randomBytes(byteLength);
  }
  
  /**
   * Generate random integer between min and max
   * @param {number} min - Minimum value
   * @param {number} max - Maximum value
   * @returns {number} Random integer
   */
  static int(min, max) {
    const range = max - min;
    const randomBytes = crypto.randomBytes(4).readUInt32BE(0);
    return min + (randomBytes % range);
  }
}

module.exports = {
  // Classes
  AESEncryption,
  RSAEncryption,
  HMACSignature,
  SecureHash,
  KeyDerivation,
  SecureRandom
};
