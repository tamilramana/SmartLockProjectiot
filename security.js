const crypto = require('crypto');
const qrcode = require('qrcode');
const speakeasy = require('speakeasy');
const { authenticator } = require('otplib');

function generate2FASecret(username, issuer = 'SmartLock') {
  const secret = speakeasy.generateSecret({
    name: `${issuer} (${username})`,
    issuer,
    length: 20,
  });

  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url,
  };
}

async function generateQRCodeDataUrl(otpauthUrl) {
  return await qrcode.toDataURL(otpauthUrl);
}

function verify2FAToken(secret, token) {
  if (!secret || !token) return false;
  const normalized = String(token).replace(/\s+/g, '').trim();
  try {
    return authenticator.check(normalized, secret);
  } catch (error) {
    return false;
  }
}

function generateBackupCodes(count = 10) {
  return Array.from({ length: count }, () => crypto.randomBytes(4).toString('hex'));
}

function hashString(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function verifyBackupCode(code, hashes) {
  if (!code || !Array.isArray(hashes)) return -1;
  const hashed = hashString(code);
  return hashes.findIndex((h) => h === hashed);
}

function generateTrustedDeviceToken() {
  return crypto.randomBytes(24).toString('hex');
}

module.exports = {
  generate2FASecret,
  generateQRCodeDataUrl,
  verify2FAToken,
  generateBackupCodes,
  hashString,
  verifyBackupCode,
  generateTrustedDeviceToken,
};
