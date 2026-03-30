const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const WebSocket = require("ws");
const schedule = require("node-schedule");
const bcrypt = require("bcryptjs"); // Ensure this is bcryptjs
const { v4: uuidv4 } = require("uuid");
require("dotenv").config();

const { encryptPayload, decryptPayload, generateHMAC, authorize, logger, MASTER_KEY } = require("./security_middleware");
const {
  generate2FASecret,
  generateQRCodeDataUrl,
  verify2FAToken,
  generateBackupCodes,
  hashString,
  verifyBackupCode,
  generateTrustedDeviceToken,
} = require("./security");

const JWT_SECRET = process.env.JWT_SECRET || "supersecret_demo_change_in_prod";
const DATA_FILE = path.join(__dirname, "data.json");
const MFA_ISSUER = process.env.MFA_ISSUER || "SmartLock";
const MFA_PERIOD = 30;
const MFA_DIGITS = 6;

let jobs = {}; // scheduleId -> scheduledJob

// Connection pooling to prevent socket exhaustion
const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 10, timeout: 5000 });

/**
 * Robust private IP detection for CORS and Proxy safety
 */
function isPrivateIp(ip) {
  if (typeof ip !== 'string') return false;
  // Normalize input: remove IPv6 mapping, brackets, and whitespace
  const normalized = ip.trim().toLowerCase().replace(/^::ffff:/, '').replace(/^\[|\]$/g, '').split(':')[0].split('%')[0];
  
  if (normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1') return true;

  // Regex for private network ranges (10.x, 192.168.x, 172.16-31.x)
  const privateRange = /^(10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}|192\.168\.(?:[0-9]{1,3}\.){1,2}[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.(?:[0-9]{1,3}\.){1,2}[0-9]{1,3})$/;
  return privateRange.test(normalized);
}

// ===== MFA helpers (TOTP, no external deps) =====
function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const b of buffer) bits += b.toString(2).padStart(8, "0");
  let output = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5);
    output += alphabet[parseInt(chunk, 2)];
  }
  const rem = bits.length % 5;
  if (rem) {
    output += alphabet[parseInt(bits.slice(bits.length - rem).padEnd(5, "0"), 2)];
  }
  return output;
}

function base32ToBuffer(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = (str || "").toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of cleaned) {
    const val = alphabet.indexOf(ch);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateBase32Secret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

function totpToken(secret, timeMs = Date.now(), step = MFA_PERIOD, digits = MFA_DIGITS) {
  const key = base32ToBuffer(secret);
  const counter = Math.floor(timeMs / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter & 0xffffffff, 4);
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);
  return String(code).padStart(digits, "0");
}

function verifyTotp(secret, token, window = 1) {
  if (!secret || !token) return false;
  const normalized = String(token).replace(/\s+/g, "");
  for (let w = -window; w <= window; w++) {
    const t = Date.now() + w * MFA_PERIOD * 1000;
    if (totpToken(secret, t) === normalized) return true;
  }
  return false;
}

const app = express();
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : true,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "10kb" }));

// Enhanced Rate Limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again after 15 minutes"
}));

// enforce HTTPS in prod (supports proxy mode with x-forwarded-proto)
app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && !req.secure && req.get("x-forwarded-proto") !== "https") {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

// serve static files (index.html and assets) so GET / works
app.use(express.static(path.join(__dirname, 'public')));
app.use('/fa', express.static(
  path.join(__dirname, 'node_modules/@fortawesome/fontawesome-free')
));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));

// WebSocket Broadcasting
let wss;
function broadcast(data) {
  if (!wss || !WebSocket) return;
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => { if (client.readyState === WebSocket.OPEN) client.send(msg); });
}

/**
 * Data Persistence Helpers (Pure JS)
 */
function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      const initial = { users: [], devices: [], logs: [], notifications: [], schedules: [] };
      fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
      return initial;
    }
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    let modified = false;
    if (Array.isArray(data.users)) {
      data.users.forEach((user) => {
        if (ensureUserMfaFields(user)) modified = true;
      });
    }
    if (modified) {
      saveData(data);
    }
    return data;
  } catch (e) {
    console.error("Error loading data.json:", e);
    return { users: [], devices: [], logs: [], notifications: [], schedules: [] };
  }
}

function saveData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (e) {
    console.error("Error saving data.json:", e);
  }
}

function ensureSampleData() {
  const data = loadData();
  let changed = false;

  if (!Array.isArray(data.users)) { data.users = []; changed = true; }
  if (!Array.isArray(data.devices)) { data.devices = []; changed = true; }
  if (!Array.isArray(data.logs)) { data.logs = []; changed = true; }
  if (!Array.isArray(data.notifications)) { data.notifications = []; changed = true; }
  if (!Array.isArray(data.schedules)) { data.schedules = []; changed = true; }

  let adminUser = data.users.find(u => u.username === 'admin');
  if (!adminUser) {
    const adminId = uuidv4();
    data.users.push({
      id: adminId,
      username: 'admin',
      password_hash: bcrypt.hashSync('admin', 10),
      role: 'admin',
      mfa_enabled: false,
      mfa_secret: null,
      mfa_secret_pending: null,
      backup_codes: [],
      trusted_devices: [],
      created_at: new Date().toISOString()
    });
    changed = true;
    adminUser = data.users.find(u => u.username === 'admin');
  }

  if (!data.users.some(u => u.username === 'user')) {
    data.users.push({
      id: uuidv4(),
      username: 'user',
      password_hash: bcrypt.hashSync('admin', 10),
      role: 'user',
      mfa_enabled: false,
      mfa_secret: null,
      mfa_secret_pending: null,
      backup_codes: [],
      trusted_devices: [],
      created_at: new Date().toISOString()
    });
    changed = true;
  }

  if (!data.devices.length) {
    data.devices = [
      {
        id: uuidv4(),
        device_id: 'front-door',
        deviceId: 'front-door',
        name: 'Front Door Lock',
        location: 'Main Entrance',
        ip_address: '192.168.1.101',
        api_key: crypto.randomBytes(24).toString('hex'),
        status: 'locked',
        owner_id: adminUser.id
      },
      {
        id: uuidv4(),
        device_id: 'garage',
        deviceId: 'garage',
        name: 'Garage Door',
        location: 'Garage',
        ip_address: '192.168.1.102',
        api_key: crypto.randomBytes(24).toString('hex'),
        status: 'unlocked',
        owner_id: adminUser.id
      },
      {
        id: uuidv4(),
        device_id: 'backyard',
        deviceId: 'backyard',
        name: 'Backyard Gate',
        location: 'Backyard',
        ip_address: '192.168.1.103',
        api_key: crypto.randomBytes(24).toString('hex'),
        status: 'offline',
        owner_id: adminUser.id
      }
    ];
    changed = true;
  }

  if (!data.notifications.length) {
    data.notifications = [
      {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        level: 'info',
        message: 'Welcome to SmartLock. Sample devices are ready.'
      },
      {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        level: 'warning',
        message: 'Your garage device is unlocked; keep an eye on it.'
      }
    ];
    changed = true;
  }

  if (!data.logs.length) {
    data.logs = [
      {
        id: uuidv4(),
        timestamp: new Date().toISOString(),
        userId: adminUser.id,
        user: adminUser.username,
        action: 'system:init',
        deviceId: null,
        details: 'Initialized sample data',
        severity: 'info',
        log_hmac: generateHMAC(`${adminUser.id}system:init${new Date().toISOString()}`, MASTER_KEY.toString())
      }
    ];
    changed = true;
  }

  if (!data.schedules.length) {
    data.schedules = [
      {
        id: uuidv4(),
        deviceId: data.devices[0]?.id || null,
        action: 'lock',
        time: new Date(Date.now() + 3600 * 1000).toISOString(),
        created_by: adminUser.id,
        created_at: new Date().toISOString()
      }
    ];
    changed = true;
  }

  if (changed) saveData(data);
}

/**
 * Helper to forward commands to ESP devices with proper Promise handling.
 * Prevents socket hang up errors with explicit timeout and cleanup.
 */
function forwardToDevice(deviceId, action) {
  return new Promise((resolve, reject) => {
    const data = loadData();
    const device = data.devices.find(d => d.id === deviceId);
    
    if (!device || !device.ip_address) {
      return reject(new Error("Device offline or not found"));
    }

    const ip = device.ip_address;
    
    // Create a 32-byte key from device API key or master key
    const deviceKey = crypto.createHash('sha256').update(device.api_key || MASTER_KEY.toString()).digest();

    const commandPayload = {
      action: action,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(8).toString('hex')
    };

    // Encrypt payload using AES-256-GCM
    const encryptedData = encryptPayload(commandPayload, deviceKey);
    const postData = JSON.stringify(encryptedData);

    if (!ip) return reject(new Error("No IP provided"));

    const options = {
      hostname: ip,
      port: 80,
      path: '/api/command',
      method: "POST",
      timeout: 4000, 
      agent: httpAgent,
      headers: {
        'Connection': 'close',
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    };

    const req = http.request(options, (res) => {
      res.on('data', () => {}); 
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode });
        } else {
          reject(new Error(`Device responded with status ${res.statusCode}`));
        }
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    req.on('timeout', () => {
      req.destroy(); // Explicitly destroy request on timeout
      reject(new Error("Request timed out"));
    });

    req.write(postData);
    req.end();
  });
}

function forwardToIp(ipAddress, action) {
  return new Promise((resolve, reject) => {
    if (!ipAddress) return reject(new Error('IP address is required'));

    const sanitized = ipAddress.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    const [hostname, port] = sanitized.split(':');
    const options = {
      hostname,
      port: port ? parseInt(port, 10) : 80,
      path: `/${action}`,
      method: 'GET',
      timeout: 4000,
      agent: httpAgent,
      headers: { Connection: 'close' }
    };

    const req = http.request(options, (res) => {
      res.on('data', () => {});
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode });
        } else {
          reject(new Error(`Device responded with status ${res.statusCode}`));
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.end();
  });
}

function normalizeDevice(device) {
  return {
    ...device,
    deviceId: device.deviceId || device.device_id || device.id,
    ipAddress: device.ipAddress || device.ip_address || null
  };
}

function findDeviceById(deviceId) {
  const data = loadData();
  return data.devices.find(d => d.id === deviceId || d.deviceId === deviceId);
}

function createDeviceAudit({ userId, action, device, status, details }) {
  if (!device) return;
  pushLog({
    userId,
    action,
    deviceId: device.id,
    details: details || `${action} ${device.name || device.deviceId || device.id}`,
    severity: 'info'
  });
}

function initializeSampleData() {
  ensureSampleData();
}

function initializeScheduleJobs() {
  const data = loadData();
  if (!Array.isArray(data.schedules)) return;
  data.schedules.forEach(scheduleJob);
}

function pushLog({ userId, action, deviceId, details, severity = 'info' }) {
  const data = loadData();
  const timestamp = new Date().toISOString();
  const hmac = generateHMAC(`${userId || 'system'}${action}${timestamp}`, MASTER_KEY.toString());
  const user = userId ? data.users.find(u => u.id === userId) : null;
  
  data.logs.unshift({
    id: uuidv4(),
    timestamp,
    userId,
    user: user ? user.username : null,
    action,
    deviceId,
    details,
    severity,
    log_hmac: hmac
  });
  
  saveData(data);
}

function pushNotification(level, message) {
  const data = loadData();
  data.notifications.unshift({ id: uuidv4(), timestamp: new Date().toISOString(), level, message });
  saveData(data);
}

function getDeviceIp(deviceId) {
  const data = loadData();
  const device = data.devices.find(d => d.id === deviceId || d.deviceId === deviceId);
  return device ? device.ip_address : null;
}

function ensureUserMfaFields(user) {
  if (!user) return false;
  let changed = false;
  if (typeof user.mfa_enabled !== 'boolean') { user.mfa_enabled = false; changed = true; }
  if (typeof user.mfa_secret === 'undefined') { user.mfa_secret = null; changed = true; }
  if (typeof user.mfa_secret_pending === 'undefined') { user.mfa_secret_pending = null; changed = true; }
  if (!Array.isArray(user.backup_codes)) { user.backup_codes = []; changed = true; }
  if (!Array.isArray(user.trusted_devices)) { user.trusted_devices = []; changed = true; }
  return changed;
}

function getTrustedDeviceTokenFromRequest(req) {
  return req.headers['x-trusted-device'] || req.body?.trustedDeviceToken || null;
}

function pruneTrustedDevices(user) {
  if (!user || !Array.isArray(user.trusted_devices)) return;
  const now = Date.now();
  user.trusted_devices = user.trusted_devices.filter((entry) => entry.expiresAt > now);
}

function isTrustedDevice(user, token) {
  if (!user || !token || !Array.isArray(user.trusted_devices)) return false;
  pruneTrustedDevices(user);
  const tokenHash = hashString(token);
  return user.trusted_devices.some((entry) => entry.tokenHash === tokenHash);
}

function addTrustedDevice(user, token, deviceName = 'browser') {
  if (!user || !token) return;
  ensureUserMfaFields(user);
  pruneTrustedDevices(user);
  const tokenHash = hashString(token);
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  user.trusted_devices.push({ id: uuidv4(), tokenHash, deviceName, createdAt: new Date().toISOString(), expiresAt });
}

function consumeBackupCode(user, code) {
  if (!user || !code || !Array.isArray(user.backup_codes)) return false;
  const idx = verifyBackupCode(code, user.backup_codes);
  if (idx === -1) return false;
  user.backup_codes.splice(idx, 1);
  return true;
}

function sanitizeUserForPublic(user) {
  if (!user) return null;
  const { password_hash, mfa_secret, mfa_secret_pending, backup_codes, trusted_devices, ...payload } = user;
  return payload;
}

function requireAuth(req, res, next) {
  const auth = req.headers["authorization"] || "";
  const m = auth.match(/^Bearer\s+(.+)$/);
  if (!m) return res.status(401).json({ error: "Unauthorized" });
  const token = m[1];

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// scheduling helpers: use real scheduler if available, otherwise no-op but keep API behavior
function scheduleJob(sch) {
  // sch: { id, deviceId, time (ISO/cron) OR {daysOfWeek, hour, minute}, action: 'lock'|'unlock' }
  if (!sch || !sch.id) return;
  // cancel existing
  cancelJob(sch.id);

  try {
    const executeTask = async () => {
      const data = loadData();
      const newStatus = sch.action === 'lock' ? 'locked' : 'unlocked';

      if (sch.deviceId) {
        const devIdx = data.devices.findIndex(d => d.id === sch.deviceId);
        if (devIdx !== -1) {
          data.devices[devIdx].status = newStatus;
          saveData(data);
        }
        if (devIdx !== -1 && data.devices[devIdx].ip_address) {
          forwardToDevice(sch.deviceId, `/${sch.action}`).catch(e => logger.error(`Schedule ${sch.action} error for ${sch.deviceId}: ${e.message}`));
        }
      } else {
        data.devices = (data.devices || []).map(d => ({ ...d, status: newStatus }));
        saveData(data);
        (data.devices || []).forEach(d => {
          if (d.ip_address) {
            forwardToDevice(d.id, `/${sch.action}`).catch(e => logger.error(`Schedule ${sch.action} error for ${d.id}: ${e.message}`));
          }
        });
      }

      pushLog({ userId: null, action: `schedule:${sch.action}`, deviceId: sch.deviceId || null, details: `Auto ${sch.action} via schedule` });
      broadcast({ type: 'device_update' });
    };

    let job;
    if (sch.daysOfWeek && Array.isArray(sch.daysOfWeek)) {
      const rule = new schedule.RecurrenceRule();
      rule.dayOfWeek = sch.daysOfWeek;
      rule.hour = sch.hour || 0;
      rule.minute = sch.minute || 0;
      job = schedule.scheduleJob(rule, executeTask);
    } else {
      const when = new Date(sch.time);
      job = schedule.scheduleJob(!isNaN(when) ? when : sch.time, executeTask);
    }
    jobs[sch.id] = job;
  } catch (e) {
    console.error('Failed to schedule', sch, e);
  }
}

function cancelJob(id) {
  if (!id) return;
  if (jobs[id]) {
    try { jobs[id].cancel(); } catch(e){ /* ignore */ }
    delete jobs[id];
  }
}

function executeScheduledEntry(sch) {
  const data = loadData();
  const newStatus = sch.action === 'lock' ? 'locked' : 'unlocked';
  if (sch.deviceId) {
    const device = data.devices.find(d => d.id === sch.deviceId || d.deviceId === sch.deviceId);
    if (device) {
      device.status = newStatus;
      if (device.ip_address) {
        forwardToDevice(device.id, `/${sch.action}`).catch(e => logger.error(`Scheduled ${sch.action} error for ${device.id}: ${e.message}`));
      }
      pushLog({ userId: null, action: `schedule:${sch.action}`, deviceId: device.id, details: `Scheduled ${sch.action} for ${device.name}` });
      broadcast({ type: 'device_update' });
      saveData(data);
    }
  } else {
    data.devices = (data.devices || []).map(device => ({ ...device, status: newStatus }));
    data.devices.forEach(device => {
      if (device.ip_address) {
        forwardToDevice(device.id, `/${sch.action}`).catch(e => logger.error(`Scheduled ${sch.action} error for ${device.id}: ${e.message}`));
      }
    });
    pushLog({ userId: null, action: `schedule:${sch.action}`, deviceId: null, details: `Scheduled ${sch.action} for all devices` });
    broadcast({ type: 'device_update' });
    saveData(data);
  }
}

function isSameMinute(timestamp, now) {
  if (!timestamp) return false;
  const last = new Date(timestamp);
  return last.getFullYear() === now.getFullYear() && last.getMonth() === now.getMonth() && last.getDate() === now.getDate() && last.getHours() === now.getHours() && last.getMinutes() === now.getMinutes();
}

function checkSchedules() {
  const now = new Date();
  const data = loadData();
  let changed = false;

  data.schedules = (data.schedules || []).filter(sch => {
    let shouldRun = false;

    if (sch.time) {
      const when = new Date(sch.time);
      if (!isNaN(when) && when <= now && (!sch.lastRun || new Date(sch.lastRun) < when)) {
        shouldRun = true;
      }
    } else if (Array.isArray(sch.daysOfWeek) && typeof sch.hour === 'number' && typeof sch.minute === 'number') {
      if (sch.daysOfWeek.includes(now.getDay()) && sch.hour === now.getHours() && sch.minute === now.getMinutes() && !isSameMinute(sch.lastRun, now)) {
        shouldRun = true;
      }
    }

    if (shouldRun) {
      executeScheduledEntry(sch);
      if (sch.time) {
        changed = true;
        return false;
      }
      sch.lastRun = now.toISOString();
      changed = true;
    }
    return true;
  });

  if (changed) {
    saveData(data);
  }
}

// restore existing sample data and schedule jobs after restart
initializeSampleData();
initializeScheduleJobs();
checkSchedules();
setInterval(checkSchedules, 60 * 1000);

// ===== routes =====

// Health Check Endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// login
app.post("/login", async (req, res) => {
  const {
    username,
    password,
    mfaToken,
    backupCode,
    rememberDevice,
    deviceName
  } = req.body || {};
  const providedTrustedToken = getTrustedDeviceTokenFromRequest(req);
  const data = loadData();
  
  const user = data.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  ensureUserMfaFields(user);

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  if (user.mfa_enabled) {
    let authenticatedWithMfa = false;

    if (providedTrustedToken && isTrustedDevice(user, providedTrustedToken)) {
      authenticatedWithMfa = true;
    }

    if (!authenticatedWithMfa && mfaToken && verify2FAToken(user.mfa_secret, mfaToken)) {
      authenticatedWithMfa = true;
    }

    if (!authenticatedWithMfa && backupCode && consumeBackupCode(user, backupCode)) {
      authenticatedWithMfa = true;
    }

    if (!authenticatedWithMfa) {
      saveData(data);
      return res.json({ success: false, mfaRequired: true });
    }

    saveData(data);
  }

  let trustedDeviceToken = null;
  if (user.mfa_enabled && rememberDevice) {
    trustedDeviceToken = generateTrustedDeviceToken();
    addTrustedDevice(user, trustedDeviceToken, deviceName || 'browser');
    saveData(data);
  }

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const response = { success: true, token, username: user.username, role: user.role };
  if (trustedDeviceToken) response.trustedDeviceToken = trustedDeviceToken;
  res.json(response);
});

app.post("/login/2fa", async (req, res) => {
  const {
    username,
    password,
    token,
    backupCode,
    rememberDevice,
    deviceName
  } = req.body || {};
  const data = loadData();
  const user = data.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  ensureUserMfaFields(user);

  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  if (!user.mfa_enabled) {
    return res.status(400).json({ error: "2FA is not enabled for this account" });
  }

  let authenticatedWithMfa = false;
  if (token && verify2FAToken(user.mfa_secret, token)) authenticatedWithMfa = true;
  if (!authenticatedWithMfa && backupCode && consumeBackupCode(user, backupCode)) authenticatedWithMfa = true;

  if (!authenticatedWithMfa) {
    saveData(data);
    return res.status(401).json({ error: "Invalid 2FA code" });
  }

  let trustedDeviceToken = null;
  if (rememberDevice) {
    trustedDeviceToken = generateTrustedDeviceToken();
    addTrustedDevice(user, trustedDeviceToken, deviceName || 'browser');
    saveData(data);
  }

  const jwtToken = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  const response = { success: true, token: jwtToken, username: user.username, role: user.role };
  if (trustedDeviceToken) response.trustedDeviceToken = trustedDeviceToken;
  res.json(response);
});

// MFA setup for current user
async function handleMfaSetup(req, res) {
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const secretData = generate2FASecret(user.username, MFA_ISSUER);
  user.mfa_secret_pending = secretData.secret;
  ensureUserMfaFields(user);
  saveData(data);

  try {
    const qrDataUrl = await generateQRCodeDataUrl(secretData.otpauthUrl);
    res.json({ success: true, secret: secretData.secret, otpauthUrl: secretData.otpauthUrl, qrDataUrl });
  } catch (err) {
    res.json({ success: true, secret: secretData.secret, otpauthUrl: secretData.otpauthUrl });
  }
}

async function handleMfaVerify(req, res) {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Token is required" });
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureUserMfaFields(user);

  if (user.mfa_secret_pending && verify2FAToken(user.mfa_secret_pending, token)) {
    return res.json({ success: true, valid: true, pending: true });
  }
  if (user.mfa_secret && verify2FAToken(user.mfa_secret, token)) {
    return res.json({ success: true, valid: true, pending: false });
  }

  res.status(401).json({ error: "Invalid MFA code" });
}

function handleMfaEnable(req, res) {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Token is required" });
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureUserMfaFields(user);
  if (!user.mfa_secret_pending) return res.status(400).json({ error: "No pending MFA setup" });
  if (!verify2FAToken(user.mfa_secret_pending, token)) {
    return res.status(401).json({ error: "Invalid MFA code" });
  }

  user.mfa_secret = user.mfa_secret_pending;
  user.mfa_enabled = true;
  user.mfa_secret_pending = null;
  const codes = generateBackupCodes(10);
  user.backup_codes = codes.map(hashString);
  ensureUserMfaFields(user);
  saveData(data);
  pushLog({ userId: req.user.id, action: "mfa:enable", details: "Enabled MFA" });
  res.json({ success: true, backupCodes: codes });
}

function handleMfaDisable(req, res) {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "Token is required" });
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureUserMfaFields(user);
  if (!user.mfa_enabled || !user.mfa_secret) return res.status(400).json({ error: "MFA not enabled" });

  const hasValidToken = verify2FAToken(user.mfa_secret, token) || consumeBackupCode(user, token);
  if (!hasValidToken) {
    return res.status(401).json({ error: "Invalid MFA code" });
  }

  user.mfa_enabled = false;
  user.mfa_secret = null;
  user.mfa_secret_pending = null;
  user.backup_codes = [];
  user.trusted_devices = [];
  saveData(data);
  pushLog({ userId: req.user.id, action: "mfa:disable", details: "Disabled MFA" });
  res.json({ success: true });
}

function handleBackupCodes(req, res) {
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureUserMfaFields(user);
  if (!user.mfa_enabled) return res.status(400).json({ error: "MFA not enabled" });

  const codes = generateBackupCodes(10);
  user.backup_codes = codes.map(hashString);
  saveData(data);
  res.json({ success: true, backupCodes: codes });
}

function handleVerifyBackup(req, res) {
  const { code } = req.body || {};
  if (!code) return res.status(400).json({ error: "Backup code is required" });
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureUserMfaFields(user);

  if (verifyBackupCode(code, user.backup_codes) !== -1) {
    return res.json({ success: true });
  }
  res.status(401).json({ error: "Invalid backup code" });
}

function handleTrustDevice(req, res) {
  const { deviceName } = req.body || {};
  const data = loadData();
  const user = data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  ensureUserMfaFields(user);
  if (!user.mfa_enabled) return res.status(400).json({ error: "MFA not enabled" });

  const trustedToken = generateTrustedDeviceToken();
  addTrustedDevice(user, trustedToken, deviceName || 'browser');
  saveData(data);
  res.json({ success: true, trustedDeviceToken: trustedToken });
}

app.post("/mfa/setup", requireAuth, handleMfaSetup);
app.post("/api/2fa/setup", requireAuth, handleMfaSetup);
app.post("/mfa/verify", requireAuth, handleMfaVerify);
app.post("/api/2fa/verify", requireAuth, handleMfaVerify);
app.post("/mfa/enable", requireAuth, handleMfaEnable);
app.post("/api/2fa/enable", requireAuth, handleMfaEnable);
app.post("/mfa/disable", requireAuth, handleMfaDisable);
app.post("/api/2fa/disable", requireAuth, handleMfaDisable);
app.post("/mfa/backup-codes", requireAuth, handleBackupCodes);
app.post("/api/2fa/backup-codes", requireAuth, handleBackupCodes);
app.post("/mfa/verify-backup", requireAuth, handleVerifyBackup);
app.post("/api/2fa/verify-backup", requireAuth, handleVerifyBackup);
app.post("/api/2fa/trust-device", requireAuth, handleTrustDevice);
app.post("/mfa/trust-device", requireAuth, handleTrustDevice);

// users (admin management)
app.get("/users", requireAuth, (req, res) => {
  const data = loadData();
  const users = data.users.map(({ password_hash, mfa_secret, mfa_secret_pending, ...u }) => u);
  res.json(users);
});

app.post("/users", requireAuth, async (req, res) => {
  const u = req.body || {};
  if (!u.username || !u.password) return res.status(400).json({ error: 'username & password required' });
  
  const data = loadData();
  if (data.users.some(user => user.username === u.username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const hash = bcrypt.hashSync(u.password, 10);
  data.users.push({
    id: uuidv4(),
    username: u.username,
    password_hash: hash,
    role: u.role || 'user',
    mfa_enabled: false,
    created_at: new Date().toISOString()
  });
  
  saveData(data);
  res.json({ success: true });
});

app.get('/users/:username', requireAuth, (req, res) => {
  const username = req.params.username;
  const data = loadData();
  const user = data.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password_hash, mfa_secret, mfa_secret_pending, ...payload } = user;
  res.json(payload);
});

app.put('/users/:username', requireAuth, (req, res) => {
  const username = req.params.username;
  const { password, role } = req.body || {};
  const data = loadData();
  const user = data.users.find(u => u.username === username);
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (password) {
    user.password_hash = bcrypt.hashSync(password, 10);
  }
  if (role) {
    user.role = role;
  }
  saveData(data);
  pushLog({ userId: req.user.id, action: 'user:update', details: `Updated ${username}` });
  res.json({ success: true });
});

app.delete('/users/:username', requireAuth, (req, res) => {
  const username = req.params.username;
  const data = loadData();
  const beforeCount = data.users.length;
  data.users = data.users.filter(u => u.username !== username);
  if (data.users.length === beforeCount) {
    return res.status(404).json({ error: 'User not found' });
  }
  saveData(data);
  pushLog({ userId: req.user.id, action: 'user:delete', details: `Deleted ${username}` });
  res.json({ success: true });
});

// devices list
app.get("/devices", requireAuth, (req, res) => {
  const data = loadData();
  res.json((data.devices || []).map(normalizeDevice));
});

// API device aliases
app.get("/api/devices", requireAuth, (req, res) => {
  const data = loadData();
  res.json((data.devices || []).map(normalizeDevice));
});

app.post("/api/devices", requireAuth, (req, res) => {
  const d = req.body || {};
  const data = loadData();
  const id = uuidv4();
  const apiKey = crypto.randomBytes(32).toString('hex');

  const device = {
    id,
    device_id: d.deviceId || id,
    deviceId: d.deviceId || id,
    name: d.name || "Unnamed",
    location: d.location || "",
    ip_address: d.ipAddress || d.ip_address || null,
    api_key: apiKey,
    status: 'offline',
    owner_id: req.user.id
  };

  data.devices.push(device);
  saveData(data);
  pushLog({ userId: req.user.id, action: 'device:create', deviceId: id, details: `Created device ${device.name}` });
  res.json({ success: true, device: normalizeDevice(device) });
});

app.post('/api/devices/:id/lock', requireAuth, (req, res) => {
  const id = req.params.id;
  const data = loadData();
  const device = data.devices.find(d => d.id === id || d.deviceId === id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  device.status = 'locked';
  saveData(data);
  pushLog({ userId: req.user.id, action: 'device:lock', deviceId: device.id, details: `Locked ${device.name}` });
  res.json({ success: true, status: 'locked' });
});

app.post('/api/devices/:id/unlock', requireAuth, (req, res) => {
  const id = req.params.id;
  const data = loadData();
  const device = data.devices.find(d => d.id === id || d.deviceId === id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  device.status = 'unlocked';
  saveData(data);
  pushLog({ userId: req.user.id, action: 'device:unlock', deviceId: device.id, details: `Unlocked ${device.name}` });
  res.json({ success: true, status: 'unlocked' });
});

app.get('/api/devices/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const data = loadData();
  const device = data.devices.find(d => d.id === id || d.deviceId === id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  res.json(normalizeDevice(device));
});

app.put('/api/devices/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const body = req.body || {};
  const data = loadData();
  const device = data.devices.find(d => d.id === id || d.deviceId === id);
  if (!device) return res.status(404).json({ error: 'Device not found' });

  if (body.deviceId) {
    device.device_id = body.deviceId;
    device.deviceId = body.deviceId;
  }
  if (body.name) device.name = body.name;
  if (body.location) device.location = body.location;
  if (body.ipAddress || body.ip_address) {
    device.ip_address = body.ipAddress || body.ip_address;
    device.ipAddress = body.ipAddress || body.ip_address;
  }
  if (body.status) device.status = body.status;

  saveData(data);
  pushLog({ userId: req.user.id, action: 'device:update', deviceId: device.id, details: `Updated ${device.name}` });
  broadcast({ type: 'device_update' });
  res.json({ success: true, device: normalizeDevice(device) });
});

app.delete('/api/devices/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const data = loadData();
  const beforeCount = data.devices.length;
  data.devices = data.devices.filter(d => d.id !== id && d.deviceId !== id);
  if (data.devices.length === beforeCount) {
    return res.status(404).json({ error: 'Device not found' });
  }
  saveData(data);
  pushLog({ userId: req.user.id, action: 'device:delete', deviceId: id, details: `Deleted device ${id}` });
  broadcast({ type: 'device_update' });
  res.json({ success: true });
});

app.post('/api/devices/:id/wifi/connect', requireAuth, (req, res) => {
  const id = req.params.id;
  const { wifiSSID, wifiPassword } = req.body || {};
  if (!wifiSSID || !wifiPassword) {
    return res.status(400).json({ error: 'wifiSSID and wifiPassword are required' });
  }
  const data = loadData();
  const device = data.devices.find(d => d.id === id || d.deviceId === id);
  if (!device) return res.status(404).json({ error: 'Device not found' });

  device.wifi_ssid = wifiSSID;
  device.last_wifi_connected_at = new Date().toISOString();
  device.status = 'online';
  saveData(data);

  pushLog({ userId: req.user.id, action: 'device:wifi_connect', deviceId: device.id, details: `Connected ${device.name} to WiFi ${wifiSSID}` });
  pushNotification('info', `Device ${device.name} connected to WiFi`);
  broadcast({ type: 'device_update' });
  res.json({ success: true });
});

// create device
app.post("/devices", requireAuth, (req, res) => {
  const d = req.body || {};
  const data = loadData();
  const id = uuidv4();
  const apiKey = crypto.randomBytes(32).toString('hex');
  
  data.devices.push({
    id,
    device_id: d.deviceId || id,
    deviceId: d.deviceId || id,
    name: d.name || "Unnamed",
    location: d.location || "",
    ip_address: d.ipAddress || d.ip_address || null,
    api_key: apiKey,
    status: 'offline',
    owner_id: req.user.id
  });

  saveData(data);

  pushLog({ userId: req.user.id, action: 'device:create', deviceId: id });
  pushNotification('info', `Device ${d.name || id} added`);
  broadcast({ type: 'device_update' });
  res.json({ id, apiKey });
});

// delete device
app.delete("/devices/:id", requireAuth, (req, res) => {
  const data = loadData();
  const id = req.params.id;
  data.devices = data.devices.filter(d => d.id !== id);
  saveData(data);

  pushLog({ userId: req.user.id, action: 'device:delete', deviceId: id });
  broadcast({ type: 'device_update' });
  res.json({ success: true });
});

app.get('/devices/:id', requireAuth, (req, res) => {
  const data = loadData();
  const device = data.devices.find(d => d.id === req.params.id);
  if (!device) return res.status(404).json({ error: 'Device not found' });
  res.json(normalizeDevice(device));
});

app.put('/devices/:id', requireAuth, (req, res) => {
  const body = req.body || {};
  const data = loadData();
  const device = data.devices.find(d => d.id === req.params.id);
  if (!device) return res.status(404).json({ error: 'Device not found' });

  if (body.deviceId) {
    device.device_id = body.deviceId;
    device.deviceId = body.deviceId;
  }
  if (body.name) device.name = body.name;
  if (body.location) device.location = body.location;
  if (body.ipAddress || body.ip_address) {
    device.ip_address = body.ipAddress || body.ip_address;
    device.ipAddress = body.ipAddress || body.ip_address;
  }
  if (body.status) device.status = body.status;

  saveData(data);
  pushLog({ userId: req.user.id, action: 'device:update', deviceId: device.id, details: `Updated ${device.name}` });
  broadcast({ type: 'device_update' });
  res.json({ success: true, device: normalizeDevice(device) });
});

app.post('/devices/:id/wifi/connect', requireAuth, (req, res) => {
  const { wifiSSID, wifiPassword } = req.body || {};
  if (!wifiSSID || !wifiPassword) {
    return res.status(400).json({ error: 'wifiSSID and wifiPassword are required' });
  }

  const data = loadData();
  const device = data.devices.find(d => d.id === req.params.id);
  if (!device) return res.status(404).json({ error: 'Device not found' });

  device.wifi_ssid = wifiSSID;
  device.last_wifi_connected_at = new Date().toISOString();
  device.status = 'online';
  saveData(data);

  pushLog({ userId: req.user.id, action: 'device:wifi_connect', deviceId: device.id, details: `Connected ${device.name} to WiFi ${wifiSSID}` });
  pushNotification('info', `Device ${device.name} connected to WiFi`);
  broadcast({ type: 'device_update' });
  res.json({ success: true });
});

app.post('/lock', requireAuth, (req, res) => {
  const data = loadData();
  data.devices = data.devices.map(device => ({ ...device, status: 'locked' }));
  saveData(data);
  pushLog({ userId: req.user.id, action: 'bulk:lock', details: 'Locked all devices' });
  data.devices.forEach(device => {
    if (device.ip_address) {
      forwardToDevice(device.id, '/lock').catch(e => logger.error(`Bulk lock error for ${device.id}: ${e.message}`));
    }
  });
  broadcast({ type: 'device_update' });
  res.json({ success: true, status: 'locked' });
});

app.post('/unlock', requireAuth, (req, res) => {
  const data = loadData();
  data.devices = data.devices.map(device => ({ ...device, status: 'unlocked' }));
  saveData(data);
  pushLog({ userId: req.user.id, action: 'bulk:unlock', details: 'Unlocked all devices' });
  data.devices.forEach(device => {
    if (device.ip_address) {
      forwardToDevice(device.id, '/unlock').catch(e => logger.error(`Bulk unlock error for ${device.id}: ${e.message}`));
    }
  });
  broadcast({ type: 'device_update' });
  res.json({ success: true, status: 'unlocked' });
});

app.post('/proxy/:action', requireAuth, async (req, res) => {
  const { action } = req.params;
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'IP address is required' });
  if (!['lock', 'unlock'].includes(action)) {
    return res.status(400).json({ error: 'Unsupported action' });
  }

  try {
    await forwardToIp(ip, action);
    res.json({ success: true });
  } catch (err) {
    logger.warn(`Proxy ${action} failed for ${ip}: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// notifications
app.get("/notifications", requireAuth, (req, res) => {
  const data = loadData();
  res.json(data.notifications);
});

app.post('/notifications', requireAuth, (req, res) => {
  const { message, level } = req.body || {};
  if (!message) return res.status(400).json({ error: 'Message is required' });
  const data = loadData();
  const note = {
    id: uuidv4(),
    message: message.toString(),
    level: level || 'info',
    timestamp: new Date().toISOString()
  };
  data.notifications.unshift(note);
  saveData(data);
  pushLog({ userId: req.user.id, action: 'notification:create', details: message });
  res.json({ success: true, note });
});

app.delete('/notifications/:id', requireAuth, (req, res) => {
  const data = loadData();
  const before = data.notifications.length;
  data.notifications = data.notifications.filter(n => n.id !== req.params.id);
  if (data.notifications.length === before) {
    return res.status(404).json({ error: 'Notification not found' });
  }
  saveData(data);
  pushLog({ userId: req.user.id, action: 'notification:delete', details: req.params.id });
  res.json({ success: true });
});

// logs
app.get("/logs", requireAuth, (req, res) => {
  const data = loadData();
  res.json(data.logs);
});

app.post('/logs', requireAuth, (req, res) => {
  const entry = req.body || {};
  const data = loadData();
  const newLog = {
    id: uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    deviceName: entry.deviceName || entry.deviceId || null,
    deviceIp: entry.deviceIp || null,
    user: entry.user || req.user.username,
    action: entry.action || 'log',
    status: entry.status || 'info',
    details: entry.details || ''
  };
  data.logs.unshift(newLog);
  saveData(data);
  res.json({ success: true, log: newLog });
});

app.get('/api/logs', requireAuth, (req, res) => {
  const data = loadData();
  res.json(data.logs);
});

app.post('/api/logs', requireAuth, (req, res) => {
  const entry = req.body || {};
  const data = loadData();
  const newLog = {
    id: uuidv4(),
    timestamp: entry.timestamp || new Date().toISOString(),
    deviceName: entry.deviceName || entry.deviceId || null,
    deviceIp: entry.deviceIp || null,
    user: entry.user || req.user.username,
    action: entry.action || 'log',
    status: entry.status || 'info',
    details: entry.details || ''
  };
  data.logs.unshift(newLog);
  saveData(data);
  res.json({ success: true, log: newLog });
});

// users
app.get('/api/users', requireAuth, (req, res) => {
  const data = loadData();
  const users = data.users.map(({ password_hash, mfa_secret, mfa_secret_pending, backup_codes, trusted_devices, ...u }) => u);
  res.json(users);
});

app.post('/api/users', requireAuth, (req, res) => {
  const body = req.body || {};
  if (!body.username || !body.password) return res.status(400).json({ error: 'username and password required' });
  const data = loadData();
  if (data.users.some(u => u.username === body.username)) return res.status(400).json({ error: 'Username exists' });
  const user = {
    id: uuidv4(),
    username: body.username,
    password_hash: bcrypt.hashSync(body.password, 10),
    role: body.role || 'user',
    mfa_enabled: false,
    mfa_secret: null,
    mfa_secret_pending: null,
    backup_codes: [],
    trusted_devices: [],
    created_at: new Date().toISOString()
  };
  data.users.push(user);
  saveData(data);
  res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
});

app.get('/api/schedules', requireAuth, (req, res) => {
  const data = loadData();
  res.json(data.schedules || []);
});

app.post('/api/schedules', requireAuth, (req, res) => {
  const payload = req.body || {};
  if (!payload.action || !['lock', 'unlock'].includes(payload.action)) {
    return res.status(400).json({ error: 'Action must be lock or unlock' });
  }
  if (!payload.time && !Array.isArray(payload.daysOfWeek)) {
    return res.status(400).json({ error: 'Time or weekly schedule required' });
  }
  const data = loadData();
  const scheduleEntry = {
    id: uuidv4(),
    deviceId: payload.deviceId || null,
    action: payload.action,
    time: payload.time || null,
    daysOfWeek: Array.isArray(payload.daysOfWeek) ? payload.daysOfWeek : undefined,
    hour: typeof payload.hour === 'number' ? payload.hour : undefined,
    minute: typeof payload.minute === 'number' ? payload.minute : undefined,
    created_by: req.user.id,
    created_at: new Date().toISOString(),
    lastRun: null
  };
  data.schedules = data.schedules || [];
  data.schedules.push(scheduleEntry);
  saveData(data);
  res.json({ success: true, schedule: scheduleEntry });
});

app.post('/schedules', requireAuth, (req, res) => {
  const payload = req.body || {};
  const data = loadData();
  const scheduleEntry = {
    id: uuidv4(),
    deviceId: payload.deviceId || null,
    action: payload.action || 'lock',
    time: payload.time || null,
    daysOfWeek: Array.isArray(payload.daysOfWeek) ? payload.daysOfWeek : undefined,
    hour: typeof payload.hour === 'number' ? payload.hour : undefined,
    minute: typeof payload.minute === 'number' ? payload.minute : undefined,
    created_by: req.user.id,
    created_at: new Date().toISOString()
  };

  if (!['lock', 'unlock'].includes(scheduleEntry.action)) {
    return res.status(400).json({ error: 'Action must be lock or unlock' });
  }
  if (!scheduleEntry.time && !Array.isArray(scheduleEntry.daysOfWeek)) {
    return res.status(400).json({ error: 'Either time or weekly schedule required' });
  }

  data.schedules = data.schedules || [];
  data.schedules.push(scheduleEntry);
  saveData(data);
  scheduleJob(scheduleEntry);
  pushLog({ userId: req.user.id, action: 'schedule:create', details: `Created schedule ${scheduleEntry.id}` });
  res.json({ success: true, schedule: scheduleEntry });
});

app.delete('/schedules/:id', requireAuth, (req, res) => {
  const data = loadData();
  const before = data.schedules.length;
  data.schedules = data.schedules.filter(s => s.id !== req.params.id);
  if (data.schedules.length === before) {
    return res.status(404).json({ error: 'Schedule not found' });
  }
  saveData(data);
  cancelJob(req.params.id);
  pushLog({ userId: req.user.id, action: 'schedule:delete', details: req.params.id });
  res.json({ success: true });
});

// ===== WiFi Connectivity Endpoints =====
// Lock specific device
app.post("/devices/:id/lock", requireAuth, (req, res) => {
  const id = req.params.id;
  const data = loadData();
  const device = data.devices.find(d => d.id === id);
  if (!device) return res.status(404).json({ error: "Not found" });

  device.status = 'locked';
  saveData(data);

  pushLog({ 
    userId: req.user.id, 
    action: 'device:lock', 
    deviceId: id, 
    details: `Successfully locked ${device.name}` 
  });

  pushNotification('info', `${device.name} has been locked by ${req.user.username}`);

  if (device.ip_address) {
    forwardToDevice(id, "/lock").catch(e => logger.error(`Device Lock Error: ${e.message}`));
  }

  broadcast({ type: 'device_update' });
  res.json({ success: true, status: "locked" });
});

// Unlock specific device
app.post("/devices/:id/unlock", requireAuth, (req, res) => {
  const id = req.params.id;
  const data = loadData();
  const device = data.devices.find(d => d.id === id);
  if (!device) return res.status(404).json({ error: "Not found" });

  device.status = 'unlocked';
  saveData(data);

  pushLog({ 
    userId: req.user.id, 
    action: 'device:unlock', 
    deviceId: id, 
    details: `Successfully unlocked ${device.name}` 
  });

  pushNotification('info', `${device.name} has been unlocked by ${req.user.username}`);

  if (device.ip_address) {
    forwardToDevice(id, "/unlock").catch(e => logger.error(`Device Unlock Error: ${e.message}`));
  }

  broadcast({ type: 'device_update' });
  res.json({ success: true, status: "unlocked" });
});

function onListen(port, protocol = 'http') {
  console.log(`SmartLock API running at ${protocol}://localhost:${port}`);
}

function reportError(err, port) {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use. Please stop the process using port ${port} and restart.`);
    console.error('On Windows: netstat -ano | findstr :' + port);
    console.error('Quick fix: run "taskkill /F /IM node.exe" in your terminal.');
    process.exit(1);
  }
  console.error('Server error', err);
  process.exit(1);
}

function initWS(server) {
  if (!WebSocket) return;
  wss = new WebSocket.Server({ server });
  wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    
    try {
      jwt.verify(token, JWT_SECRET);
      console.log('WS Client connected');
    } catch (e) {
      console.warn('WS Auth failed');
      ws.close();
    }

    ws.on('message', (msg) => { /* handle client messages if needed */ });
  });
}

function startServer(port) {
  const protocol = process.env.USE_HTTPS === "true" ? 'https' : 'http';
  let server;

  function createHttpsServer() {
    const keyPath = process.env.SSL_KEY_PATH || path.join(__dirname, "ssl", "key.pem");
    const certPath = process.env.SSL_CERT_PATH || path.join(__dirname, "ssl", "cert.pem");

    if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
      console.error("HTTPS requested but SSL files missing:", keyPath, certPath);
      process.exit(1);
    }
    server = https.createServer({
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    }, app);
  }

  if (protocol === 'https') {
    createHttpsServer();
  } else {
    server = http.createServer(app);
  }

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${port} is busy, trying port ${port + 1}...`);
      startServer(port + 1);
    } else {
      reportError(err, port);
    }
  });
  server.listen(port, () => {
    onListen(port, protocol);
    initWS(server);
  });
}

// Graceful Shutdown
process.on('SIGINT', () => {
  console.log('Shutting down server...');
  if (wss) wss.close();
  httpAgent.destroy();
  process.exit(0);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

const initialPort = Number(process.env.PORT || 3000);
startServer(initialPort);
