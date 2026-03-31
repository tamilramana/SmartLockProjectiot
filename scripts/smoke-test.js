const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
const username = process.env.SMOKE_USER || 'admin';
const password = process.env.SMOKE_PASS || 'admin';

function log(step, message) {
  console.log(`[${step}] ${message}`);
}

async function requestJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch (err) {
    body = text;
  }
  return { res, body };
}

function assertOk(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function buildAuthHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json'
  };
}

function loadSampleDeviceCredentials() {
  const dataPath = path.join(process.cwd(), 'data.json');
  if (!fs.existsSync(dataPath)) return null;
  const raw = fs.readFileSync(dataPath, 'utf8');
  const data = JSON.parse(raw);
  const devices = Array.isArray(data.devices) ? data.devices : [];
  const withApiKey = devices.find((d) => d && (d.deviceId || d.device_id) && d.api_key);
  if (!withApiKey) return null;
  return {
    deviceId: withApiKey.deviceId || withApiKey.device_id,
    apiKey: withApiKey.api_key
  };
}

async function main() {
  log('START', `Running smoke test against ${baseUrl}`);

  const health = await requestJson(`${baseUrl}/health`);
  assertOk(health.res.ok, `Health check failed: ${health.res.status}`);
  assertOk(health.body && health.body.status === 'ok', 'Health response is invalid');
  log('PASS', 'Health endpoint');

  const login = await requestJson(`${baseUrl}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  assertOk(login.res.ok, `Login failed: ${login.res.status}`);
  assertOk(login.body && login.body.token, 'Login did not return a token');
  const token = login.body.token;
  log('PASS', 'Login endpoint');

  const headers = buildAuthHeaders(token);

  const coreEndpoints = [
    '/devices',
    '/api/devices',
    '/notifications',
    '/logs',
    '/schedules',
    '/api/schedules'
  ];

  for (const endpoint of coreEndpoints) {
    const result = await requestJson(`${baseUrl}${endpoint}`, { headers });
    assertOk(result.res.ok, `${endpoint} failed: ${result.res.status}`);
    assertOk(Array.isArray(result.body), `${endpoint} did not return an array`);
    log('PASS', `GET ${endpoint}`);
  }

  const deviceCreds = loadSampleDeviceCredentials();
  if (!deviceCreds) {
    log('WARN', 'Skipping device-auth endpoints (no sample device with api_key in data.json)');
    log('DONE', 'Smoke test passed with warnings');
    return;
  }

  const timestamp = Date.now().toString();
  const signature = crypto
    .createHmac('sha256', deviceCreds.apiKey)
    .update(JSON.stringify({ deviceId: deviceCreds.deviceId, timestamp }))
    .digest('hex');

  const deviceAuth = await requestJson(`${baseUrl}/device/authenticate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceId: deviceCreds.deviceId,
      apiKey: deviceCreds.apiKey,
      signature,
      timestamp
    })
  });
  assertOk(deviceAuth.res.ok, `/device/authenticate failed: ${deviceAuth.res.status}`);
  log('PASS', 'POST /device/authenticate');

  const deviceStatus = await requestJson(`${baseUrl}/device/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceId: deviceCreds.deviceId,
      apiKey: deviceCreds.apiKey,
      status: 'locked',
      batteryLevel: 95,
      signal: -60,
      timestamp: Date.now()
    })
  });
  assertOk(deviceStatus.res.ok, `/device/status failed: ${deviceStatus.res.status}`);
  log('PASS', 'POST /device/status');

  const deviceCommands = await requestJson(`${baseUrl}/device/commands`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      deviceId: deviceCreds.deviceId,
      apiKey: deviceCreds.apiKey
    })
  });
  assertOk(deviceCommands.res.ok, `/device/commands failed: ${deviceCommands.res.status}`);
  assertOk(deviceCommands.body && Array.isArray(deviceCommands.body.commands), '/device/commands response shape is invalid');
  log('PASS', 'POST /device/commands');

  log('DONE', 'All smoke checks passed');
}

main().catch((err) => {
  console.error(`[FAIL] ${err.message}`);
  process.exit(1);
});
