const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const DEVICE_ID = process.env.DEVICE_ID || 'front-door';

// Read the API Key directly from data.json if not set via environment variable
let API_KEY = process.env.API_KEY || '';
let DEVICE_PORT = process.env.PORT || 8080;

if (!API_KEY) {
  try {
    const dataPath = path.join(__dirname, '..', 'data.json');
    const data = JSON.parse(fs.readFileSync(dataPath, 'utf8'));
    const device = data.devices.find(d => 
        d.id === DEVICE_ID || d.deviceId === DEVICE_ID || d.device_id === DEVICE_ID
    );
    if (device) {
        API_KEY = device.api_key;
        if (device.ip_address && device.ip_address.includes(':')) {
            DEVICE_PORT = parseInt(device.ip_address.split(':')[1], 10);
        }
    }
  } catch (e) {
    console.log("Warning: Could not read data.json to auto-fetch API key.");
  }
}

if (!API_KEY) {
  console.error("❌ Could not find API_KEY for device", DEVICE_ID);
  console.error("Please provide it via API_KEY environment variable.");
  process.exit(1);
}

let isLocked = true;

// Utility to calculate HMAC-SHA256
function calculateHMAC(payloadStr) {
    return crypto.createHmac('sha256', API_KEY).update(payloadStr).digest('hex');
}

// Function to simulate Arduino delay
const delay = ms => new Promise(res => setTimeout(res, ms));

async function runVirtualDevice() {
    console.log(`\n======================================================`);
    console.log(`🤖 STARTING VIRTUAL IOT DEVICE [${DEVICE_ID}]`);
    console.log(`📡 Connecting to: ${BASE_URL}`);
    console.log(`🔑 API Key Loaded: ${API_KEY.slice(0, 5)}...${API_KEY.slice(-5)}`);
    console.log(`🔌 Listening for Push on Port: ${DEVICE_PORT}`);
    console.log(`======================================================\n`);
    
    // Create HTTP Push Server
    const server = http.createServer((req, res) => {
        if (req.method === 'POST' && req.url === '/api/command') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    // decrypt logic inside virtual device, but for simplicity we rely on the action payload 
                    // Server.js wraps it in AES-256-GCM. We can extract action directly from the log for our simulation
                    // Wait, server decrypts it. For our simulation, we just toggle isLocked!
                    
                    if (body.includes('action":"lock')) {
                        isLocked = true;
                        console.log(`\n📥 [PUSH] Lock command received. [${DEVICE_ID}] Door is now LOCKED. 🔒`);
                    } else if (body.includes('action":"unlock')) {
                        isLocked = false;
                        console.log(`\n📥 [PUSH] Unlock command received. [${DEVICE_ID}] Door is now UNLOCKED. 🔓`);
                    }
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ status: 200 }));
                } catch(e) {
                    res.writeHead(500);
                    res.end();
                }
            });
        } else {
            res.writeHead(404);
            res.end();
        }
    });
    server.listen(DEVICE_PORT, () => console.log(`✅ [HTTP] Started push listener on :${DEVICE_PORT}`));

    // 1. Authentication (Mimics device_secure.ino authenticateWithServer)
    const timestamp = Date.now().toString();
    const authPayload = { deviceId: DEVICE_ID, timestamp };
    const authSignature = calculateHMAC(JSON.stringify(authPayload));
    
    try {
        const authRes = await fetch(`${BASE_URL}/device/authenticate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                deviceId: DEVICE_ID,
                apiKey: API_KEY, // Backend backwards compatibility
                timestamp,
                signature: authSignature
            })
        });
        
        if (!authRes.ok) {
            console.error(`❌ [AUTH] Failed to authenticate with backend! Status: ${authRes.status}`);
            const errorMsg = await authRes.text();
            console.error(`Response: ${errorMsg}`);
            return;
        } else {
            console.log("✅ [AUTH] Authenticated successfully with backend.");
        }
    } catch(e) {
        console.error(`❌ [AUTH] Connection Error: ${e.message}`);
        console.log("Make sure the backend is running (npm start).");
        return;
    }

    // 2. Start Polling Loop (Status: 30s, Commands: 5s)
    let loopCount = 0;
    
    // Status reporting every 30 seconds
    setInterval(async () => {
        try {
            const statusReq = await fetch(`${BASE_URL}/device/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    deviceId: DEVICE_ID,
                    apiKey: API_KEY,
                    status: isLocked ? 'locked' : 'unlocked',
                    batteryLevel: 100,
                    signal: -50,
                    timestamp: Date.now()
                })
            });
            if (statusReq.ok) console.log(`👉 [POLL][STATUS] Device status (${isLocked ? 'locked' : 'unlocked'}) reported.`);
            else console.log(`⚠️ [POLL][STATUS] Failed to report status. Status: ${statusReq.status}`);
        } catch(e) {
            console.error(`⚠️ [POLL][STATUS] Request failed: ${e.message}`);
        }
    }, 30000);

    // Command checking every 5 seconds
    setInterval(async () => {
        loopCount++;
        if (loopCount % 6 === 0) {
            process.stdout.write("."); // heartbeat indicator
        }

        try {
            const cmdRes = await fetch(`${BASE_URL}/device/commands`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    deviceId: DEVICE_ID,
                    apiKey: API_KEY
                })
            });
            
            if (cmdRes.ok) {
                const data = await cmdRes.json();
                if (data.commands && data.commands.length > 0) {
                    console.log(`\n📥 [COMMAND] Received ${data.commands.length} command(s) from server!`);
                    
                    for (const cmd of data.commands) {
                        console.log(`⚙️ Executing command: ${cmd.action}`);
                        
                        // Execute command
                        if (cmd.action === 'lock') {
                            isLocked = true;
                            console.log(`🔒 [${DEVICE_ID}] is now LOCKED.`);
                        } else if (cmd.action === 'unlock') {
                            isLocked = false;
                            console.log(`🔓 [${DEVICE_ID}] is now UNLOCKED.`);
                        }

                        // Simulate mechanical delay
                        await delay(500);
                        
                        // Report Back (Action Report)
                        const reportPayload = {
                            deviceId: DEVICE_ID,
                            apiKey: API_KEY,
                            action: cmd.action,
                            actionTimestamp: Date.now(),
                            success: true
                        };
                        const reportSig = calculateHMAC(JSON.stringify(reportPayload));
                        reportPayload.signature = reportSig;
                        
                        await fetch(`${BASE_URL}/device/action-report`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(reportPayload)
                        });
                        console.log(`✅ [ACTION-REPORT] Confirmed ${cmd.action} execution to backend.`);
                    }
                }
            }
        } catch(e) {
            // suppress connection refuse on polling to avoid spamming logs if server restarts
        }
    }, 5000);
    
    console.log("⏱️ [POLLING] Started auto-polling for commands (5s) and status (30s)...");
}

runVirtualDevice();
