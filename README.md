# SmartLock – IoT Lock System

A Node.js backend + ESP8266 firmware for a WiFi-connected smart lock with a web dashboard.

---

## Repository Layout

```
SmartLockProjectiot/
├── server.js            # Node.js API server (Express)
├── security.js          # MFA / TOTP / backup-code helpers
├── security_middleware.js  # AES, HMAC, RBAC, logging utilities
├── dataStore.js         # Atomic JSON data persistence helpers
├── data.json            # Runtime data store (auto-created)
├── database_schema.sql  # Reference SQL schema (for future SQLite migration)
├── esp.ino              # ESP8266 firmware (Arduino sketch)
├── device_auth.ino      # ESP security documentation & configuration reference
├── .env.example         # Environment variable template
├── package.json
└── README.md
```

---

## Quick Start – Server

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env and change JWT_SECRET and MASTER_KEY to random values
```

### 3. Start the server
```bash
npm start
```
The API listens on **http://localhost:3000** by default (change `PORT` in `.env`).

### Default credentials
| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin    | admin |
| user     | admin    | user  |

> ⚠️  Change these passwords immediately after first login.

---

## Quick Start – ESP8266 Firmware

### 1. Open `esp.ino` in Arduino IDE

### 2. Edit the configuration at the top of the file
```cpp
#define WIFI_SSID       "your_network_name"
#define WIFI_PASSWORD   "your_wifi_password"
#define SERVER_HOST     "192.168.x.x"   // LAN IP of the server machine
#define SERVER_PORT     3000
```

### 3. Flash to your ESP8266

On first boot the device will:
1. Connect to WiFi
2. Call `POST /device/register` → receive a unique API key from the server
3. Start serving `/lock`, `/unlock`, and `/status` on port 80
4. Send a heartbeat to the server every 30 seconds

---

## Security Architecture

```
User Browser
    │  HTTPS (JWT Bearer token)
    ▼
Node.js Server (server.js)
    │  Auth + RBAC + Audit Logs
    │  GET /lock?apiKey=<device-key>
    ▼
ESP8266 (esp.ino)
    │  API key validated per request
    ▼
Relay → Physical Lock
```

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Password storage | bcrypt (10 rounds) | Never store plain passwords |
| User auth | JWT (1 h expiry) | Stateless, no session hijacking |
| Brute-force protection | 5-attempt lockout (15 min) | Stop password attacks |
| Device auth | Per-device API key | Only the server controls the lock |
| Role-based access | admin / user roles | Limit who can do what |
| Multi-factor auth | TOTP (RFC 6238) | Second factor via authenticator app |
| Audit logging | HMAC-signed entries | Tamper-evident event history |
| Transport | HTTPS (optional, see `.env`) | Encrypt data in transit |

---

## API Reference

### Public endpoints (no token required)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/login` | Login → returns JWT |
| POST | `/device/register` | ESP self-registration |
| POST | `/device/heartbeat` | ESP keep-alive (API key in body) |
| POST | `/device/log` | ESP audit log (API key in body) |

### Authenticated endpoints (Bearer JWT required)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/devices` | List all devices |
| POST | `/devices` | Add a device |
| POST | `/devices/:id/lock` | Lock a specific device |
| POST | `/devices/:id/unlock` | Unlock a specific device |
| GET | `/logs` | Audit log |
| GET | `/notifications` | Notifications |
| GET | `/users` | List users (admin) |
| POST | `/mfa/setup` | Begin MFA setup |
| POST | `/mfa/enable` | Confirm and activate MFA |

---

## Environment Variables

See `.env.example` for the full list.  The most important ones:

| Variable | Description |
|----------|-------------|
| `JWT_SECRET` | Secret used to sign JWTs — **must be changed in production** |
| `MASTER_KEY` | 32-char key for AES/HMAC operations — **must be changed in production** |
| `PORT` | Server port (default: 3000) |
| `USE_HTTPS` | Set to `true` to enable TLS (requires SSL certs) |

