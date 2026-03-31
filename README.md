# SmartLock IoT Project

A web-based smart lock control system. Manage and monitor IoT door locks from a browser. The backend is Node.js/Express; the frontend is plain HTML/CSS/JS served from the same server. An ESP8266 Arduino sketch (`esp.ino`) runs on the physical lock hardware.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Available Pages](#available-pages)
4. [Default Credentials](#default-credentials)
5. [Environment Variables](#environment-variables)
6. [Running with HTTPS](#running-with-https)
7. [Hardware Setup (ESP8266)](#hardware-setup-esp8266)
8. [Project Structure](#project-structure)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| [Node.js](https://nodejs.org/) | 18.x LTS or later | Download from nodejs.org |
| npm | 9.x or later | Bundled with Node.js |

Verify your installation:

```bash
node --version   # should print v18.x.x or higher
npm --version    # should print 9.x.x or higher
```

---

## Quick Start

```bash
# 1. Clone the repository (skip if you already have the folder)
git clone https://github.com/tamilramana/SmartLockProjectiot.git
cd SmartLockProjectiot

# 2. Install dependencies
npm install

# 3. Start the server
npm start

# 4. Optional: run API/module smoke checks (in another terminal)
npm run smoke
```

The server starts on **http://localhost:3000** by default.  
Open that URL in your browser — you will be redirected to the login page automatically.
The smoke check should print `All smoke checks passed` when the API and module routes are healthy.

---

## Available Pages

After logging in at `http://localhost:3000`, navigate using the top menu:

| URL | Page | Description |
|---|---|---|
| `/login.html` | Login | Sign in with username & password |
| `/index.html` | Dashboard | Device stats, quick lock/unlock all |
| `/devices.html` | Devices | Add, edit, delete, lock, and unlock individual devices |
| `/notifications.html` | Notifications | View and manage system notifications |
| `/logs.html` | Activity Logs | Full audit trail with search/filter |
| `/schedules.html` | Schedules | Create one-time or weekly recurring lock/unlock schedules |
| `/users.html` | Users *(admin only)* | Add, edit, and delete user accounts |

---

## Default Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `admin` | Administrator |
| `user` | `admin` | Regular user |

> **Security note:** Change these passwords immediately if you expose the server to a network.

---

## Environment Variables

Create a `.env` file in the project root to override any of these (all are optional):

```env
# TCP port the server listens on (default: 3000)
PORT=3000

# Secret key used to sign JWT tokens — CHANGE THIS in any non-demo deployment
JWT_SECRET=supersecret_demo_change_in_prod

# Issuer name shown in authenticator apps for 2FA (default: SmartLock)
MFA_ISSUER=SmartLock

# Comma-separated list of allowed CORS origins (default: all origins)
ALLOWED_ORIGINS=http://localhost:3000,http://192.168.1.100:3000

# Set to "true" to enable HTTPS (requires SSL certificate files below)
USE_HTTPS=false

# Paths to SSL certificate files (only needed when USE_HTTPS=true)
SSL_KEY_PATH=./ssl/key.pem
SSL_CERT_PATH=./ssl/cert.pem
```

Example `.env` for a local demo (nothing needs to change — just start the server):

```bash
npm start
```

---

## Running with HTTPS

1. Generate a self-signed certificate (for local testing):

   ```bash
   mkdir ssl
   openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem \
     -days 365 -nodes -subj "/CN=localhost"
   ```

2. Set environment variables:

   ```env
   USE_HTTPS=true
   SSL_KEY_PATH=./ssl/key.pem
   SSL_CERT_PATH=./ssl/cert.pem
   ```

3. Start the server:

   ```bash
   npm start
   ```

4. Open **https://localhost:3000** (accept the browser certificate warning for self-signed certs).

---

## Hardware Setup (ESP8266)

The file `esp.ino` is the Arduino firmware for the physical lock.

### Requirements
- Arduino IDE 1.8+ or Arduino IDE 2.x
- **Board**: ESP8266 (e.g. NodeMCU, Wemos D1 Mini)
- **Libraries** (install via Arduino Library Manager):
  - `ESP8266WiFi` (bundled with ESP8266 board package)
  - `ESP8266WebServer` (bundled)
  - `ESP8266HTTPClient` (bundled)

### Steps

1. **Install the ESP8266 board package** in Arduino IDE:
   - Go to *File → Preferences → Additional Board Manager URLs* and add:
     ```
     https://arduino.esp8266.com/stable/package_esp8266com_index.json
     ```
   - Go to *Tools → Board → Boards Manager*, search **esp8266**, and install.

2. **Edit `esp.ino`** — update these three lines to match your network:

   ```cpp
   const char* ssid       = "YOUR_WIFI_SSID";
   const char* password   = "YOUR_WIFI_PASSWORD";
   const char* serverHost = "192.168.1.100"; // LAN IP of the PC running npm start
   ```

3. **Wire the relay**: Connect the relay signal pin to `D1` (GPIO 5).

4. **Upload the sketch** to your ESP8266 via Arduino IDE.

5. Open the Arduino Serial Monitor (115200 baud) — the device prints its IP address and a registration confirmation from the server.

The ESP registers itself with the backend automatically. It then appears in the **Devices** page of the web UI.

---

## Project Structure

```
SmartLockProjectiot/
├── server.js              ← Express API server (entry point)
├── security.js            ← 2FA / TOTP / backup code helpers
├── security_middleware.js ← Encryption, HMAC, JWT middleware
├── dataStore.js           ← Data access helpers
├── data.json              ← JSON database (users, devices, logs, etc.)
├── database_schema.sql    ← SQL schema reference (documentation only)
├── package.json           ← Node.js dependencies & scripts
├── .env                   ← (create this) Environment variable overrides
├── esp.ino                ← ESP8266 Arduino firmware for the physical lock
├── device_auth.ino        ← ESP8266 sketch with AES-GCM encrypted comms
├── public/
│   ├── login.html         ← Login page
│   ├── index.html         ← Dashboard
│   ├── devices.html       ← Device management & control
│   ├── notifications.html ← Notifications
│   ├── logs.html          ← Activity logs
│   ├── schedules.html     ← Lock/unlock schedules
│   └── users.html         ← User management (admin only)
└── ssl/                   ← (create this) TLS certificate files for HTTPS
```

---

## Troubleshooting

### `Error: listen EADDRINUSE :::3000`
Port 3000 is already in use. Either:
- Stop the process using port 3000, or
- Start on a different port: `PORT=3001 npm start`

On Windows you can find and kill the process:
```bat
netstat -ano | findstr :3000
taskkill /F /PID <PID>
```

### `Cannot find module '...'`
Dependencies are missing. Run:
```bash
npm install
```

### Browser shows `Cannot GET /`
The server is not running. Make sure `npm start` completed without errors and the terminal shows:
```
SmartLock API running at http://localhost:3000
```

### Login fails with correct credentials
The `data.json` file may be corrupted or the password hashes may be incorrect. Reset the file by restoring it from the repository:
```bash
git checkout data.json
```

### ESP8266 cannot reach the server
- Confirm the PC and ESP8266 are on the **same Wi-Fi network**.
- Find the PC's local IP: `ipconfig` (Windows) or `ip addr` / `ifconfig` (Linux/macOS).
- Update `serverHost` in `esp.ino` with that IP and re-upload the sketch.
- Ensure no firewall is blocking port 3000 on the PC.

