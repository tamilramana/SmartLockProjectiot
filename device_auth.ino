// ═══════════════════════════════════════════════════════════════════════
//  SmartLock – ESP8266 Security Configuration  (device_auth.ino)
//
//  This file documents every security mechanism used by the ESP firmware
//  and explains how each one maps to the server-side logic in server.js.
//
//  ── SECURITY LAYERS ─────────────────────────────────────────────────
//
//  1. API Key Authentication
//     Every /lock and /unlock request is validated against the API key
//     that was issued by the server at registration time.
//     The key is passed as:
//       • Query param: GET /lock?apiKey=<key>   (sent by server.js)
//       • Header:      X-API-Key: <key>          (alternative)
//     An attacker on the same LAN cannot control the lock without the key.
//
//  2. Device Registration with Key Issuance
//     On first boot the ESP calls POST /device/register.
//     The server generates a cryptographically random 32-byte (256-bit)
//     API key and returns it to the device.  The key is stored in the
//     device's RAM and used for all subsequent requests.
//     Each device gets a unique key stored in data.json.
//
//  3. Heartbeat & Online Status
//     The ESP calls POST /device/heartbeat every 30 s.
//     This lets the server detect when a device goes offline (no heartbeat
//     for >60 s) and keeps the displayed IP address current if DHCP
//     assigns a new address.
//
//  4. Audit Logging
//     After every lock/unlock the ESP calls POST /device/log.
//     This creates a tamper-evident HMAC-signed log entry on the server
//     so administrators can see exactly when the physical lock was
//     operated and by what mechanism.
//
//  5. Relay Wiring (physical security)
//     RELAY_PIN = D1 (GPIO5)
//     HIGH (relay OFF)  → door LOCKED   (secure default on boot/power loss)
//     LOW  (relay ON)   → door UNLOCKED
//     The relay defaults to HIGH so the lock engages if power is cut.
//
//  ── SERVER-SIDE COUNTERPARTS ────────────────────────────────────────
//
//  Route                  Auth             Purpose
//  ─────────────────────  ───────────────  ──────────────────────────────
//  POST /device/register  none             ESP self-registers, gets key
//  POST /device/heartbeat device API key   Keep-alive / IP refresh
//  POST /device/log       device API key   Audit log from hardware
//  GET  /devices/:id/lock JWT (user)        User triggers lock via dashboard
//  GET  /devices/:id/unlock JWT (user)     User triggers unlock via dashboard
//
//  The dashboard lock/unlock routes authenticate the *user* with a JWT,
//  then the server authenticates *itself to the ESP* with the device's
//  API key when forwarding the command.
//
// ═══════════════════════════════════════════════════════════════════════

// ── Security constants (mirrored from esp.ino for reference) ─────────
// Keep this in sync with the #define values at the top of esp.ino.

// WiFi network the ESP connects to
// #define WIFI_SSID      "YOUR_WIFI_SSID"
// #define WIFI_PASSWORD  "YOUR_WIFI_PASSWORD"

// Node.js server address
// #define SERVER_HOST    "192.168.1.100"
// #define SERVER_PORT    3000

// Heartbeat interval
// #define HEARTBEAT_MS   30000UL

// Relay pin
// #define RELAY_PIN D1

// ── AES / HMAC note ─────────────────────────────────────────────────
// For higher security in production you can extend the firmware to verify
// an HMAC-SHA256 signature on every command, preventing replay attacks.
// The server already generates HMAC-signed log entries (see MASTER_KEY in
// security_middleware.js).  The pattern for command signing would be:
//
//   Server side (security_middleware.js):
//     generateHMAC(`${action}:${timestamp}:${nonce}`, MASTER_KEY)
//
//   ESP side (Arduino Crypto library):
//     SHA256HMAC hmac(key, keyLen);
//     hmac.update(message, msgLen);
//     hmac.finalize(digest, digestLen);
//     if (memcmp(digest, receivedDigest, digestLen) == 0) { /* proceed */ }
//
// This file intentionally contains no executable code – all firmware
// logic lives in esp.ino.
