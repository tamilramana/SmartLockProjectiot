// ═══════════════════════════════════════════════════════════════════════
//  SmartLock – ESP8266 Firmware  (esp.ino)
//
//  Features:
//    • Registers itself with the Node.js server on every boot
//    • Receives its API key from the server after registration
//    • Validates the API key on every /lock and /unlock request
//    • Sends a heartbeat to the server every 30 s (updates IP + status)
//    • Reports each lock/unlock event back to the server's audit log
//    • Reports status via GET /status
//
//  ── HOW TO CONFIGURE ────────────────────────────────────────────────
//  1. Set WIFI_SSID and WIFI_PASSWORD below.
//  2. Set SERVER_HOST to the LAN IP of the machine running server.js.
//  3. Flash to your ESP8266 board.
//  4. The board will register with the server on first boot and store
//     the returned API key in memory (used for all future requests).
// ═══════════════════════════════════════════════════════════════════════

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>

// ── User Configuration ───────────────────────────────────────────────
// Change these values before flashing. Do NOT commit real credentials.
#define WIFI_SSID       "YOUR_WIFI_SSID"
#define WIFI_PASSWORD   "YOUR_WIFI_PASSWORD"

// LAN IP address of the machine running server.js
#define SERVER_HOST     "192.168.1.100"
#define SERVER_PORT     3000

// Heartbeat interval (milliseconds)
#define HEARTBEAT_MS    30000UL
// ─────────────────────────────────────────────────────────────────────

#define RELAY_PIN D1   // HIGH = locked (relay OFF), LOW = unlocked (relay ON)

ESP8266WebServer httpServer(80);
WiFiClient       wifiClient;

// API key received from the server after registration.
// An empty key means the device has not yet registered or is in dev mode
// (all requests accepted).
String deviceApiKey = "";

unsigned long lastHeartbeat = 0;

// ── helpers ───────────────────────────────────────────────────────────

// Return true when the incoming request carries a valid API key.
// The key is read from the ?apiKey= query parameter first, then from the
// X-API-Key header, so the server can choose either approach.
bool isAuthorized() {
  if (deviceApiKey.length() == 0) return true;  // dev mode – no key set yet
  String key = httpServer.arg("apiKey");
  if (key.length() == 0) key = httpServer.header("X-API-Key");
  return key == deviceApiKey;
}

// ── HTTP route handlers ───────────────────────────────────────────────

void handleLock() {
  if (!isAuthorized()) {
    httpServer.send(403, "text/plain", "Forbidden: invalid API key");
    Serial.println("[WARN] Unauthorized /lock attempt");
    return;
  }
  digitalWrite(RELAY_PIN, HIGH);   // Relay OFF → door locked
  httpServer.send(200, "text/plain", "Locked");
  Serial.println("[INFO] Door Locked");
  sendDeviceLog("lock", "success");
}

void handleUnlock() {
  if (!isAuthorized()) {
    httpServer.send(403, "text/plain", "Forbidden: invalid API key");
    Serial.println("[WARN] Unauthorized /unlock attempt");
    return;
  }
  digitalWrite(RELAY_PIN, LOW);    // Relay ON → door unlocked
  httpServer.send(200, "text/plain", "Unlocked");
  Serial.println("[INFO] Door Unlocked");
  sendDeviceLog("unlock", "success");
}

void handleStatus() {
  bool locked = (digitalRead(RELAY_PIN) == HIGH);
  String body = "{\"status\":\"" + String(locked ? "locked" : "unlocked") +
                "\",\"ip\":\"" + WiFi.localIP().toString() + "\"}";
  httpServer.send(200, "application/json", body);
}

// ── Server communication ──────────────────────────────────────────────

// Register this device with the backend.  Called once on boot.
// On success the server returns a JSON object containing "apiKey".
void registerDevice() {
  String deviceId = String(ESP.getChipId());
  String url = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/device/register";
  String payload = "{\"deviceId\":\"" + deviceId +
                   "\",\"ipAddress\":\"" + WiFi.localIP().toString() +
                   "\",\"name\":\"ESP-" + deviceId + "\"}";

  HTTPClient http;
  http.begin(wifiClient, url);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(payload);

  if (code == 200 || code == 201) {
    String resp = http.getString();
    Serial.println("[INFO] Registered: " + resp);

    // Parse the apiKey field from the JSON response
    // e.g. {"success":true,"deviceId":"...","apiKey":"abc123..."}
    int idx = resp.indexOf("\"apiKey\":\"");
    if (idx >= 0) {
      int start = idx + 10;
      int end   = resp.indexOf("\"", start);
      if (end > start) {
        deviceApiKey = resp.substring(start, end);
        Serial.println("[INFO] API key stored");
      }
    }
  } else {
    Serial.printf("[ERROR] Registration failed (HTTP %d). Retrying in 10s...\n", code);
    delay(10000);
    registerDevice();
  }
  http.end();
}

// Send a periodic heartbeat so the server can update our IP and status.
void sendHeartbeat() {
  if (deviceApiKey.length() == 0) return;  // not registered yet

  String deviceId = String(ESP.getChipId());
  String url = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/device/heartbeat";
  String payload = "{\"deviceId\":\"" + deviceId +
                   "\",\"ipAddress\":\"" + WiFi.localIP().toString() +
                   "\",\"apiKey\":\"" + deviceApiKey + "\"}";

  HTTPClient http;
  http.begin(wifiClient, url);
  http.addHeader("Content-Type", "application/json");
  int code = http.POST(payload);
  Serial.printf("[INFO] Heartbeat: HTTP %d\n", code);
  http.end();
}

// Log a lock/unlock event back to the server's audit log.
void sendDeviceLog(String action, String status) {
  if (deviceApiKey.length() == 0) return;

  String deviceId = String(ESP.getChipId());
  String url = "http://" + String(SERVER_HOST) + ":" + String(SERVER_PORT) + "/device/log";
  String payload = "{\"deviceId\":\"" + deviceId +
                   "\",\"action\":\"" + action +
                   "\",\"status\":\"" + status +
                   "\",\"apiKey\":\"" + deviceApiKey + "\"}";

  HTTPClient http;
  http.begin(wifiClient, url);
  http.addHeader("Content-Type", "application/json");
  http.POST(payload);
  http.end();
}

// ── Arduino entry points ──────────────────────────────────────────────

void setup() {
  Serial.begin(115200);

  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, HIGH);  // Start locked

  Serial.println("[INFO] Connecting to WiFi...");
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("[INFO] WiFi connected. IP: ");
  Serial.println(WiFi.localIP());

  // Register with the backend and fetch our API key
  registerDevice();

  // Register HTTP routes
  httpServer.on("/lock",   handleLock);
  httpServer.on("/unlock", handleUnlock);
  httpServer.on("/status", handleStatus);

  httpServer.begin();
  Serial.println("[INFO] HTTP server started");
}

void loop() {
  httpServer.handleClient();

  // Periodic heartbeat
  if (millis() - lastHeartbeat >= HEARTBEAT_MS) {
    lastHeartbeat = millis();
    if (WiFi.status() == WL_CONNECTED) {
      sendHeartbeat();
    } else {
      Serial.println("[WARN] WiFi disconnected, reconnecting...");
      WiFi.reconnect();
    }
  }
}

