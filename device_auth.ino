#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>

const char* ssid = "YOUR_WIFI";
const char* password = "YOUR_PASSWORD";
const char* apiKey = "DEVICE_SECRET_HEX_KEY"; // Must match DB

void setup() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  // Register with server via HTTPS
}

void handleCommand(String jsonPayload) {
  // 1. Parse IV, Tag, and Content
  // 2. Decrypt using GCM256 with apiKey
  // 3. Verify HMAC signature
  // 4. Check timestamp for replay attacks
  
  GCM<AES256> gcm;
  byte key[32]; // Derived from apiKey
  byte iv[12];
  byte tag[16];
  
  gcm.setKey(key, 32);
  gcm.setIV(iv, 12);
  
  // if (gcm.decrypt(output, input, len)) {
  //   if (gcm.verifyTag(tag, 16)) {
  //     executeLock(command);
  //   }
  // }
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    // Send heartbeat with HMAC signature
    // Check for incoming commands
  }
  delay(5000);
}