#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>

const char* ssid = "vivo Y29 5G";
const char* password = "ramana@123";

// set this to the machine IP running server.js (update to your PC's LAN IP)
const char* serverHost = "192.168.1.100";
const int serverPort = 3000;

#define RELAY_PIN D1

ESP8266WebServer server(80);

void setup() {
  Serial.begin(115200);

  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, HIGH);

  Serial.println("Connecting to WiFi...");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nConnected to WiFi");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());

  // register device with backend so web UI can forward commands to this ESP
  {
    HTTPClient http;
    String deviceId = String(ESP.getChipId());
    String url = String("http://") + serverHost + ":" + String(serverPort) + "/device/register";
    String payload = String("{\"deviceId\":\"") + deviceId + String("\",\"ipAddress\":\"") + WiFi.localIP().toString() + String("\",\"name\":\"ESP-") + deviceId + String("\"}");

    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    int httpCode = http.POST(payload);
    if (httpCode > 0) {
      Serial.printf("Device register HTTP code: %d\n", httpCode);
      String resp = http.getString();
      Serial.println(resp);
    } else {
      Serial.printf("Device register failed, error: %s\n", http.errorToString(httpCode).c_str());
    }
    http.end();
  }

  server.on("/lock", []() {
    digitalWrite(RELAY_PIN, HIGH);
    server.send(200, "text/plain", "Door Locked");
    Serial.println("Door Locked");
  });

  server.on("/unlock", []() {
    digitalWrite(RELAY_PIN, LOW);
    server.send(200, "text/plain", "Door Unlocked");
    Serial.println("Door Unlocked");
  });

  server.begin();
  Serial.println("Server Started");
}

void loop() {
  server.handleClient();
}
