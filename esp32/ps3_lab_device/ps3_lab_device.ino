/*
  PS3 Guardian lab device: the ESP32 of the IoT Pro Kit on the Pi's lab Wi-Fi.

  Every 15 s it sends its sensor readings to the Pi (POST /iot) and gets back the mode that
  the Pi's page asks for. In normal mode it is an ordinary sensor that talks only to the Pi
  and to the time server: that is what the Pi's network monitor learns as its normal.

  The test modes imitate what malware does on a network, so the monitor can be seen catching
  it. They are harmless: look-ups of names that do not exist, and a small web page fetched on
  a timer. Nothing is attacked, and every test stops by itself.
    dga       looks up made-up, random-looking names          -> alert after about 30 s
    phishing  looks up a fake bank-site name                  -> alert at the first look-up
    tunnel    looks up long random sub-names under one name   -> alert after about 2 minutes
    beacon    fetches http://example.com/ every 60 s          -> alert after about 10 minutes, but only
              once the monitor has known this device for 2 hours (it learns its normal first)

  Before uploading (docs/esp32-lab-device.md):
    1. Libraries (Sketch > Include Library > Manage Libraries): "DHT sensor library" by Adafruit
       and "Adafruit BMP085 Library" (it reads the BMP180). Accept the extra libraries they need.
    2. Copy secrets.example.h to secrets.h and fill in the Wi-Fi password and the pairing token.
    3. Set the pins below to the labels on your board.
  Board: "ESP32 Dev Module". Serial Monitor at 115200 baud shows what it does.
*/
#include <WiFi.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <time.h>
#include <DHT.h>
#include <Adafruit_BMP085.h>

#if __has_include("secrets.h")
#include "secrets.h"
#else
#error "Copy secrets.example.h to secrets.h (same folder) and fill in the Wi-Fi password and the pairing token"
#endif

// ---- This device's name: on the Pi page, in alerts, and on the Wi-Fi ----
const char *DEVICE_NAME = "esp32-lab";

// ---- Pins: set them to the labels on your IoT Pro Kit board. -1 = not connected. ----
const int DHT_PIN = 4;              // DHT11/DHT22 data
const uint8_t DHT_TYPE = DHT11;     // DHT22 if yours is the white one
const int TRIG_PIN = 5;             // ultrasonic sensor: trigger
const int ECHO_PIN = 18;            // ultrasonic sensor: echo
const int IR_PIN = 19;              // IR obstacle sensor: output
const bool IR_ACTIVE_LOW = true;    // most IR modules pull their output low when something is in front
const int VR1_PIN = 34;             // VR1 knob (potentiometer): must be GPIO 32-39, see below
const int MQ135_PIN = 35;           // MQ-135 air-quality sensor, analog output: must be GPIO 32-39
const int I2C_SDA = 21;             // BMP180 (I2C)
const int I2C_SCL = 22;
// Analog pins: only GPIO 32-39 (ADC1) can be read while Wi-Fi is on. The others (ADC2) cannot.

const unsigned long REPORT_EVERY_MS = 15000;
const char *FAKE_SITES[] = {"sbi-kyc-update-verify.xyz", "hdfc-netbanking-login.top",
                            "paytm-kyc-verify.online", "icici-netbanking-update.xyz"};
const int NUM_FAKE_SITES = sizeof(FAKE_SITES) / sizeof(FAKE_SITES[0]);
const char *TUNNEL_PARENT = "ps3guardian-dns-test-7q2x.com";  // made up: the look-ups find nothing
const char *BEACON_URL = "http://example.com/";              // IANA's example page, there for tests

DHT dht(DHT_PIN >= 0 ? DHT_PIN : 0, DHT_TYPE);
Adafruit_BMP085 bmp;
bool bmpFound = false;

String mode = "normal";             // the test running now
unsigned long modeStart = 0, modeLength = 0, lastReport = 0, lastStep = 0;
bool reportedYet = false, steppedYet = false;
int fakeSite = -1;

bool isAdc1(int pin) { return pin >= 32 && pin <= 39; }

String randomName(int length, const char *letters) {
  String s;
  size_t n = strlen(letters);
  for (int i = 0; i < length; i++) s += letters[random((long)n)];   // random() uses the ESP32's hardware RNG
  return s;
}

// The value after "key": in the Pi's short answer, e.g. {"mode":"dga","seconds_left":300}
String jsonValue(const String &json, const char *key) {
  String k = String("\"") + key + "\":";
  int i = json.indexOf(k);
  if (i < 0) return "";
  i += k.length();
  while (i < (int)json.length() && json[i] == ' ') i++;
  if (i < (int)json.length() && json[i] == '"') {
    int end = json.indexOf('"', i + 1);
    return end < 0 ? String("") : json.substring(i + 1, end);
  }
  int end = i;
  while (end < (int)json.length() && (isDigit(json[end]) || json[end] == '-' || json[end] == '.')) end++;
  return json.substring(i, end);
}

float distanceCm() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  unsigned long us = pulseIn(ECHO_PIN, HIGH, 30000UL);   // no echo within 30 ms (about 5 m): nothing
  return us ? (float)us * 0.0343f / 2 : NAN;
}

void addReading(String &json, const char *name, float value, int decimals) {
  if (isnan(value)) return;                               // a sensor that did not answer is left out
  if (json.length() > 1) json += ",";
  json += "\"";
  json += name;
  json += "\":";
  json += String(value, decimals);
}

String readings() {
  String j = "{";
  if (DHT_PIN >= 0) {
    addReading(j, "temp_c", dht.readTemperature(), 1);
    addReading(j, "humidity", dht.readHumidity(), 0);
  }
  if (bmpFound) {
    addReading(j, "bmp_temp_c", bmp.readTemperature(), 1);
    addReading(j, "pressure_hpa", (float)bmp.readPressure() / 100.0f, 1);
  }
  if (TRIG_PIN >= 0 && ECHO_PIN >= 0) addReading(j, "distance_cm", distanceCm(), 1);
  if (IR_PIN >= 0) addReading(j, "obstacle", digitalRead(IR_PIN) == (IR_ACTIVE_LOW ? LOW : HIGH) ? 1 : 0, 0);
  if (isAdc1(VR1_PIN)) addReading(j, "knob", analogRead(VR1_PIN), 0);
  if (isAdc1(MQ135_PIN)) addReading(j, "air_raw", analogRead(MQ135_PIN), 0);
  addReading(j, "rssi", WiFi.RSSI(), 0);
  addReading(j, "uptime_s", (float)(millis() / 1000), 0);
  addReading(j, "heap_kb", (float)(ESP.getFreeHeap() / 1024), 0);
  return j + "}";
}

void startMode(const String &wanted, long seconds) {
  if (wanted == "normal") {
    Serial.println("Test stopped: back to normal");
    mode = "normal";
    return;
  }
  if (wanted != "dga" && wanted != "phishing" && wanted != "tunnel" && wanted != "beacon") return;
  mode = wanted;
  modeStart = millis();
  modeLength = (unsigned long)constrain(seconds, 30L, 1800L) * 1000UL;  // the Pi decides; 30 min at most
  steppedYet = false;
  if (mode == "phishing") fakeSite = (fakeSite + 1) % NUM_FAKE_SITES;
  Serial.printf("Test started: %s for %ld s (harmless: nothing is attacked)\n", mode.c_str(), seconds);
}

void report() {
  String body = String("{\"device\":\"") + DEVICE_NAME + "\",\"mode\":\"" + mode + "\",\"readings\":" + readings() + "}";
  HTTPClient http;
  http.setTimeout(5000);
  if (!http.begin(String(PI_URL) + "/iot")) {
    Serial.println("PI_URL in secrets.h is not a valid address");
    return;
  }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Guardian-Token", PI_TOKEN);
  int code = http.POST(body);
  String answer = code > 0 ? http.getString() : String("");
  http.end();
  if (code == 401) {
    Serial.println("The Pi refused the pairing token: check PI_TOKEN in secrets.h");
    return;
  }
  if (code != 200) {
    Serial.printf("Report not accepted: %s\n", code > 0 ? String(code).c_str() : HTTPClient::errorToString(code).c_str());
    return;
  }
  if (!reportedYet) {
    Serial.println("Reporting to the Pi every 15 s, for example: " + body);
    reportedYet = true;
  }
  String wanted = jsonValue(answer, "mode");
  long seconds = jsonValue(answer, "seconds_left").toInt();
  if (wanted.length() && wanted != mode) startMode(wanted, seconds);
}

unsigned long stepEvery() {
  if (mode == "dga") return 6000;
  if (mode == "phishing") return 30000;
  if (mode == "tunnel") return 4000;
  return 60000;                                           // beacon
}

void step() {
  if (mode == "beacon") {
    HTTPClient http;
    http.setReuse(false);                                 // a new connection each time, like a check-in
    http.setTimeout(5000);
    http.begin(BEACON_URL);
    int code = http.GET();
    http.end();
    Serial.printf("[test] checked in with example.com (HTTP %d)\n", code);
    return;
  }
  String name;
  if (mode == "dga") {
    name = randomName(12 + (int)random(5), "bcdfghjklmnpqrstvwxz") + ".com";
  } else if (mode == "phishing") {
    name = FAKE_SITES[fakeSite < 0 ? 0 : fakeSite];
  } else {
    name = randomName(30, "abcdefghijklmnopqrstuvwxyz234567") + "." + TUNNEL_PARENT;
  }
  IPAddress ip;
  bool found = WiFi.hostByName(name.c_str(), ip) == 1;
  Serial.printf("[test] looked up %s: %s\n", name.c_str(), found ? ip.toString().c_str() : "no such name");
}

void joinWifi() {
  Serial.printf("Joining the Wi-Fi %s ...\n", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  for (int i = 0; i < 40 && WiFi.status() != WL_CONNECTED; i++) delay(500);
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("On %s as %s, signal %d dBm\n", WIFI_SSID, WiFi.localIP().toString().c_str(), WiFi.RSSI());
  } else {
    Serial.println("Not on the Wi-Fi yet: check WIFI_PASS in secrets.h and that the Pi's hotspot is on. Retrying.");
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println();
  Serial.println("PS3 Guardian lab device");
  if (TRIG_PIN >= 0) {
    pinMode(TRIG_PIN, OUTPUT);
    digitalWrite(TRIG_PIN, LOW);
  }
  if (ECHO_PIN >= 0) pinMode(ECHO_PIN, INPUT);
  if (IR_PIN >= 0) pinMode(IR_PIN, INPUT);
  if (DHT_PIN >= 0) dht.begin();
  Wire.begin(I2C_SDA, I2C_SCL);
  bmpFound = bmp.begin();
  Serial.println(bmpFound ? "BMP180: found" : "BMP180: not found (check I2C_SDA and I2C_SCL)");
  if (VR1_PIN >= 0 && !isAdc1(VR1_PIN)) Serial.println("VR1_PIN is not GPIO 32-39: it cannot be read while Wi-Fi is on");
  if (MQ135_PIN >= 0 && !isAdc1(MQ135_PIN)) Serial.println("MQ135_PIN is not GPIO 32-39: it cannot be read while Wi-Fi is on");
  WiFi.setHostname(DEVICE_NAME);                          // the name the Pi shows in alerts
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  joinWifi();
  configTime(19800, 0, "pool.ntp.org");                   // India time (UTC+5:30)
}

bool firstLoop = true;

void loop() {
  unsigned long now = millis();
  bool online = WiFi.status() == WL_CONNECTED;
  if (firstLoop || now - lastReport >= REPORT_EVERY_MS) {
    firstLoop = false;
    lastReport = now;
    if (online) {
      report();
    } else {
      Serial.println("Waiting for the Wi-Fi ...");
    }
  }
  if (mode != "normal") {
    if (now - modeStart >= modeLength) {
      Serial.println("Test over: back to normal");
      mode = "normal";
    } else if (online && (!steppedYet || now - lastStep >= stepEvery())) {
      lastStep = now;
      steppedYet = true;
      step();
    }
  }
  delay(20);
}
