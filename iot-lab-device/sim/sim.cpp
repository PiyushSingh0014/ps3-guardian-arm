// Runs the sketch's setup() and loop() on a simulated clock, on a PC: home-hub/tests/test_esp32_sketch.py
// builds it with the sketch included as sketch_body.inc. The fake Pi asks for one test (argv[1])
// at the first report and counts its time down, like app/lab_devices.py.
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include "Arduino.h"
#include "WiFi.h"
#include "HTTPClient.h"
#include "Wire.h"
#include "DHT.h"
#include "Adafruit_BMP085.h"

static unsigned long g_ms = 0;
static const char *g_test = "dga";
static unsigned long g_test_until = 0;      // ms; 0 = no test asked
static int g_lookups = 0, g_checkins = 0, g_reports = 0;

// --- Arduino core stand-ins with behaviour ---
void pinMode(uint8_t, uint8_t) {}
void digitalWrite(uint8_t, uint8_t) {}
int digitalRead(uint8_t) { return 1; }
uint16_t analogRead(uint8_t) { return 1234; }
void delay(uint32_t ms) { g_ms += ms; }
void delayMicroseconds(uint32_t) {}
unsigned long millis() { return g_ms; }
unsigned long pulseIn(uint8_t, uint8_t, unsigned long) { return 0; }
long random(long n) { return n > 0 ? rand() % n : 0; }
long random(long a, long b) { return a + random(b - a); }
extern "C" void configTime(long, int, const char *, const char *, const char *) {}
String::String(int v, unsigned char) : s(std::to_string(v)) {}
String::String(unsigned int v, unsigned char) : s(std::to_string(v)) {}
String::String(long v, unsigned char) : s(std::to_string(v)) {}
String::String(unsigned long v, unsigned char) : s(std::to_string(v)) {}
String::String(float v, unsigned int d) { char b[48]; snprintf(b, sizeof b, "%.*f", (int)d, (double)v); s = b; }
String::String(double v, unsigned int d) { char b[48]; snprintf(b, sizeof b, "%.*f", (int)d, v); s = b; }
int String::indexOf(char c, unsigned int from) const { auto p = s.find(c, from); return p == std::string::npos ? -1 : (int)p; }
int String::indexOf(const String &x, unsigned int from) const { auto p = s.find(x.s, from); return p == std::string::npos ? -1 : (int)p; }
String String::substring(unsigned int a, unsigned int b) const { String r; r.s = s.substr(a, b - a); return r; }
long String::toInt() const { return atol(s.c_str()); }
String operator+(const String &a, const String &b) { String r(a); r += b; return r; }
String operator+(const String &a, const char *b) { String r(a); r += b; return r; }
String operator+(const char *a, const String &b) { String r(a); r += b; return r; }
void HardwareSerial::begin(unsigned long) {}
size_t HardwareSerial::println(const char *t) { return (size_t)::printf("[%7.1f s] %s\n", g_ms / 1000.0, t); }
size_t HardwareSerial::println(const String &t) { return println(t.c_str()); }
size_t HardwareSerial::println() { return 0; }
size_t HardwareSerial::printf(const char *f, ...) {
  char b[512]; va_list ap; va_start(ap, f); vsnprintf(b, sizeof b, f, ap); va_end(ap);
  size_t n = strlen(b); if (n && b[n - 1] == '\n') b[n - 1] = 0;
  if (strncmp(b, "[test] looked up", 16) == 0) g_lookups++;
  if (strncmp(b, "[test] checked in", 17) == 0) g_checkins++;
  if (g_lookups + g_checkins <= 3 || strncmp(b, "[test]", 6) != 0) println(b);
  return n;
}
HardwareSerial Serial;
uint32_t EspClass::getFreeHeap() { return 212000; }
EspClass ESP;
// --- Wi-Fi and HTTP: a fake Pi ---
String IPAddress::toString() const { return String("10.42.0.170"); }
bool WiFiClass::mode(wifi_mode_t) { return true; }
bool WiFiClass::setHostname(const char *) { return true; }
int WiFiClass::hostByName(const char *, IPAddress &) { g_ms += 120; return 0; }   // NXDOMAIN after 120 ms
bool WiFiClass::setAutoReconnect(bool) { return true; }
wl_status_t WiFiClass::begin(const char *, const char *, int32_t, const uint8_t *, bool) { return WL_CONNECTED; }
wl_status_t WiFiClass::status() { return WL_CONNECTED; }
IPAddress WiFiClass::localIP() { return IPAddress(); }
int8_t WiFiClass::RSSI() { return -30; }
WiFiClass WiFi;
static String g_url;
bool HTTPClient::begin(String url) { g_url = url; return true; }
bool HTTPClient::begin(String, uint16_t, String) { return true; }
void HTTPClient::setReuse(bool) {}
void HTTPClient::setTimeout(uint16_t) {}
int HTTPClient::GET() { g_ms += 300; return 200; }
int HTTPClient::POST(uint8_t *, size_t) { return -1; }
int HTTPClient::POST(String) {
  g_ms += 250;                                   // a report takes a moment: this is what exposed the bug
  if (g_reports++ == 0) g_test_until = g_ms + 300000;   // the page asks for a 5-minute test
  return 200;
}
void HTTPClient::addHeader(const String &, const String &, bool, bool) {}
String HTTPClient::getString(void) {
  char b[96];
  if (g_test_until > g_ms) snprintf(b, sizeof b, "{\"mode\":\"%s\",\"seconds_left\":%lu}", g_test, (g_test_until - g_ms) / 1000);
  else snprintf(b, sizeof b, "{\"mode\":\"normal\",\"seconds_left\":0}");
  return String(b);
}
void HTTPClient::end(void) {}
String HTTPClient::errorToString(int) { return String("error"); }
bool TwoWire::begin(int, int, uint32_t) { return true; }
TwoWire Wire;
DHT::DHT(uint8_t, uint8_t, uint8_t) {}
void DHT::begin(uint8_t) {}
float DHT::readTemperature(bool, bool) { return 30.0f; }
float DHT::readHumidity(bool) { return 50.0f; }
bool Adafruit_BMP085::begin(uint8_t, TwoWire *) { return true; }
float Adafruit_BMP085::readTemperature(void) { return 31.0f; }
int32_t Adafruit_BMP085::readPressure(void) { return 97350; }

#include "sketch_body.inc"

int main(int argc, char **argv) {
  if (argc > 1) g_test = argv[1];
  setup();
  while (g_ms < 420000) loop();                  // 7 simulated minutes
  printf("SUMMARY test=%s reports=%d lookups=%d checkins=%d\n", g_test, g_reports, g_lookups, g_checkins);
  return 0;
}
