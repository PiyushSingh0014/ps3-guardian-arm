// Stand-ins for the arduino-esp32 3.x APIs the sketch uses, with the same signatures as the real
// headers (checked against espressif/arduino-esp32 master). Only for iot-lab-device/sim/sim.cpp.
#pragma once
#include <cstdint>
#include <cstring>
#include <math.h>   // Arduino.h includes math.h: isnan() and NAN at global scope
#include <cstddef>
#include <string>
typedef bool boolean;
#define LOW 0x0
#define HIGH 0x1
#define INPUT 0x01
#define OUTPUT 0x03
#define constrain(amt, low, high) ((amt) < (low) ? (low) : ((amt) > (high) ? (high) : (amt)))
void pinMode(uint8_t pin, uint8_t mode);
void digitalWrite(uint8_t pin, uint8_t val);
int digitalRead(uint8_t pin);
uint16_t analogRead(uint8_t pin);
void delay(uint32_t);
void delayMicroseconds(uint32_t us);
unsigned long millis();
unsigned long pulseIn(uint8_t pin, uint8_t state, unsigned long timeout = 1000000L);
long random(long);
long random(long, long);
inline boolean isDigit(int c) { return c >= '0' && c <= '9'; }
extern "C" void configTime(long gmtOffset_sec, int daylightOffset_sec, const char *server1, const char *server2 = nullptr, const char *server3 = nullptr);
class String {
 public:
  String(const char *c = "") : s(c ? c : "") {}
  String(const String &o) = default;
  explicit String(char c) : s(1, c) {}
  explicit String(int, unsigned char base = 10);
  explicit String(unsigned int, unsigned char base = 10);
  explicit String(long, unsigned char base = 10);
  explicit String(unsigned long, unsigned char base = 10);
  explicit String(float, unsigned int decimalPlaces = 2);
  explicit String(double, unsigned int decimalPlaces = 2);
  String &operator=(const String &o) = default;
  String &operator=(const char *c) { s = c; return *this; }
  unsigned int length() const { return s.size(); }
  bool reserve(unsigned int n) { s.reserve(n); return true; }
  const char *c_str() const { return s.c_str(); }
  char operator[](unsigned int i) const { return s[i]; }
  int indexOf(char c, unsigned int from = 0) const;
  int indexOf(const String &x, unsigned int from = 0) const;
  String substring(unsigned int a, unsigned int b) const;
  long toInt() const;
  String &operator+=(const String &o) { s += o.s; return *this; }
  String &operator+=(const char *c) { s += c; return *this; }
  String &operator+=(char c) { s += c; return *this; }
  bool operator==(const String &o) const { return s == o.s; }
  bool operator==(const char *c) const { return s == c; }
  bool operator!=(const String &o) const { return s != o.s; }
  bool operator!=(const char *c) const { return s != c; }
  std::string s;
};
String operator+(const String &a, const String &b);
String operator+(const String &a, const char *b);
String operator+(const char *a, const String &b);
class HardwareSerial {
 public:
  void begin(unsigned long baud);
  size_t println(const char *);
  size_t println(const String &);
  size_t println();
  size_t printf(const char *format, ...) __attribute__((format(printf, 2, 3)));
};
extern HardwareSerial Serial;
class EspClass { public: uint32_t getFreeHeap(); };
extern EspClass ESP;
