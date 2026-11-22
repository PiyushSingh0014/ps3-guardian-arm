#pragma once
#include "Arduino.h"
#define DHT11 11
#define DHT22 22
class DHT {
 public:
  DHT(uint8_t pin, uint8_t type, uint8_t count = 6);
  void begin(uint8_t usec = 55);
  float readTemperature(bool S = false, bool force = false);
  float readHumidity(bool force = false);
};
