#pragma once
#include "Arduino.h"
#include "Wire.h"
#define BMP085_ULTRAHIGHRES 3
class Adafruit_BMP085 {
 public:
  bool begin(uint8_t mode = BMP085_ULTRAHIGHRES, TwoWire *wire = &Wire);
  float readTemperature(void);
  int32_t readPressure(void);
};
