#pragma once
#include "Arduino.h"
class TwoWire { public: bool begin(int sda, int scl, uint32_t frequency = 0); };
extern TwoWire Wire;
