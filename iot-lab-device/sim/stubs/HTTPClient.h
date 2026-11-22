#pragma once
#include "Arduino.h"
class HTTPClient {
 public:
  bool begin(String url);
  bool begin(String host, uint16_t port, String uri = "/");
  void setReuse(bool reuse);
  void setTimeout(uint16_t timeout);
  int GET();
  int POST(uint8_t *payload, size_t size);
  int POST(String payload);
  void addHeader(const String &name, const String &value, bool first = false, bool replace = true);
  String getString(void);
  void end(void);
  static String errorToString(int error);
};
