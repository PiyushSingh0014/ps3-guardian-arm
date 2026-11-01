#pragma once
#include "Arduino.h"
class IPAddress { public: String toString() const; };
typedef enum { WL_IDLE_STATUS = 0, WL_CONNECTED = 3 } wl_status_t;
typedef enum { WIFI_MODE_STA = 1 } wifi_mode_t;
#define WIFI_STA WIFI_MODE_STA
class WiFiClass {
 public:
  static bool mode(wifi_mode_t);
  static bool setHostname(const char *hostname);
  static int hostByName(const char *aHostname, IPAddress &aResult);
  bool setAutoReconnect(bool autoReconnect);
  wl_status_t begin(const char *ssid, const char *passphrase = NULL, int32_t channel = 0, const uint8_t *bssid = NULL, bool tryConnect = true);
  wl_status_t status();
  IPAddress localIP();
  int8_t RSSI();
};
extern WiFiClass WiFi;
