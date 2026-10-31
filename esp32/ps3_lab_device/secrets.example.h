// Copy this file to secrets.h in the same folder and fill in the two values marked FILL IN.
// secrets.h is not uploaded to git (.gitignore), so the password and the token stay on your laptop.
// To see both values, run on the Pi:   cat ~/.ps3_lab_wifi ~/.ps3_guardian_token
#pragma once

#define WIFI_SSID "PS3-Guardian-Lab"
#define WIFI_PASS "FILL IN: the lab Wi-Fi password (first line printed by the command above)"
#define PI_URL    "http://10.42.0.1:8000"
#define PI_TOKEN  "FILL IN: the pairing token (second line)"
