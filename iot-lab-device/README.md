# IoT lab device (ESP32)

**What it is for:** showing that the Home Hub catches an infected IoT device. The ESP32 joins the hub's Wi-Fi as an
ordinary smart sensor and posts DHT11 and BMP180 readings every 15 s. From the hub's web page, four harmless test
modes make it behave like a device taken over by malware.

| Test | What the ESP32 does | What the hub raises | When |
| --- | --- | --- | --- |
| DGA | looks up made-up names such as `kqxzvbtrwmlp.com` every 6 s | DANGEROUS: malware looking for its controller | after about 30 s |
| Fake bank site | looks up `sbi-kyc-update-verify.xyz` every 30 s | DANGEROUS: device opened a phishing website, and the site is blocked | at the first look-up |
| DNS tunnel | a 30-letter sub-name every 4 s | DANGEROUS: data hidden in DNS look-ups | after about 2 minutes |
| Beacon | fetches `http://example.com/` every 60 s | SUSPICIOUS: device calling home at fixed times | after about 10 minutes |

Nothing is attacked: the names do not exist, the beacon fetches IANA's example page, and every test stops by itself.

| Folder | What it is |
| --- | --- |
| [`ps3_lab_device/`](ps3_lab_device/) | The Arduino sketch. Copy `secrets.example.h` to `secrets.h` and fill in the Wi-Fi password and the device token; `secrets.h` is never committed |
| [`sim/`](sim/) | Runs the sketch's loop on a PC with a simulated clock and a fake hub, for the tests (`home-hub/tests/test_esp32_sketch.py`) |

**Use it:** flash it with the Arduino IDE (ESP32 boards; libraries: Adafruit DHT sensor library, Adafruit BMP085),
then start the tests from the hub's page, **Lab devices**. Wiring, flashing and troubleshooting:
[docs/esp32-lab-device.md](../docs/esp32-lab-device.md).
