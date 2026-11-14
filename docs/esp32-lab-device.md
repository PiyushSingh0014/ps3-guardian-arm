# ESP32 lab device (`esp32/ps3_lab_device`)

The ESP32 on the IoT Pro Kit board joins the Pi's lab Wi-Fi as an ordinary smart sensor. Every 15 seconds it sends its readings to the Pi.

From the Pi page you can switch on a **test mode**. In a test mode the ESP32 behaves the way infected IoT devices do on a network, so the network monitor can be seen catching it, live.

```
ESP32 ──Wi-Fi PS3-Guardian-Lab──► Pi (10.42.0.1)
  │  every 15 s: readings ──► POST /iot ──► Pi page, "Lab devices"
  │  ◄── the mode the page asked for
  └─ test mode: name look-ups / check-ins ──► network monitor (wlan0) ──► "Network alerts"
```

**The test modes are harmless.** The ESP32 only looks up names that do not exist, or fetches IANA's example page on a timer. Nothing is attacked, nothing leaves the lab except those small requests, and every test stops by itself.

| Test (button on the page) | What the ESP32 does | Alert on the Pi | When |
| --- | --- | --- | --- |
| Looks up made-up names (DGA) | every 6 s, a random name such as `kqxzvbtrwmlp.com` | DANGEROUS: Malware looking for its controller | after about 30 s |
| Looks up a fake bank site | every 30 s, one name such as `sbi-kyc-update-verify.xyz` | DANGEROUS: Device opened a phishing website | at the first look-up |
| Hides data in DNS (tunnel) | every 4 s, a 30-letter sub-name of one made-up name | DANGEROUS: Data hidden in DNS lookups | after about 2 minutes |
| Checks in like clockwork (beacon) | every 60 s, fetches `http://example.com/` | SUSPICIOUS: Device calling home at fixed times | after about 10 minutes |

- **Run times.** The first three tests run for 5 minutes and the beacon test for 15. **Stop the test** ends one early.
- **Beacon test.** It only alerts once the monitor has known the device for 2 hours: the monitor first learns each device's normal. Until then the page shows "learning its normal until HH:MM", and the beacon button stays grey: check-ins during learning would become part of the device's normal, and the test would never alert. Switch the ESP32 on at least 2 hours before you film this test.
- **Repeating a test.** The same problem is reported at most once every 10 minutes, so wait that long between runs of the same test.
- **Llama's explanation.** With the Llama service running, Llama's two-sentence explanation appears under each alert once it is written. The first one takes longest, and a test explained before is instant: see [network-detector.md](network-detector.md#llama-explanations). To have all four instant in a video, run `python -m advisor.warm_cache --net` on the Pi once beforehand.

The page shows which test is running and the latest alerts about the device. Like every request to the Pi, the mode buttons need the pairing token, which the page asks for once.

## Set up (once)

You need Arduino IDE 2 with the **esp32 by Espressif** boards package, and the lab Wi-Fi from [network-detector.md](network-detector.md) part 2.

1. **Libraries.** Sketch → Include Library → **Manage Libraries**, then install:
   - **DHT sensor library** (by Adafruit)
   - **Adafruit BMP085 Library**, which reads the BMP180

   Choose **Install all** when asked about the libraries they need.

2. **Open the sketch** `esp32/ps3_lab_device/ps3_lab_device.ino`. A copy is also in the laptop folder `D:\ARM\ps3-starter\sms_detector\esp32\ps3_lab_device`.

3. **Secrets.** In that folder, `secrets.h` holds the lab Wi-Fi password and the lab-device token. It is never uploaded to git. If it is missing, copy `secrets.example.h` to `secrets.h`. Fill in the two lines marked FILL IN. To see both values, run this on the Pi:

   ```bash
   cat ~/.ps3_lab_wifi ~/.ps3_lab_device_token
   ```

   The first line printed is the Wi-Fi password; the second is the token for `PI_TOKEN`. The lab-device token is good only for posting readings (`POST /iot`): a device that leaks it cannot read alerts or messages. Since update 36 the phones use a separate, longer pairing token; an ESP32 flashed before keeps working, because its old token became the lab-device token.

4. **Wiring and pins.** On the IoT Pro Kit, the sensors are separate modules with their own pin headers. The ESP32 has two header strips beside it, labelled with GPIO numbers. A female–female jumper wire joins a sensor's signal pin to the ESP32 pin. Each sensor gets its power from its **PWR SWITCH** (the red DIP switches); set it to ON.

   Wire with the kit switched off. The Pi is on the same board: run `sudo shutdown -h now` first. The sketch's pins match this wiring:

   | Sensor pin | ESP32 header pin | Power |
   | --- | --- | --- |
   | DHT11 **O/P** | **GPIO4** | DHT11-PWR on |
   | BMP-180 **SDA**, **SCL** | **GPIO21**, **GPIO22** | BMP180-PWR on |
   | VR1 **SIGNAL** | **GPIO34** | VR1 **3.3/5V** → **3.3V**, VR1 **GND** → **GND**: VR1 has no power switch |

   - **The 5 V sensors** (ultrasonic, IR, MQ-135) are left out (`-1`). The ESP32's pins take at most **3.3 V**, and these modules run on 5 V. To add one, put a divider on its output: signal → **1 kΩ** → ESP32 pin, ESP32 pin → **2 kΩ** → GND. Then set its pin in the sketch: ultrasonic TRIG 5 and ECHO 18, IR 19, MQ-135 35.
   - **Analog sensors** (VR1, MQ-135) must be on **GPIO 32–39**. The ESP32 cannot read its other analog pins while Wi-Fi is on, and the sketch says so on the Serial Monitor.
   - **MQ-135 readings** are raw values: higher means more gas. They are not calibrated to ppm.

5. **Upload.** Tools → Board → **ESP32 Dev Module**, then choose the port. The kit's ESP32 has a **CP2102** USB chip, so its port is **Silicon Labs CP210x USB to UART Bridge (COMx)**. If Windows lists it under *Other devices* instead, install the **CP210x Universal Windows Driver** from silabs.com. Then **Upload**. If the upload stops at `Connecting....`, hold the board's **BOOT** button until it starts.

6. **Check.** Open the Serial Monitor at **115200** baud. It shows the sensors found, the Wi-Fi address, and the first report. Within 15 s, `esp32-lab` appears on the Pi page under **Lab devices**, with its readings.

## When something is wrong

| Serial Monitor says | Fix |
| --- | --- |
| `Not on the Wi-Fi yet` | Check `WIFI_PASS` in `secrets.h`, and that the Pi is the hotspot: `bash scripts/setup_gateway.sh --status`. |
| `The Pi refused the pairing token` | `PI_TOKEN` in `secrets.h` must equal `cat ~/.ps3_lab_device_token` on the Pi. |
| `Report not accepted: connection refused` | The Pi app is not running: `sudo systemctl status ps3-guardian`. |
| `BMP180: not found` | Check `I2C_SDA` and `I2C_SCL`. |
| A reading is missing on the page | That sensor did not answer: check its pin. A sensor that does not answer is left out rather than shown as 0. |

The device's name on the Wi-Fi is `esp32-lab`, so alerts show it next to its address.

## How it fits

- The Pi side is `app/lab_devices.py`:
  - `POST /iot`: readings in (the lab-device token, or the pairing token), mode out.
  - `GET /iot`: the page's view, with each device's latest network alerts.
  - `POST /iot/mode`: the page's buttons.
- Readings and device names come from the device, so the Pi checks them (numbers only, at most 20) and the page shows them as plain text.
- The alerts come from the unchanged network monitor ([network-detector.md](network-detector.md)). The ESP32 is simply one more device on the lab Wi-Fi.
