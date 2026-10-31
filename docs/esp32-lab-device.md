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
- **Beacon test.** It only alerts once the monitor has known the device for 2 hours: the monitor first learns each device's normal. The page shows "learning its normal until HH:MM" until then. Switch the ESP32 on at least 2 hours before you film this test.
- **Repeating a test.** The same problem is reported at most once every 10 minutes, so wait that long between runs of the same test.

The page shows which test is running and the latest alerts about the device. Mode buttons need no token, like the rest of the page, so only people on the lab Wi-Fi can use them.

## Set up (once)

You need Arduino IDE 2 with the **esp32 by Espressif** boards package, and the lab Wi-Fi from [network-detector.md](network-detector.md) part 2.

1. **Libraries.** Sketch → Include Library → **Manage Libraries**, then install:
   - **DHT sensor library** (by Adafruit)
   - **Adafruit BMP085 Library**, which reads the BMP180

   Choose **Install all** when asked about the libraries they need.

2. **Open the sketch** `esp32/ps3_lab_device/ps3_lab_device.ino`. A copy is also in the laptop folder `D:\ARM\ps3-starter\sms_detector\esp32\ps3_lab_device`.

3. **Secrets.** In that folder, `secrets.h` holds the lab Wi-Fi password and the pairing token. It is never uploaded to git. If it is missing, copy `secrets.example.h` to `secrets.h`. Fill in the two lines marked FILL IN. To see both values, run this on the Pi:

   ```bash
   cat ~/.ps3_lab_wifi ~/.ps3_guardian_token
   ```

   The first line printed is the Wi-Fi password; the second is the token.

4. **Pins.** At the top of the sketch, set each pin to the label printed on your board. Use `-1` for anything that is not connected.

   | Constant | Default | Sensor |
   | --- | --- | --- |
   | `DHT_PIN`, `DHT_TYPE` | 4, `DHT11` | DHT11 (blue) or DHT22 (white): temperature, humidity |
   | `TRIG_PIN`, `ECHO_PIN` | 5, 18 | ultrasonic distance sensor |
   | `IR_PIN`, `IR_ACTIVE_LOW` | 19, true | IR obstacle sensor; most modules pull the output low when something is in front |
   | `VR1_PIN` | 34 | VR1 knob (potentiometer) |
   | `MQ135_PIN` | 35 | MQ-135 air-quality sensor: a raw value, higher means more gas; it is not calibrated to ppm |
   | `I2C_SDA`, `I2C_SCL` | 21, 22 | BMP180: pressure and temperature |

   Analog sensors (VR1, MQ-135) must be on **GPIO 32–39**. The ESP32 cannot read its other analog pins while Wi-Fi is on, and the sketch says so on the Serial Monitor.

5. **Upload.** Tools → Board → **ESP32 Dev Module**, choose the port, then **Upload**. If the upload stops at `Connecting....`, hold the board's **BOOT** button until it starts.

6. **Check.** Open the Serial Monitor at **115200** baud. It shows the sensors found, the Wi-Fi address, and the first report. Within 15 s, `esp32-lab` appears on the Pi page under **Lab devices**, with its readings.

## When something is wrong

| Serial Monitor says | Fix |
| --- | --- |
| `Not on the Wi-Fi yet` | Check `WIFI_PASS` in `secrets.h`, and that the Pi is the hotspot: `bash scripts/setup_gateway.sh --status`. |
| `The Pi refused the pairing token` | `PI_TOKEN` in `secrets.h` must equal `cat ~/.ps3_guardian_token` on the Pi. |
| `Report not accepted: connection refused` | The Pi app is not running: `sudo systemctl status ps3-guardian`. |
| `BMP180: not found` | Check `I2C_SDA` and `I2C_SCL`. |
| A reading is missing on the page | That sensor did not answer: check its pin. A sensor that does not answer is left out rather than shown as 0. |

The device's name on the Wi-Fi is `esp32-lab`, so alerts show it next to its address.

## How it fits

- The Pi side is `app/lab_devices.py`:
  - `POST /iot`: readings in (pairing token needed), mode out.
  - `GET /iot`: the page's view, with each device's latest network alerts.
  - `POST /iot/mode`: the page's buttons.
- Readings and device names come from the device, so the Pi checks them (numbers only, at most 20) and the page shows them as plain text.
- The alerts come from the unchanged network monitor ([network-detector.md](network-detector.md)). The ESP32 is simply one more device on the lab Wi-Fi.
