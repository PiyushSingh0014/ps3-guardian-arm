# Network detector (`detectors/net`)

The Pi watches every connection of every device on its own Wi-Fi and raises an alert when a device:

- scans,
- floods,
- guesses passwords,
- calls home like malware,
- looks up phishing or machine-made names,
- hides data in DNS,
- or suddenly behaves unlike its normal self.

Alerts appear on the Pi's page under **Network alerts**, with the same kind of advice as SMS alerts. It reads connection summaries (flows), never the content of the traffic.

Results on CIC-IDS2017: [eval/results_net.md](../eval/results_net.md).

## How it works

```
Pi's Wi-Fi (wlan0) ──► NFStream: packets → flows (who, to whom, which port, how much, when;
                                        the name looked up or the server's name)
                    ──► engine.py
                         ├─ rules.py     port scan · sweep of many machines (worms, Mirai) · flood (DoS)
                         │               · slow flood (slowloris) · password guessing · malware ports
                         ├─ dns.py       phishing look-up (the link checker) · DGA names · DNS tunnel
                         ├─ baseline.py  each device's normal: alert on a sudden change
                         └─ beacon       a fixed rhythm to a server outside the device's normal
                    ──► logs/net_alerts.jsonl ──► GET /alerts ──► Pi page
```

Each alert has:

- **Kind:** a playbook in `advisor/playbooks/`.
- **Verdict:** suspicious or dangerous.
- **Reasons in plain English,** with addresses and numbers. A device's self-chosen name and the domain names it looked up are kept out of the reasons; they appear only in the details, made unclickable.
- **Advice:** the playbook's first steps.

The same problem is reported at most once per 10 minutes, unless it gets worse (for example, a scan going from 20 to 100 ports).

| Alert | Fires when (within the window) | Verdict |
| --- | --- | --- |
| Port scan | one address tries ≥ 20 closed ports on another (60 s) | suspicious; dangerous at 100 |
| Network scan | one address tries the same port on ≥ 15 machines that never answer (60 s) | suspicious; dangerous at 50, or for Telnet (Mirai) |
| Flood | ≥ 300 connections (or 200 half-open ones) to one target port (10 s); or ≥ 50 slow, nearly empty connections (60 s) | dangerous |
| Password guessing | ≥ 15 short connections to a login port: SSH, FTP, Telnet, RDP, mail, databases, SMB, VNC (60 s) | dangerous at 40 |
| Malware port | a home device connects out on Telnet, IRC, Tor, SMB or 4444 | suspicious |
| Phishing look-up | a device looks up a site on the phishing list, or a brand's name on someone else's site | dangerous |
| DGA names | ≥ 5 machine-made-looking names from one device (10 min) | dangerous |
| DNS tunnel | ≥ 25 long (≥ 18 characters), never-repeating sub-names under one site (10 min) | dangerous |
| Beacon | ≥ 10 contacts at a fixed rhythm (≥ 30 s apart) to a server outside the device's normal and the top 10,000 sites | suspicious |
| Unusual device | a 5-minute period over 3× the device's own 99th percentile in connections, data sent, servers, ports or DNS look-ups, plus ≥ 5 new servers | suspicious |

- **Thresholds.** These are prior assumptions from how the attacks work, not values fitted to a test set. One round of fixes used only Monday's normal traffic of CIC-IDS2017.
- **Learning.** A device's first 2 hours are learning only: no unusual-device or beacon alerts then.

## Set up on the Pi

### 1. Install and start the monitor

This step needs no network change. It starts watching `wlan0` (today, mostly the Pi's own traffic):

```bash
cd ~/ps3-guardian
bash scripts/install_netmon.sh
```

- It installs NFStream into `~/ps3-venv`.
- It creates the systemd service `ps3-netmon`, which runs as your user with only the two capture capabilities (CAP_NET_RAW, CAP_NET_ADMIN).
- It starts the service now and at every boot.
- The log is `logs/netmon.log`.

### 2. Make the Pi the hotspot for the ESP32 and lab devices

The Pi's Wi-Fi becomes a hotspot, `PS3-Guardian-Lab` (2.4 GHz, WPA2, so an ESP32 can join). A phone plugged into the Pi gives it internet over USB:

```
internet ◄── internet phone ◄─USB tethering─ Pi ──► Wi-Fi PS3-Guardian-Lab, the Pi is 10.42.0.1
                                                     ├─ ESP32
                                                     ├─ laptop (SSH)
                                                     └─ your phone with the companion app
```

The internet phone can be a second phone that does nothing else. Ours is a Motorola, because the Galaxy S25 would not switch to USB tethering. Your own phone then joins `PS3-Guardian-Lab` like the other devices, so the detector checks its connections too.

**Prepare the internet phone (once):**

1. **Its own internet:** a SIM with mobile data, or a Wi-Fi other than the hotspot of a phone that will join the lab Wi-Fi.
2. **Never on the lab Wi-Fi:** it must not join `PS3-Guardian-Lab` itself, or its internet goes round in a circle.
3. **Tethering by itself:** Settings → About phone → tap **Build number** 7 times. Then Developer options → **Default USB configuration** → **USB tethering**. Tethering now starts whenever the phone is plugged in and unlocked.
4. **Data Saver off:** Android blocks tethering while it is on.
5. **Optional,** for a spare phone with nothing personal on it: Screen lock → None, so tethering also restarts by itself after the Pi restarts.

**Switch:**

1. Plug the internet phone into a USB port of the Pi. Switch on **USB tethering** if it didn't start by itself.
2. Leave the Pi on your phone's Wi-Fi hotspot for now. It is the way back if something goes wrong.
3. On the Pi:

   ```bash
   cd ~/ps3-guardian
   vcgencmd get_throttled            # 0x0 = power OK; anything else: use the official 3 A supply first
   bash scripts/setup_gateway.sh     # checks everything, prints the hotspot password, asks before switching
   ```

4. Your SSH session ends. On the laptop, join the Wi-Fi `PS3-Guardian-Lab` (password printed in step 3; it is also in `~/.ps3_lab_wifi`), then:

   ```bash
   ssh arrehinus@10.42.0.1
   cd ~/ps3-guardian && bash scripts/setup_gateway.sh --keep
   ```

   If you don't run `--keep` within 10 minutes, the Pi switches back to your phone's hotspot by itself, and you can SSH in as before.

5. Switch off your phone's hotspot and join `PS3-Guardian-Lab` with it. In the companion app, set the Pi address to `http://10.42.0.1:8000` (same pairing token) and tap **Test connection**.

If one phone does both jobs (internet over USB and the app), it stays off the lab Wi-Fi. Its app uses the USB address that `--keep` prints.

**Other commands:**

- `bash scripts/setup_gateway.sh --status` shows the Wi-Fi, the data used through the internet phone, and the devices on the hotspot.
- `bash scripts/setup_gateway.sh --undo` goes back to your phone's hotspot. Switch that hotspot on first.

**Things to know:**

- **Power.** The internet phone charges from the Pi's USB port. The Pi has restarted by itself before, so check `vcgencmd get_throttled` after plugging the phone in.
- **After a restart** of the Pi, tethering comes back by itself if the internet phone is unlocked or has no screen lock (with Default USB configuration set). Otherwise unlock it or switch tethering on again.
- **Mobile data.** Every device on `PS3-Guardian-Lab` uses the internet phone's data.
  - **Android phones** are told the hotspot is metered (the script adds Android's `ANDROID_METERED` hint to the hotspot's DHCP answers), so they hold back big background downloads there, such as app updates and backups.
  - **On the laptop,** set it yourself. Windows: Settings → Network & internet → Wi-Fi → PS3-Guardian-Lab → Metered connection.
  - **To see the data used:** `--status`.
- **Consent.** Everyone whose device joins `PS3-Guardian-Lab` should know the Pi checks its connections. As with SMS: consent first.
  - **What is kept:** alerts, per-device counts, and the addresses or names of the servers each device uses (`data/net/devices.json`). Never the content.
  - **Removing a device:** stop `ps3-netmon`, delete its entry from that file and its lines from `logs/net_alerts.jsonl`, then start the service again.

## Use it on a capture file or the test data

```bash
python -m detectors.net.monitor --pcap capture.pcap                  # any capture file (needs NFStream)
python -m detectors.net.monitor --cic "TrafficLabelling /Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
python detectors/net/eval_net.py --data "TrafficLabelling "          # the full CIC-IDS2017 evaluation
```

## What it cannot do

- **Attacks inside normal-looking web traffic** (SQL injection, XSS, Heartbleed in CIC-IDS2017): seeing them needs the content of the packets. It reads only connection summaries.
- **Encrypted DNS** (DNS over HTTPS) hides look-ups from the DNS checks; the server-name (TLS) check still sees the website.
- **Beacons** can also be normal apps that call home on a timer. They are only "suspicious", and come after the device's learning period.
- **Llama explanations.** Network alerts use the checked playbook text for now. Llama's prompt is written for messages; a network version will be tested on the Pi next.
