# Network detector (`detectors/net`)

The Pi watches every connection of every device on its own Wi-Fi and raises an alert when a device:

- scans,
- floods,
- guesses passwords,
- calls home like malware,
- looks up phishing or machine-made names,
- opens a link from a message the Pi flagged as a scam,
- hides data in DNS,
- or suddenly behaves unlike its normal self.

Alerts appear on the Pi's page under **Network alerts**, with the same kind of advice as SMS alerts, and as notifications in the phone app ([android-companion.md](android-companion.md), Part H). Above them, **Devices on this Wi-Fi** lists every device with a risk level. It reads connection summaries (flows), never the content of the traffic.

Results on CIC-IDS2017: [eval/results_net.md](../eval/results_net.md). To see it catch a device live, use the ESP32 lab device and its harmless test modes: [esp32-lab-device.md](esp32-lab-device.md).

## How it works

```
Pi's Wi-Fi (wlan0) ──► NFStream: packets → flows (who, to whom, which port, how much, when;
                                        the name looked up or the server's name)
                    ──► engine.py
                         ├─ rules.py     port scan · sweep of many machines (worms, Mirai) · flood (DoS)
                         │               · slow flood (slowloris) · password guessing · malware ports
                         ├─ dns.py       link from a scam message opened (scamlinks.py) · phishing look-up
                         │               (the link checker) · DGA names · DNS tunnel
                         ├─ baseline.py  each device's normal: alert on a sudden change
                         └─ beacon       a fixed rhythm to a server outside the device's normal
                    ──► logs/net_alerts.jsonl ──► GET /alerts, GET /devices ──► Pi page, phone app

flagged SMS, chat or pasted message ──► app/server.py ──► data/fusion/watch.json (its websites, 24 h) ──► dns.py
```

Each alert has:

- **Kind:** a playbook in `advisor/playbooks/`.
- **Verdict:** suspicious or dangerous.
- **Reasons in plain English,** with addresses and numbers. A device's self-chosen name and the domain names it looked up are kept out of the reasons; they appear only in the details, made unclickable.
- **Advice:** the playbook's first steps.
- **Llama's explanation,** when the Pi runs the Llama service: two plain-language sentences, written in the background ([below](#llama-explanations)).

The same problem is reported at most once per 10 minutes, unless it gets worse (for example, a scan going from 20 to 100 ports).

| Alert | Fires when (within the window) | Verdict |
| --- | --- | --- |
| Port scan | one address tries ≥ 20 closed ports on another (60 s) | suspicious; dangerous at 100 |
| Network scan | one address tries the same port on ≥ 15 machines that do not answer or refuse, and those are most of the machines it tried there (60 s) | suspicious; dangerous at 50, or for Telnet (Mirai) |
| Flood | ≥ 300 connections (or 200 half-open ones) to one target port (10 s); or ≥ 50 slow, nearly empty connections (60 s) | dangerous |
| Password guessing | ≥ 15 short connections to a login port: SSH, FTP, Telnet, RDP, mail, databases, SMB, VNC (60 s) | dangerous at 40 |
| Malware port | a home device connects out on Telnet, IRC, Tor, SMB or 4444 | suspicious |
| Link from a scam message opened | a device looks up a website that came in a message the Pi flagged as a scam in the last 24 hours (below) | dangerous |
| Phishing look-up | a device looks up a site on the phishing list, or a brand's name on someone else's site; not services that pages load in the background, such as Gravatar or Google's AMP cache | dangerous |
| DGA names | ≥ 5 machine-made-looking names from one device (10 min) | dangerous |
| DNS tunnel | ≥ 25 long (≥ 18 characters), never-repeating sub-names under one site (10 min) | dangerous |
| Beacon | ≥ 10 new connections at a fixed rhythm (≥ 30 s apart) to a server outside the device's normal and the top 10,000 sites; keep-alives inside one open connection do not count | suspicious |
| Unusual device | a small home device (≤ 50 servers while learning): a 5-minute period over 3× its own 99th percentile in connections, data sent, servers, ports or DNS look-ups, plus ≥ 5 new servers | suspicious |

- **Thresholds.** These are prior assumptions from how the attacks work, not values fitted to a test set. One round of fixes used only Monday's normal traffic of CIC-IDS2017.
- **Learning.** A device's first 2 hours are learning only: no unusual-device or beacon alerts then.
- **Unusual device is for small home devices.** A device that used more than 50 servers while learning is a laptop or phone: how much it does follows its user. In a busy hour on the lab Wi-Fi a laptop opening 30 websites in 10 minutes set it off twice, so it is no longer reported for such devices. The other checks still watch them.
- **A busy browser is no network scan.** Browsers open many connections at once, and some get no answer. On the lab Wi-Fi a laptop had 15 such tries on port 443 while it made some 2,900 connections in 5 minutes. A scan now needs most of the machines tried on that port to stay silent, as a worm's tries do.
- **Only new connections are tries** for network scans, password guessing and beacons on live traffic. The flow meter cuts a long connection into pieces after 10 s of silence, and those pieces are not new tries. For a network scan, a machine that answered at all does not count, even if the device then closed the connection unused, as browsers do. Both kinds raised false alarms on the lab Wi-Fi ([eval/results_net.md](../eval/results_net.md)). CIC-IDS2017's rows cannot tell these apart, so they keep the older test.

## Messages meet network traffic

The SMS and link checks see a scam message; the network monitor sees what devices open. Together they can tell when someone opened a link from a scam:

1. When the Pi flags an SMS, a chat or a message pasted on its page, the app writes the websites in its links to `data/fusion/watch.json`, for 24 hours (`detectors/net/scamlinks.py`).
2. The network monitor reads that list. When a device on the lab Wi-Fi looks up one of those websites, it raises **"Link from a scam message opened"** for that device. The alert says when the message came and how ("an SMS from a mobile number"). This replaces the phishing look-up alert for that name.

- **Why it matters.** Real Indian scam links often use short domains that look just like genuine bulk-SMS link domains, so the link checker alone rates them safe ([eval/results_url.md](../eval/results_url.md)). The message's sender and text gave the scam away, and the look-up shows that the link was opened.
- **Left out:** official sites, popular sites, link shorteners, chat links and shared services such as Google Drive. Everyone opens those all day, so a match would say nothing. Messages judged safe or plain marketing add nothing either.
- **Kept:** only the website names, each for 24 hours. No text, no sender.
- **Look-ups only after the message came** count (with one minute of slack for clocks).

**Test it from the laptop** (on `PS3-Guardian-Lab`):

1. On the Pi's page, check this message with the sender `9812345678`. It should come out DANGEROUS:

   ```
   Dear customer your SBI account will be blocked today. Update KYC now: http://sbi-kyc-verify-ps3lab.xyz/login
   ```

2. In PowerShell on the laptop, look the name up. Only look it up: don't open it in a browser.

   ```powershell
   Resolve-DnsName sbi-kyc-verify-ps3lab.xyz -Server 10.42.0.1 -ErrorAction SilentlyContinue
   ```

3. About 10–20 s later: "DANGEROUS: Link from a scam message opened" for the laptop on the page, the laptop "At risk" under **Devices on this Wi-Fi**, and a notification on the phone app.

## Devices on this Wi-Fi

`GET /devices` lists every device that was active on the lab Wi-Fi this week, riskiest first. The Pi's page and the phone app show it. Addresses that are not a device's own, such as `0.0.0.0` (a device still asking for an address), are left out.

- **At risk:** a dangerous alert in the last 24 hours. **Check:** a suspicious one. **OK:** none.
- **Each device shows:**
  - its name (from the hotspot, or from the ESP32's reports);
  - when it was last active (the monitor saves this every 10 minutes);
  - whether the monitor is still learning its normal;
  - a one-line summary;
  - its latest 3 alerts.

## Llama explanations

With the Llama service running, a new alert appears on the page at once with the checked playbook text. Llama's explanation follows under it: two sentences on what the device did, what the attacker or malware wants, and why it is a warning sign. The steps still come from the playbook.

- **What Llama sees.** The alert type, the playbook's checked fact and what the attacker wants, and the monitor's reasons in plain words:
  - the device in the alert becomes "the device";
  - other addresses become "another device on your network" or "a server on the internet";
  - website names become "a website".

  The device's own name and the names it looked up never reach Llama: whoever chose them could hide instructions in them. Network alerts have their own system text and four worked examples (`advisor/prompt.py`), because "who the message pretends to be from" does not fit a device.
- **The same checker as for messages.** An answer that calls the alert normal or harmless is refused, and a sentence with a link or a number is dropped. The page then keeps the playbook text.
- **One at a time, messages first.** The app explains the newest 20 alerts of the last week (the page lists 20), newest first. A new explanation starts only when no message is waiting for Llama. A message checked while Llama explains a network alert waits for it, and the page says so. Its verdict and steps still appear at once.
- **Time on the Pi** (measured on 3 November 2026, 13 network prompts, four worked examples):
  - The first network explanation after a message took 86 s: Llama first reads the network examples, about 770 tokens, and its first word came after 67 s.
  - The next ones took 21–31 s, because they reuse the examples.
  - The same alerts again are instant, from the answer cache (0.1 s for all of them). A repeat of an ESP32 test is instant this way.
  - Afterwards Llama re-reads the message examples when idle (about 38 s), so the next message check is fast again.
  - The fourth example (update 23) is for "Link from a scam message opened": without it, Llama wrote that the message was "flagged by the device itself". It added about 19 s to the first explanation; the others did not change.
- **To switch it off,** set `NET_EXPLAIN=0` in the app's environment.

To review the answers and their time, and to fill the answer cache before a demo, run this on the Pi with the Llama service running:

```bash
cd ~/ps3-guardian && source ~/ps3-venv/bin/activate
python -m advisor.warm_cache --net
```

It explains one sample of each of the 10 alert kinds, plus every alert in `logs/net_alerts.jsonl`. The table goes to `eval/advisor_net_review.md`. Add `--fresh` to time every answer without the cache.

## Set up on the Pi

### 1. Install and start the monitor

This step needs no network change. It starts watching `wlan0`, which carries mostly the Pi's own traffic until the Pi becomes the hotspot (part 2):

```bash
cd ~/ps3-guardian
bash scripts/install_netmon.sh
```

- It installs NFStream into `~/ps3-venv`.
- It creates the systemd service `ps3-netmon`, which runs as your user with only the two capture capabilities (CAP_NET_RAW, CAP_NET_ADMIN).
- It starts the service now and at every boot.
- It installs `ps3-leases`, so alerts can show device names. NetworkManager's list of devices on the hotspot is readable only by root. Whenever that list changes, `ps3-leases` copies each device's address and the name it gave itself (nothing else) to `/run/ps3-guardian/leases`, readable by your user.
- The log is `logs/netmon.log`. It has every alert and, every 15 minutes, a status line such as `[net] 19:30 1234 flows so far (56 in the last 15 min), 1 alerts`. The status line comes on time even when nothing is on the Wi-Fi (`0 in the last 15 min`), so `tail -n 3 logs/netmon.log` shows at once whether the monitor sees your devices.
- **If the capture gets stuck** (the Wi-Fi carries packets but no flow comes out for 10 minutes), the log says `the Wi-Fi carried … packets … but the capture saw no flow: restarting the capture`, the monitor stops and systemd starts it again 10 s later.

Running the script again is safe: it rewrites the services and restarts the monitor.

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

- **Power.** The internet phone charges from the Pi's USB port. The Pi has restarted by itself before (the last time on 3 November, just after the services were restarted while the S25 charged from it at about 20% battery), so check `vcgencmd get_throttled` after plugging the phone in. Plug the phone in with a charged battery.
- **Keep the system log across restarts,** so the next unexpected restart shows its cause (`journalctl -b -1`). Run this once:

  ```bash
  sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald
  ```
- **After a restart** of the Pi, tethering comes back by itself if the internet phone is unlocked or has no screen lock (with Default USB configuration set). Otherwise unlock it or switch tethering on again.
- **Mobile data.** Every device on `PS3-Guardian-Lab` uses the internet phone's data.
  - **Android phones** are told the hotspot is metered (the script adds Android's `ANDROID_METERED` hint to the hotspot's DHCP answers), so they hold back big background downloads there, such as app updates and backups.
  - **On the laptop,** set it yourself. Windows: Settings → Network & internet → Wi-Fi → PS3-Guardian-Lab → Metered connection.
  - **To see the data used:** `--status`.
- **Consent.** Everyone whose device joins `PS3-Guardian-Lab` should know the Pi checks its connections. As with SMS: consent first.
  - **What is kept:** alerts, per-device counts, when each device was last active, and the addresses or names of the servers each device uses (`data/net/devices.json`). Never the content. From flagged messages, the website names in their links, for 24 hours (`data/fusion/watch.json`).
  - **Removing a device:** stop `ps3-netmon`, delete its entry from that file and its lines from `logs/net_alerts.jsonl`, then start the service again.

## Measure it on real traffic

Two tools for the report. Run them on the Pi, from `~/ps3-guardian` with `source ~/ps3-venv/bin/activate`.

**False alarms per day.** The monitor keeps the hours it watched and the flows it saw per day (`data/net/days.json`). The app logs every test started from its page (`logs/lab_tests.jsonl`).

- **Watched time** is written down every 5 minutes on a clock of its own, quiet or not, and each day gets its own time (split at midnight).
- It counts only while the Wi-Fi is up and the capture works. Of that, the **hours with traffic** are the 5-minute stretches in which at least one flow came.
- **A new count** starts when the file is new: the monitor writes the time into it (`_started`), and `label` and `measure` leave out alerts from before then.
- Before update 26 the time was written down only when a flow arrived, so a quiet stretch went to the next day all at once: on 5 Nov 2026 the file had 60 hours for that one day, after two days with nobody on the Wi-Fi. To start counting afresh, stop the monitor, move the file aside and start it again:

  ```bash
  sudo systemctl stop ps3-netmon
  mv data/net/days.json data/net/days-before-update26.json
  sudo systemctl start ps3-netmon
  ```

1. Leave the lab Wi-Fi in normal use for a day or more: the laptop and phones on `PS3-Guardian-Lab`, used as usual. An hour in, check that the monitor sees them: `tail -n 3 logs/netmon.log` should show hundreds or thousands of flows `in the last 15 min` while the laptop is in use.

   **No time for a day?** A busy hour packs much of a day's variety into an hour: 30 common websites opened one after another, YouTube, Windows Update, the apps you use, a video call. It gives false alarms per hour of use and per 10,000 connections, not per day. The results are in [eval/results_net.md](../eval/results_net.md).
2. Say what each alert was, in the terminal:

   ```bash
   python scripts/net_traffic.py label
   ```

   It shows the alerts of the days the monitor watched, one at a time, with the device, the kind and the red flags. Type a letter and press Enter:
   - `t`: a test, you caused it on purpose (such as the laptop's look-ups);
   - `f`: a false alarm, nothing was wrong;
   - `r`: a real problem.

   Enter on its own skips an alert you are not sure about, and `q` (or Ctrl+C) stops. Each answer is saved at once in `data/net/labels.json`, so running it again carries on where you stopped; `--again` goes through the labelled ones too. Alerts during the ESP32's test modes are labelled `test` already.

3. Measure:

   ```bash
   python scripts/net_traffic.py measure
   ```

   It prints a table per day (hours watched, hours with traffic, flows, alerts, and how they were labelled), the false alarms per watched day and per 24 hours with traffic, and the false alarms by kind and by device.
   - Alerts of days without watched time (before the monitor kept it) are left out; `--all` lists them.
   - A day with fewer than 300 flows an hour is named as **hardly used**: a laptop in use makes thousands an hour, so such a day does not show normal use.

**In a spreadsheet instead:** `python scripts/net_traffic.py export alerts.csv` writes every alert with its label so far. Fill the `label` column with `test`, `false` or `real`, then run `python scripts/net_traffic.py measure alerts.csv`. The sheet may go through Excel, which re-writes dates in the PC's own format and may save in the Windows code page: `measure` matches each row to the alert log by its `id`, so it still counts it on the right day.

**CPU, memory and temperature:**

```bash
python scripts/pi_usage.py --minutes 30
```

- **What it samples:** every 5 s, the monitor, the app and Llama, and the whole Pi. It prints a table of averages and peaks and writes every sample to `logs/pi_usage-….csv`.
- **CPU figures** are a share of all four cores: 25% is one core fully busy.
- **What to do during the 30 minutes** so the table covers the real work: one ESP32 test, and one message check that Llama explains.
- **If the run was cut off** before its table (the SSH window closed, the laptop slept): `python scripts/pi_usage.py --from last` prints the table from the samples saved so far.

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
- **Beacons over one open connection are not seen.** Only new connections count, because apps that keep a connection open ping it at a fixed rhythm too ([eval/results_net.md](../eval/results_net.md)). Malware that checks in over a connection it keeps open would need a separate "long connection" check.
- **Llama explains network alerts in English only.** Messages can also get Hindi.
- **An internet outage can look like a scan.** When the internet phone loses its connection, every new connection from the lab Wi-Fi fails. A device that retries many servers within a minute then looks like it is scanning.
