# Network detector: results

Measured 2026-10-26 with `detectors/net/eval_net.py` on CIC-IDS2017, and with `detectors/net/train_dga.py` for the DGA model. How the detector works is in [docs/network-detector.md](../docs/network-detector.md).

## CIC-IDS2017: five days of a company network with labelled attacks

[CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Sharafaldin, Habibi Lashkari and Ghorbani, ICISSP 2018) is five working days of traffic from a company network of about a dozen PCs and servers, with attacks on four of the days. The flows used here are the labelled CSV files (`GeneratedLabelledFlows.zip`): 2,830,743 flows over 40.7 hours.

### How it was run

- **Order.** The days are fed in order, as one Pi would see them. Monday has normal traffic only, so it is where each device's normal behaviour is learned; Tuesday to Friday hold the attacks.
- **When an attack counts as detected.** An alert of the kind you would expect (for example "password guessing" for SSH-Patator) names the attack's addresses during its main period, give or take 5 minutes. The main period is the 5th to 95th percentile of the attack flows' start times.
- **What counts as a false alarm.** Any alert that matches no attack. Alerts that name the attackers' own machine (205.174.165.73) outside the labelled times are counted apart (see below).
- **One round of tuning, on Monday only.** The first run gave 464 false alarms on Monday and 1,412 over the five days. Then:
  - three rule changes were made using Monday's normal traffic;
  - one change follows a known CICFlowMeter quirk: it counts the Ethernet padding of empty packets as data (Engelen et al., 2021).

  The results below are from the second run. Nothing was changed after looking at the attack days.

### Attacks

| Attack (day) | Flows | Main period | Detected | First alert | Alert kind |
| --- | --- | --- | --- | --- | --- |
| FTP-Patator, password guessing (Tue) | 7,938 | 09:22–10:17 | yes | at once | password guessing |
| SSH-Patator, password guessing (Tue) | 5,897 | 14:12–15:08 | yes | at once | password guessing |
| DoS slowloris (Wed) | 5,796 | 09:48–10:09 | yes | at once | flood |
| DoS Slowhttptest (Wed) | 5,499 | 10:15–10:33 | yes | after 4 min | flood |
| DoS Hulk (Wed) | 231,073 | 10:43–10:59 | yes | at once | flood |
| DoS GoldenEye (Wed) | 10,293 | 11:10–11:19 | yes | after 49 s | flood |
| Infiltration, then an internal port scan (Thu) | 36 | 14:19–15:41 | yes | after 13 min | port scan |
| Bot (Ares) calling its controller (Fri) | 1,966 | 10:14–12:36 | yes | after 10 min | beacon |
| PortScan (Fri) | 158,930 | 14:51–15:22 | yes | at once | port scan |
| DDoS, LOIC (Fri) | 128,027 | 15:57–16:15 | yes | at once | flood |
| Heartbleed (Wed) | 11 | 15:12–15:30 | no | – | – |
| Web attacks: brute force, XSS, SQL injection (Thu) | 2,180 | 09:23–10:42 | no | – | – |

**All 10 attacks that show in the shape of the traffic were detected, 7 of them within the first minute.**

- **Bot:** a beacon alert needs 10 regular check-ins, which takes about 10 minutes at the Ares bot's interval.
- **Infiltration:** the alert came when the infected PC began scanning the network.
- **Heartbleed and the three web attacks were missed.** They look like ordinary web connections; seeing them needs the content of the packets (a web application firewall), which this detector does not read by design.

### False alarms

With update 27 (the busy hour on the lab Wi-Fi, below):

| Day | Hours | Alerts | False alarms | of which beacons | others |
| --- | --- | --- | --- | --- | --- |
| Monday (normal traffic only) | 8.1 | 38 | 38 | 25 | 13 |
| Tuesday | 8.1 | 63 | 43 | 41 | 2 |
| Wednesday | 8.5 | 22 | 14 | 13 | 1 |
| Thursday morning | 4.0 | 8 | 8 | 7 | 1 |
| Thursday afternoon | 4.1 | 85 | 17 | 9 | 8 |
| Friday morning | 4.0 | 33 | 7 | 7 | 0 |
| Friday afternoon, port scan | 2.5 | 43 | 7 | 4 | 3 |
| Friday afternoon, DDoS | 1.5 | 22 | 10 | 10 | 0 |
| **Total** | **40.7** | **314** | **144** | **116** | **28** |

- **Not counting beacons:** 28 false alarms in 40.7 hours for about a dozen machines, fewer than one an hour for the whole network.
  - Most are browsers that opened many connections that never answered (10 "network scans" on Monday).
  - A few, on Thursday afternoon, look like real but unlabelled attack traffic, for example a scan from the attackers' gateway 172.16.0.1. They are still counted as false.
- **Beacon alerts are the weak point here, partly because of the data.** The CSV times are rounded to whole minutes, so any connection repeated about once a minute looks perfectly regular after rounding. On the Pi the monitor sees exact times and the server names (TLS), and it skips popular websites. This test cannot show how much that helps; the real-traffic week will.
- **41 alerts named the attackers' own machine outside the labelled times.** They are the infected PCs still calling the bot's controller on Friday afternoon, after the labelled Bot hour; CIC's labels call that traffic normal (Engelen et al. list such label gaps). They are counted neither as detections nor as false alarms.

### Before and after the Monday tuning

| | False alarms, Monday | False alarms, five days | Attacks detected |
| --- | --- | --- | --- |
| First run | 464 | 1,412 | 10 of 10 (any alert kind, looser matching) |
| Second run | 47 | 162 | 10 of 10 (the expected alert kind) |
| Update 27 (reported) | 38 | 144 | 10 of 10, with the same first-alert times |

The changes:

- **Machines that answer don't count toward a "sweep".** A browser opening many working connections is not a scan.
- **Server replies are not new connections.** A reply cut off into a flow of its own, from a service port to a client's temporary port, is ignored.
- **Floods are counted per target port, without DNS.** Look-ups to the company's name server are not a flood.
- **A big download alone is not an anomaly.**
- **Beacons need 10 check-ins at least 30 seconds apart.**
- **Empty packets are empty, even with CICFlowMeter's padding.**

Update 27 came from the lab Wi-Fi, not from this data, and the five days only checked it afterwards:

- **A sweep needs most of the machines tried on that port to stay silent.** Monday's port-443 "scans" fell from 18 to 10.
- **"Unusual device" is only for small home devices** (at most 50 servers while learning). The company PCs used far more, so its 6 false alarms are gone. None of the attacks needed it: FTP-Patator was also caught as password guessing, Infiltration as a port scan.

## DGA model: does a domain name look machine-made?

ExtraHop's DGA Detection Training Dataset (MIT licence): 16.2 million names, half generated by known malware families. 800,000 were sampled; 80% train, 20% held out.

| Test | Names | Machine-made names caught at ≥ 0.9 | Real names flagged at ≥ 0.9 |
| --- | --- | --- | --- |
| Held-out ExtraHop names | 160,000 | 89.8% | 0.35% |
| Chrome's top 1M websites (names of 6+ letters) | 605,266 | – | 0.85% |

ROC AUC is 0.997 on the held-out names. The real names it flags are mostly random-looking themselves (ad and tracking hosts such as `xqvbnzmkrtplwj`).

The alert needs **5 different such names from one device within 10 minutes**, so a single odd name never raises one.

## The Pi's own lab Wi-Fi: first day (1 November 2026)

The Pi is the hotspot `PS3-Guardian-Lab`. On it: a laptop, a Galaxy S25 and the ESP32 lab device ([docs/esp32-lab-device.md](../docs/esp32-lab-device.md)). The monitor ran live on `wlan0` (NFStream), with about 2,250 flows every 15 minutes.

**All four of the ESP32's test modes were caught, each naming `esp32-lab (10.42.0.170)`:**

| Test (what the ESP32 did) | Alert | After |
| --- | --- | --- |
| made-up `.com` names, one every 6 s | DANGEROUS: Malware looking for its controller | the 5th name (about 30 s) |
| `sbi-kyc-update-verify.xyz`, every 30 s | DANGEROUS: Device opened a phishing website | the first look-up |
| 30-character sub-names of one made-up name, every 4 s | DANGEROUS: Data hidden in DNS lookups | the 25th look-up (about 2 minutes) |
| `http://example.com/` every 60 s, a new connection each time (after the device's 2-hour learning time) | SUSPICIOUS: Device calling home at fixed times | the 10th check-in (13:29:05); no repeat for the other 5 |

**False alarms: keep-alives looked like beacons.** Between 11:40 and 12:31 the laptop got about a dozen "calling home at fixed times" alerts: Cloudflare and Google addresses, every 31 or 45 seconds, with no server name.

- **The cause.** Those are apps that keep one connection open and ping it. The flow meter starts a new flow after 10 s of silence, so every ping became a "contact", without a TCP handshake or a server name.
- **The fix.** On live traffic, a beacon now counts only new connections: TCP flows that start with a handshake, and UDP flows that name their server (a new QUIC session does). Tools that time connection starts, such as RITA, look for beacons the same way. The ESP32's beacon test opens a new connection for each check-in, so it still counts (tests cover both cases).
- **What it can no longer see.** Malware that checks in over one connection it keeps open.
- **After the fix** (the monitor restarted with it the same afternoon), the laptop got no more "calling home" alerts, while the ESP32's beacon test was still caught. A longer count follows below.
- **Learning matters for the beacon test.** Run during the device's first 2 hours, its check-ins became part of its normal and no alert came. The test was run again after the learning time.
- **CIC-IDS2017 cannot measure this.** Its CSV rows show 0 SYN packets even for port-scan traffic, which is nearly all SYN packets: 158,923 of 158,923 PortScan flows. They also carry no server names. So CSV rows keep the old rule, and the CIC-IDS2017 numbers above are unchanged. The lab Wi-Fi's own alerts are the measurement.

**A second false alarm, the next day (2 November, 12:47): the laptop "tried to connect to 15 different machines on port 443 within a minute, mostly without answer".** Port 443 is HTTPS. Only the laptop raised it, so an internet outage, which makes every busy device fail at once, is unlikely.

- **The likely cause.** The alert does not record which connections they were. Two kinds of normal flows counted as failed tries:
  - the ends of idle connections that the laptop's apps closed: pieces without a handshake, often refused by servers that had already forgotten them;
  - connections that a server answered but the laptop closed unused (browsers open spare connections).

  CIC-IDS2017's Monday has the same kind: 18 of its 47 false alarms are such "scans", all on port 443.
- **The fix (update 18).** On live traffic, a network-scan try is now a new connection that got no answer or was refused. The same "new connections only" rule now applies to password guessing, so pauses in an SSH session are not logins. The CIC-IDS2017 numbers did not change then (checked: the same 162 false alarms and the same detections).

## The Pi's lab Wi-Fi: a busy hour (5 November 2026)

- **Why an hour, not a day.** The first try at a whole day (3–5 November) had nobody on the lab Wi-Fi after its first hour: 3,272 flows in 60.9 hours. It also showed that the monitor wrote its watched time down only when traffic came (fixed in update 26). So the laptop was put through one busy hour instead, which packs much of a day's variety into an hour.
- **What was done,** with the laptop on `PS3-Guardian-Lab` and the S25 as the Pi's internet:
  - PowerShell opened 30 common websites, one every 20 seconds: Indian and global news, shopping, travel, food delivery, cricket, coding and learning sites, maps;
  - YouTube for about 10 minutes, Windows Update, and the apps in daily use.
- **Counted:** 36 minutes (0.6 hours), 4,415 flows, traffic in every 5-minute stretch.

| Time | Alert | Why it was false | Fix (update 27) |
| --- | --- | --- | --- |
| 15:25 | Unusual device: 2,895 connections in 5 minutes (its usual most 686), 228 new servers | the laptop was simply used more than before | "Unusual device" only for small home devices: at most 50 servers while learning. The laptop had 175, the ESP32 4 |
| 15:30 | Unusual device: 7,251 connections and 853 servers in 5 minutes | the same | the same |
| 15:25 | Network scan: 15 machines on port 443 within a minute, mostly without answer | 15 unanswered tries while the laptop made some 2,900 connections in 5 minutes | a sweep needs most of the machines tried on that port to stay silent |
| 15:25 | Phishing look-up: `cdn.ampproject.org` | Google's AMP cache: news sites load its script | services that pages load in the background are never listed whole |
| 15:27 | Phishing look-up: `www.gravatar.com` (the list has `gravatar.com`) | Gravatar's profile pictures, shown on many sites | the same |

- **All 5 alerts were false alarms,** all from the laptop: 5 in 36 minutes of busy use, about 11 per 10,000 flows. Nothing was set off on purpose, and no device was infected.
- **The two look-ups are on the public list** because pages on those services were abused (Gravatar profiles, pages cached by Google's AMP cache). Of 117 common background services checked against the current list (fonts, analytics, ads, video, CDNs), only these two were flagged.
- **Each fix has a test made from its alert,** which fails on the old rules, and all of them were run on CIC-IDS2017 again (above): false alarms 162 → 144, every attack still caught.
- **Lighter use before:** about an hour of ordinary laptop use on 3 November (some 3,000 flows) brought no false alarm.

## Llama's explanations of network alerts (Pi 4, 2–3 November 2026)

`python -m advisor.warm_cache --net --fresh` on the Pi explains one sample of each alert kind, worded as the monitor writes them, plus every alert in the monitor's file. Each answer is written again, without the answer cache. Alerts that differ only in their addresses share a prompt, because addresses and names are replaced before Llama sees them. The latest run is in [advisor_net_review.md](advisor_net_review.md).

| | 2 November: 3 worked examples, 11 prompts | 3 November: 4 worked examples, 13 prompts |
| --- | --- | --- |
| Answers accepted by the checker | 11 of 11 | 13 of 13 |
| First explanation after a message (Llama reads the network examples from scratch) | 67.6 s, the first word after 52.2 s | 86.2 s, the first word after 67.4 s |
| The next ones (examples reused: 576 and 768 tokens) | 20.6–28.0 s | 21.0–31.0 s |
| The same alerts again (answer cache) | 0.1 s for all 11 | (not repeated) |
| Writing speed | 3.06–3.11 tokens/s | 2.91–2.94 tokens/s |

- **All answers stick to what the monitor saw,** for example: "A device on your Wi-Fi opened a fake website that uses SBI's name to steal a password, card details or OTP. Real Indian bank websites end in .bank.in, and this address is not SBI's official website."
- **The network-scan fact mattered.** With the first fact, which named only Mirai and Telnet, Llama blamed the laptop's port-443 "scan" on Mirai-type botnets. With the general fact (update 18) it says "which is how a worm or botnet infects more devices. Normal devices connect to a few servers, and those servers answer, so this is a warning sign to check."
- **The scam-link alert needed its own example.** The first live "Link from a scam message opened" was explained as a message "flagged as a scam by the device itself". With a fourth worked example and clearer words (update 23): "A device on your Wi-Fi opened the link from a scam message that came from a mobile number at 21:02, a fake page made to steal a password, card details or OTP." It cost 19 s on the first explanation after a message, and less than 0.2 tokens/s of writing speed.
- **Some answers are one sentence.** Llama ended them itself after about 35–45 tokens, well below the 72-token limit (estimated from each answer's writing time and speed). They say what happened but leave out the checked fact. The page shows the monitor's checked red flags under every answer anyway.
- **On the page,** the laptop's port-443 alert got its explanation in the background in 85 s: it waited behind the benchmark, which was running at the same time.

## CPU, memory and temperature on the Pi (3 November 2026)

`python scripts/pi_usage.py` sampled every 5 s for 23 minutes (278 samples), right after the services restarted. The lab Wi-Fi had light traffic: the laptop only. One message was checked on the page and explained by Llama (29.8 s, 3.23 tokens/s). CPU is a share of all four cores: 25% is one core fully busy.

| | CPU, average | CPU, peak | Memory, average | Memory, peak |
| --- | --- | --- | --- | --- |
| Network monitor | 0.1% | 0.5% | 550 MB (see below) | 550 MB |
| App | 0.1% | 19.6% (starting up) | 193 MB | 198 MB |
| Llama service | 4.1% | 96.2% | 1,248 MB | 1,249 MB |
| Whole Pi | 4.9% | 96.6% | at least 1,848 MB stayed free | |

- **Idle, the whole Pi used about 1% CPU.** `systemctl status` agreed: the monitor had used 13 s of CPU in about half an hour.
- **Llama is the only heavy part.** It kept all four cores at about 95% for some 50 s around the one check, and only then.
- **The monitor's 550 MB is counted high.** NFStream's capture runs as several processes that share memory, and the tool adds up each one's resident size. Raspberry Pi OS keeps per-service memory counting off, so `systemctl status` shows none.
- **Temperature:** 40–42 °C idle, 62 °C while Llama wrote, 73.5 °C just after Llama loaded at the restart. `vcgencmd get_throttled` was `0x80000`: the soft temperature limit was reached at least once since the Pi started, and no under-voltage. A heatsink or a small fan is advisable for long Llama use.

## Not measured yet

- **A second busy hour with update 27,** to show the fixes on the Pi itself.
- **False alarms per day** on the lab Wi-Fi over a whole day of normal use, and the **per-device normal** for small home devices over days. Tool: `scripts/net_traffic.py` ([docs/network-detector.md](../docs/network-detector.md#measure-it-on-real-traffic)).
- **The monitor's real memory:** the sum of each process's share (PSS) needs root, because the monitor holds capture capabilities.

## Reproduce

```bash
# CIC-IDS2017: download GeneratedLabelledFlows.zip from https://www.unb.ca/cic/datasets/ids-2017.html, unzip
python detectors/net/eval_net.py --data "TrafficLabelling "
# DGA model (about 3 minutes): the data file is in github.com/ExtraHop/DGA-Detection-Training-Dataset (Git LFS)
python detectors/net/train_dga.py --data dga-training-data-encoded.json.gz
```
