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

| Day | Hours | Alerts | False alarms | of which beacons | others |
| --- | --- | --- | --- | --- | --- |
| Monday (normal traffic only) | 8.1 | 47 | 47 | 25 | 22 |
| Tuesday | 8.1 | 67 | 46 | 41 | 5 |
| Wednesday | 8.5 | 25 | 17 | 13 | 4 |
| Thursday morning | 4.0 | 8 | 8 | 7 | 1 |
| Thursday afternoon | 4.1 | 90 | 18 | 9 | 9 |
| Friday morning | 4.0 | 33 | 7 | 7 | 0 |
| Friday afternoon, port scan | 2.5 | 45 | 9 | 4 | 5 |
| Friday afternoon, DDoS | 1.5 | 22 | 10 | 10 | 0 |
| **Total** | **40.7** | **337** | **162** | **116** | **46** |

- **Not counting beacons:** 46 false alarms in 40.7 hours for about a dozen machines, roughly one per hour for the whole network.
  - Most are browsers that opened many connections that never answered (18 on Monday).
  - A few, on Thursday afternoon, look like real but unlabelled attack traffic, for example a scan from the attackers' gateway 172.16.0.1. They are still counted as false.
- **Beacon alerts are the weak point here, partly because of the data.** The CSV times are rounded to whole minutes, so any connection repeated about once a minute looks perfectly regular after rounding. On the Pi the monitor sees exact times and the server names (TLS), and it skips popular websites. This test cannot show how much that helps; the real-traffic week will.
- **41 alerts named the attackers' own machine outside the labelled times.** They are the infected PCs still calling the bot's controller on Friday afternoon, after the labelled Bot hour; CIC's labels call that traffic normal (Engelen et al. list such label gaps). They are counted neither as detections nor as false alarms.

### Before and after the Monday tuning

| | False alarms, Monday | False alarms, five days | Attacks detected |
| --- | --- | --- | --- |
| First run | 464 | 1,412 | 10 of 10 (any alert kind, looser matching) |
| Second run (reported) | 47 | 162 | 10 of 10 (the expected alert kind) |

The changes:

- **Machines that answer don't count toward a "sweep".** A browser opening many working connections is not a scan.
- **Server replies are not new connections.** A reply cut off into a flow of its own, from a service port to a client's temporary port, is ignored.
- **Floods are counted per target port, without DNS.** Look-ups to the company's name server are not a flood.
- **A big download alone is not an anomaly.**
- **Beacons need 10 check-ins at least 30 seconds apart.**
- **Empty packets are empty, even with CICFlowMeter's padding.**

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
- **The fix (update 18).** On live traffic, a network-scan try is now a new connection that got no answer or was refused. The same "new connections only" rule now applies to password guessing, so pauses in an SSH session are not logins. The CIC-IDS2017 numbers above are unchanged (checked: the same 162 false alarms and the same detections).

## Llama's explanations of network alerts (Pi 4, 2 November 2026)

`python -m advisor.warm_cache --net` on the Pi explained one sample of each of the 10 alert kinds, worded as the monitor writes them, plus the 2 alerts then in the monitor's file. That made 11 different prompts: the ESP32's beacon alert has the same prompt as the beacon sample, because addresses and names are replaced before Llama sees them.

It ran twice. The first run used the old network-scan fact. After update 18, a fresh run wrote every answer again, without the answer cache: [advisor_net_review.md](advisor_net_review.md).

| | Result |
| --- | --- |
| Answers accepted by the checker | 11 of 11, in both runs |
| First explanation after a message (692-token prompt; Llama reads the network examples, about 590 tokens, from scratch) | 67.6 s, the first word after 52.2 s |
| The next ones (576–640 tokens reused) | 20.6–28.0 s, the first word after 5.6–9.8 s |
| The same 11 again, from the answer cache (first run) | 0.1 s for all 11 |
| Writing speed | 3.06–3.11 tokens/s |

- **All answers stick to what the monitor saw,** for example: "A device on your Wi-Fi opened a fake website that uses SBI's name to steal a password, card details or OTP. Real Indian bank websites end in .bank.in, and this address is not SBI's official website."
- **The network-scan fact mattered.** In the first run, Llama blamed the laptop's port-443 "scan" on Mirai-type botnets: the playbook's checked fact named only Mirai and Telnet. With the general fact, the answer ends: "Normal devices connect to a few servers, and those answer, so this is a warning sign to check, not proof."
- **Weakest answer:** the Telnet scan (row 2) reads clumsily ("trying to connect to weak passwords or known flaws", "infect devices from infected cameras and routers"), though its facts are right.
- **Five answers are one sentence.** Llama ended them itself after about 35–45 tokens, well below the 72-token limit (estimated from each answer's writing time and speed). They say what happened but leave out the checked fact. The page shows the monitor's checked red flags under every answer anyway.
- **On the page,** the laptop's port-443 alert got its explanation in the background, in 85 s: it waited behind the benchmark, which was running at the same time.

## Not measured yet

- **A longer real-traffic count.** False alarms per day on the lab Wi-Fi after the beacon fix, and the **per-device normal** for small home devices.
- **Speed on the Pi.** It will be measured with the monitor running there.

## Reproduce

```bash
# CIC-IDS2017: download GeneratedLabelledFlows.zip from https://www.unb.ca/cic/datasets/ids-2017.html, unzip
python detectors/net/eval_net.py --data "TrafficLabelling "
# DGA model (about 3 minutes): the data file is in github.com/ExtraHop/DGA-Detection-Training-Dataset (Git LFS)
python detectors/net/train_dga.py --data dga-training-data-encoded.json.gz
```
