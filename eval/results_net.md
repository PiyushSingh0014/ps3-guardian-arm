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

## Not measured yet

- **DNS checks** (phishing look-ups, DGA bursts, DNS tunnels) and the **per-device normal** for small home devices. They need real names and real devices. They are covered by tests now, and will be measured on the Pi's own network with the ESP32.
- **Speed on the Pi.** It will be measured with the monitor running there.

## Reproduce

```bash
# CIC-IDS2017: download GeneratedLabelledFlows.zip from https://www.unb.ca/cic/datasets/ids-2017.html, unzip
python detectors/net/eval_net.py --data "TrafficLabelling "
# DGA model (about 3 minutes): the data file is in github.com/ExtraHop/DGA-Detection-Training-Dataset (Git LFS)
python detectors/net/train_dga.py --data dga-training-data-encoded.json.gz
```
