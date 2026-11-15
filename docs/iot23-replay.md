# Replaying real IoT malware traffic (IoT-23)

## Why

The network monitor was measured on CIC-IDS2017 (a company network, [eval/results_net.md](../eval/results_net.md)) and live on the lab Wi-Fi, where the only infected device was our own ESP32 running test modes the team wrote. The hard review (gap 2.6) asked for independent evidence: real IoT malware, captured by someone else. IoT-23 is that, and replaying it needs no attack tool, only files.

## The data

**IoT-23** (Garcia, Parmisano and Erquiaga, Stratosphere Laboratory, CTU Prague, 2020; [Zenodo, doi:10.5281/zenodo.4743746](https://zenodo.org/records/4743746); licence CC BY 4.0): 20 captures of a Raspberry Pi infected with real IoT malware (Mirai, Torii, Okiru, Hajime, Gagfyt, Hide and Seek, Muhstik and others) and 3 captures of real smart-home devices (a Philips Hue lamp, an Amazon Echo, a Somfy door lock). Each comes with its Zeek connection log, labelled flow by flow by the dataset's authors (`bro/conn.log.labeled`): `Benign`, or `Malicious` with a detailed label such as `PartOfAHorizontalPortScan`, `DDoS`, `C&C`, `C&C-HeartBeat`, `Attack`, `Okiru` or `FileDownload`.

## Download (on the Pi or the laptop)

```bash
cd ~/ps3-guardian
bash scripts/get_iot23.sh
```

It downloads the labelled logs of a default set, into `~/iot23/` (outside the repo): Mirai (34-1, 44-1), Torii (20-1), a trojan (42-1), Hakai (8-1), and the three smart-home devices (`hp-4-1`, `hp-5-1`, `hp-7-1`). It checks each file's size first and skips anything over 400 MB (`MAX_MB=1000 bash scripts/get_iot23.sh ...` allows more). Other scenarios: `bash scripts/get_iot23.sh 1-1 3-1`. The capture itself, for the full monitor path: `bash scripts/get_iot23.sh --pcap 34-1` (about 120 MB for 34-1).

## Run

```bash
source ~/ps3-venv/bin/activate
python -m detectors.net.replay ~/iot23/*
python -m detectors.net.replay --pcap ~/iot23/CTU-IoT-Malware-Capture-34-1
```

- **By default** each line of the labelled Zeek log becomes a flow: addresses, ports, packets, payload bytes, and the SYN and reset flags from Zeek's history string. The flows go through the same engine as the live monitor ([detectors/net/replay.py](../detectors/net/replay.py)), with a fresh state, no watch list and no DNS blocking. Zeek's connection log names no websites, so the checks on looked-up names (phishing sites, DGA names, DNS tunnels) do not run.
- **`--pcap`** reads the capture itself through NFStream, exactly as live, names included; the Zeek log then gives only the labels.
- Nothing is sent on any network, and nothing reaches the app's alert list. `--report eval/results_iot23.md` also writes a Markdown table.

## How it is scored

As for CIC-IDS2017:

- **A behaviour is detected** when an alert names an address that showed it (the infected Raspberry Pi) between the 5th and 95th percentile of its labelled flows in time, give or take 5 minutes. It is **fitting** when the alert's kind matches: a scan for `PartOfAHorizontalPortScan`, a flood for `DDoS`, a beacon or a risky port for `C&C`. The report also gives the time from the behaviour's first flow to the first alert.
- **False alarms:** on the three smart-home captures, every alert. On the malware captures, an alert that names no address with malicious flows. Alerts about the infected address outside its labelled periods are counted apart, because IoT-23 labels some of an infected device's traffic as benign.

## Limits

- **IoT-23's network is not the lab Wi-Fi.** Each capture holds one infected device and its traffic to the internet; there are no phones or laptops to cause false alarms, except in the three benign captures.
- **The first 2 hours of a device are its normal** (as live). A device infected from the first minute, as in many captures, has its controller learned as normal: beacons to it are not reported. The review named this weakness; the replay measures it.
- **The labels are the dataset's,** made by its authors from their knowledge of each capture.

Paste the output into the chat: the results go into [eval/results_net.md](../eval/results_net.md).
