# Guides

Every part of Sajag (PS3 Guardian) has a guide here. Start with the [README](../README.md) for the whole picture, the
[technical report](../report/sajag-phase1-report.pdf) for the approach and the algorithms, and
[status.md](status.md) for the state of every part.

## Set up and use

| Guide | What it covers |
| --- | --- |
| [android-companion.md](android-companion.md) | Installing the Sajag app, pairing it with the Home Hub, chats, more phones, the study switch, troubleshooting |
| [phone-guard.md](phone-guard.md) | The checks and Llama on the phone: how they work, why they agree with the hub, how to install and test |
| [esp32-lab-device.md](esp32-lab-device.md) | The ESP32 lab IoT device: wiring, flashing, its four harmless test modes |
| [dns-blocking.md](dns-blocking.md) | Blocking scam websites on the hub's Wi-Fi, and how to undo it |

## How each part works

| Guide | Part |
| --- | --- |
| [url-detector.md](url-detector.md) | Link checker: lists, rules, domain model |
| [sender-rules.md](sender-rules.md) | Sender ID rules (`cap`, `brand`, `suffix`) and how they were measured |
| [sms-model-v2.md](sms-model-v2.md) | SMS model v2 trained on the team's messages, and the rule it was judged by |
| [network-detector.md](network-detector.md) | Network monitor: flows, rules, DNS checks, each device's normal; the hub as a hotspot |
| [file-checker.md](file-checker.md) | File checker: APK, PDF, Office, zip and web files |
| [step3-fast-advisor.md](step3-fast-advisor.md) | The Llama advisor on the Pi 4: the C++ engine, the prompt, the cached prefix |

## Testing and results

| Guide | What it covers |
| --- | --- |
| [accuracy-test.md](accuracy-test.md) | The accuracy test: labelled sets, real messages, Llama v5 against v4, the live test on the phone |
| [llama-grading.md](llama-grading.md) | Grading Llama's sentences: the grounding checks and 100 graded answers |
| [india-sms-test-set.md](india-sms-test-set.md) | The India SMS test set: where its 227 messages come from |
| [iot23-replay.md](iot23-replay.md) | Replaying IoT-23's real IoT malware captures through the network monitor |

Measured results are in [results/](../results/README.md).

## History

| Guide | What it covers |
| --- | --- |
| [step2-vertical-slice.md](step2-vertical-slice.md) | The first end-to-end path: message, finding, advice, app (October 2026) |
| [status.md](status.md) | The state of every part, with the update that built it |
