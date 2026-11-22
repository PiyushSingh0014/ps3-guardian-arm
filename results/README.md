# Measured results

Every number in the README and the report comes from one of these files, and every file says which script made it.

| File | What was measured | Headline |
| --- | --- | --- |
| [results_accuracy.md](results_accuracy.md) | The accuracy test (22 November 2026): labelled sets, as the phone decides | 755 of 859 real Indian scam campaigns flagged (87.9%), never used to build Sajag; public held-out: 95.6% of scams, 1.2% of normal messages |
| [results_sms.md](results_sms.md) | The SMS checker: held-out public messages, the India test set, the team's real traffic, SMS model v2 | F1 0.950 held out; the real sender ID cuts false alarms on Indian messages |
| [results_url.md](results_url.md) | The link checker, held out by domain | 80.9% of brand-new phishing sites flagged with no lists; 1.1% of popular sites called dangerous |
| [results_net.md](results_net.md) | The network monitor: CIC-IDS2017, the lab Wi-Fi, IoT-23, Llama for network alerts, CPU and memory | 10 of 10 network-level attacks; 0 false alarms in 20,960 lab flows; 2 of 5 IoT-23 infected devices |
| [results_files.md](results_files.md) | The file checker: test files, 521 ordinary PDFs, the team's everyday files | 21 of 21 right; no false alarm on 521 PDFs |
| [results_pi4.md](results_pi4.md) | Llama 3.2 1B on the Raspberry Pi 4: load, prefix, speed per alert | 18-31 s per new explanation, repeats at once |

How to reproduce each one is at the end of its file. Llama on the phone and Phone Guard's agreement with the hub are in
[docs/phone-guard.md](../docs/phone-guard.md); the grading of Llama's sentences is in
[docs/llama-grading.md](../docs/llama-grading.md).
