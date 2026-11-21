# Phone Guard: verdicts on the phone, without the Pi (update 43)

## Why

Until update 43 the phone app only read messages: the Pi decided. Away from the Pi's Wi-Fi, a message waited on the phone until it got home. Now PS3 Guardian has two parts, both on Arm hardware and neither using a cloud service:

| | Phone Guard (the Android phone) | Home Hub (the Raspberry Pi 4) |
| --- | --- | --- |
| Protects | its owner, anywhere: at home, on mobile data, with no network at all | every device on the home Wi-Fi: phones, laptops, smart plugs, cameras |
| Checks | SMS, chats from unknown numbers, links in them, text shared to the app | the same, plus files, the whole network's traffic, and the public phishing list |
| Explains | the playbook's advice: what it is, the red flags, the steps (1930) | the same, plus Llama 3.2 1B's two-sentence explanation |
| Acts | an alert at once | an alert, and the websites of dangerous messages blocked on its Wi-Fi |

When the phone is on the Pi's Wi-Fi, both judge each message: the phone at once, then the Pi, whose answer (with Llama's text) replaces the phone's alert while it is still on screen.

## What runs on the phone

The Pi's own checks, copied to Kotlin (`android/app/src/main/java/com/ps3guardian/app/guard/`):

- the text cleaning of the SMS model (`train_baseline.clean_text`: HTML entities, ftfy's simple fixes);
- the SMS text model (TF-IDF of character pieces and a logistic regression, trained on the same 6,053 public messages with the same script) and the India rules;
- the sender ID with TRAI's rules and the two sender rules switched on on the Pi (`cap`, `brand`);
- the link checker: link parsing with the Public Suffix List, official websites, brand imitation, short and chat links, free hosting, and the link model (the same file as the Pi's);
- the scam types and the 25 playbooks' steps.

Their data (patterns, lists, models, playbooks: 3.4 MB) is written into `android/app/src/main/assets/guard/` by `scripts/export_phone_guard.py`, from the same Python modules the Pi runs. `tests/test_phone_guard.py` fails if a rule, a list or a playbook changes on the Pi and the export is not run again.

**Stays on the Pi:** Llama 3.2 1B (a 1 GB model), the public phishing list (392,000 websites), the file checker and the network monitor. Without the list, the phone's link checker is the one measured "with no lists" in [eval/results_url.md](../eval/results_url.md): 81% of brand-new phishing sites flagged, 1.1% of popular websites called dangerous.

## Does the phone decide as the Pi does?

Checked on a computer: the phone's Kotlin code (run on the JVM by `android/guard-check/`) against the Pi's Python code (`scripts/check_phone_guard.py`), both without the phishing list and with the sender rules `cap` and `brand`. Same SMS model file, 16,272 test messages:

| Messages | How many | Same verdict | The same in every detail |
| --- | --- | --- | --- |
| India test set, each with its own sender and 8 other senders (none, business IDs, mobile numbers, a name) | 2,043 | 2,043 | 2,043 |
| Public messages (the 6,053 unique ones) | 6,053 | 6,053 | 6,053 |
| Hard cases ("hxxp", "@" trick, Google Translate and AMP links, redirects, IP addresses, punycode, Hindi, emoji, HTML entities), each with 8 senders | 176 | 176 | 168 |
| Links: 3,000 phishing domains, 2,000 popular websites, 3,000 held-out test domains, in 5 shapes | 8,000 | 8,000 | 8,000 |

"Every detail" is the verdict, the score to 3 decimals, the scam type, every reason in order, and every link's verdict, kind and reasons. The 8 that differ are one message written in mojibake on purpose ("Itâ€™s"): the Pi's ftfy repairs it and the phone does not (a phone receives proper Unicode), which changes the score a little but not the verdict.

**Speed:** on a laptop-class computer, loading takes about 0.2 s and a message about 0.7 ms. On the phone, the app writes the time of every check in its list ("on this phone, 3 ms").

## Install and test (update 43)

1. Copy the new `android` folder to the Android Studio computer (as in [android-companion.md](android-companion.md), Part B) and press **Run ▶** with the phone connected. It updates the app in place: settings, pairing and the list stay.
2. Open the app: under the title it says **Phone Guard is on**.
3. **Test without the Pi:** switch the phone's Wi-Fi off (mobile data may stay on). Tap **Send a test scam**: the alert comes at once, ending "(Checked on this phone.)", and the list shows "DANGEROUS (…) on this phone, N ms" and "the Pi did not answer". A real SMS from another phone gives the same.
4. **Back home:** switch Wi-Fi on. Messages kept while away go to the Pi (for Llama's explanation, the phishing list and the study's counts). An alert still on screen gets the Pi's text; one already dismissed is not shown again.

## Limits

- **No Llama on the phone yet,** so away from home the advice is the playbook's (what, red flags, steps), without the two-sentence explanation. ExecuTorch runs on Android, and the same model file could run on the phone: Phase 2.
- **No phishing list on the phone:** a reported phishing site that the rules and the link model miss is caught only by the Pi, when the phone is home. Phase 2: copy the list to the phone when it is home.
- **Files** shared to the app are checked only by the Pi.
- **Mojibake** is not repaired on the phone (see above).
- **The phone's own internet traffic** is not watched: the Pi watches the devices on its Wi-Fi. A local VPN on the phone could do it: Phase 2.
