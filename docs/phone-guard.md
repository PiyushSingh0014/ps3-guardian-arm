# Phone Guard: verdicts on the phone, without the Pi (update 43), and Llama there too (update 44)

## Why

Until update 43 the phone app only read messages: the Pi decided. Away from the Pi's Wi-Fi, a message waited on the phone until it got home. Now PS3 Guardian has two parts, both on Arm hardware and neither using a cloud service:

| | Phone Guard (the Android phone) | Home Hub (the Raspberry Pi 4) |
| --- | --- | --- |
| Protects | its owner, anywhere: at home, on mobile data, with no network at all | every device on the home Wi-Fi: phones, laptops, smart plugs, cameras |
| Checks | SMS, chats from unknown numbers, links in them, text shared to the app | the same, plus files, the whole network's traffic, and the public phishing list |
| Explains | the playbook's advice: what it is, the red flags, the steps (1930); away from the Pi, Llama 3.2 1B's two-sentence explanation, once Llama is copied from the Pi (update 44) | the same, with Llama 3.2 1B on the Pi |
| Acts | an alert at once | an alert, and the websites of dangerous messages blocked on its Wi-Fi |

When the phone is on the Pi's Wi-Fi, both judge each message: the phone at once, then the Pi, whose answer (with Llama's text) replaces the phone's alert while it is still on screen. When the Pi cannot be reached, Llama on the phone writes the explanation instead ([below](#llama-on-the-phone-update-44)).

## What runs on the phone

The Pi's own checks, copied to Kotlin (`android/app/src/main/java/com/ps3guardian/app/guard/`):

- the text cleaning of the SMS model (`train_baseline.clean_text`: HTML entities, ftfy's simple fixes);
- the SMS text model (TF-IDF of character pieces and a logistic regression, trained on the same 6,053 public messages with the same script) and the India rules;
- the sender ID with TRAI's rules and the two sender rules switched on on the Pi (`cap`, `brand`);
- the link checker: link parsing with the Public Suffix List, official websites, brand imitation, short and chat links, free hosting, and the link model (the same file as the Pi's);
- the scam types and the 25 playbooks' steps;
- Llama's prompt for messages and the checks on its answer (`advisor/prompt.py`, `advisor/validator.py`), for Llama on the phone (update 44).

Their data (patterns, lists, models, playbooks, Llama's prompt and checks: 3.5 MB) is written into `android/app/src/main/assets/guard/` by `scripts/export_phone_guard.py`, from the same Python modules the Pi runs. `tests/test_phone_guard.py` fails if a rule, a list, a playbook or the Llama prompt changes on the Pi and the export is not run again.

**Stays on the Pi:** the public phishing list (392,000 websites), the file checker, the network monitor and the explanations of network alerts. Llama's model (1 GB) is not in the app: the phone copies it from its own Pi (update 44). Without the list, the phone's link checker is the one measured "with no lists" in [eval/results_url.md](../eval/results_url.md): 81% of brand-new phishing sites flagged, 1.1% of popular websites called dangerous.

## Does the phone decide as the Pi does?

Checked on a computer: the phone's Kotlin code (run on the JVM by `android/guard-check/`) against the Pi's Python code (`scripts/check_phone_guard.py`), both without the phishing list and with the sender rules `cap` and `brand`. Same SMS model file, 16,272 test messages:

| Messages | How many | Same verdict | The same in every detail |
| --- | --- | --- | --- |
| India test set, each with its own sender and 8 other senders (none, business IDs, mobile numbers, a name) | 2,043 | 2,043 | 2,043 |
| Public messages (the 6,053 unique ones) | 6,053 | 6,053 | 6,053 |
| Hard cases ("hxxp", "@" trick, Google Translate and AMP links, redirects, IP addresses, punycode, Hindi, emoji, HTML entities), each with 8 senders | 176 | 176 | 168 |
| Links: 3,000 phishing domains, 2,000 popular websites, 3,000 held-out test domains, in 5 shapes | 8,000 | 8,000 | 8,000 |

"Every detail" is the verdict, the score to 3 decimals, the scam type, every reason in order, and every link's verdict, kind and reasons. The 8 that differ are one message written in mojibake on purpose ("Itâ€™s"): the Pi's ftfy repairs it and the phone does not (a phone receives proper Unicode), which changes the score a little but not the verdict.

**Speed:** on a laptop-class computer, loading takes about 0.2 s and a message about 0.7 ms. On the Galaxy S25, the app's list showed 2 to 11 ms per message (21 November: "SAFE (0.15) on this phone, 2 ms", "DANGEROUS (1.00) on this phone, 8 ms", "SUSPICIOUS (0.58) on this phone, 11 ms").

## Llama on the phone (update 44)

**Why:** away from the Pi's Wi-Fi, an alert had the playbook's advice but no plain-language explanation until the phone got home.

**How:**

- The app copies the Pi's own model files, `llama3_2.pte` and `tokenizer.model` (about 1 GB), from the paired Pi, over the pinned HTTPS connection with the pairing token (`GET /llama`, `app/llama_files.py`). It checks each file's SHA-256 against the Pi's and keeps them in its private storage. The model is never in the app or the repository.
- It runs them with ExecuTorch's Android library, release 1.5.1, the release the Pi's model was exported with (`org.pytorch:executorch-android`), on the phone's Arm CPU (XNNPACK). Greedy, as on the Pi; at most 64 new pieces of text in English and 160 in Hindi.
- Only when the Pi cannot be reached. The phone's alert comes at once; a few seconds later Llama's text replaces it while it is on screen, ending "(Explained by Llama 3.2 on this phone, in N s.)". At home the Pi explains, as before. **Share to PS3 Guardian** with a message's text does the same.
- Llama sees what it sees on the Pi: the scanner result, the scam type, the playbook's checked fact and the scammer's goal, the warning signs, and who the message claims to be (from the fixed list). Never the message text or the sender. Its answer passes the Pi's checks: a sentence with a number, a link, an organisation, a rule or a claim that the evidence does not have is dropped, and if nothing is left the playbook's text stays.
- The model is loaded for an alert and leaves the phone's memory after 3 minutes without one.

**The same prompt and checks as the Pi's**, compared on a computer (`scripts/check_phone_guard.py`, the phone's Kotlin code run by `android/guard-check/`):

| What | How many | The same on the phone |
| --- | --- | --- |
| Llama's prompt for each flagged test message that Llama would explain (the whole prompt, in English and in Hindi) | 8,833 | 8,833 |
| Who the message claims to be (all 16,272 test messages) | 16,272 | 16,272 |
| Answers through the answer checker: Llama's 100 graded answers from the Pi, the worked examples in both languages, and variants that add numbers, links, organisations, rules, hedges and contradictions or cut the answer short | 9,850 | 9,850 (what is shown, and every reason for dropping a sentence) |

**What can differ:** Llama's words. The phone's CPU does its arithmetic with other kernels than the Pi 4's, and at a near-tie greedy decoding can then pick another word, as seen between Arm and x86 builds ([step3-fast-advisor.md](step3-fast-advisor.md)); the checks hold either answer to the same evidence. The phone also counts pieces of text where the Pi counts tokens: a Devanagari letter can be a few tokens in one piece, so a Hindi answer can run a little longer before it is cut.

**Speed on the phone:** to be measured on the Galaxy S25. The app writes each explanation's numbers in its list: "Llama on this phone explained it in T s, L s of it loading the model; read P tokens in A s, wrote G in B s" (the last part comes from ExecuTorch's runner; the model is loaded only for the first alert in 3 minutes).

## Install and test (updates 43 and 44)

1. Update the Pi (update 44) and restart it: it now gives its Llama files to paired phones.
2. Copy the new `android` folder to the Android Studio computer (as in [android-companion.md](android-companion.md), Part B) and press **Run ▶** with the phone connected. It updates the app in place (version 2.2): settings, pairing and the list stay. The first build downloads ExecuTorch's library (about 8 MB).
3. Open the app: under the title it says **Phone Guard is on**.
4. **Copy Llama** (once, on the Pi's Wi-Fi, paired): tap **Get Llama from the Pi (about 1 GB)**, then **Copy**. Keep the screen open; it takes a few minutes and ends "Llama 3.2 1B is now on this phone (… MB), checked against the Pi's." If it stops, tap the button again: it goes on from where it stopped.
5. **Test without the Pi:** switch the phone's Wi-Fi off (mobile data may stay on). Tap **Send a test scam**: the alert comes at once, ending "(Checked on this phone.)", and the list shows "DANGEROUS (…) on this phone, N ms" and "the Pi did not answer". A few seconds later the alert's text becomes Llama's, ending "(Explained by Llama 3.2 on this phone, in N s.)", and the list shows "Llama on this phone explained it in N s, …" with the model's load time and the tokens read and written. A real SMS from another phone gives the same.
6. **Back home:** switch Wi-Fi on. Messages kept while away go to the Pi (for its phishing list, its Llama and the study's counts). An alert still on screen gets the Pi's text; one already dismissed is not shown again.

## Limits

- **Llama on the phone needs one copy from the Pi** (about 1 GB, on the Pi's Wi-Fi). Uninstalling the app deletes it; updating the app keeps it. Network alerts are explained only on the Pi: they are about the home network.
- **Llama's speed on the phone is not measured yet,** and its words can differ a little from the Pi's (see above).
- **No phishing list on the phone:** a reported phishing site that the rules and the link model miss is caught only by the Pi, when the phone is home. Phase 2: copy the list to the phone when it is home.
- **Files** shared to the app are checked only by the Pi.
- **Mojibake** is not repaired on the phone (see above).
- **The phone's own internet traffic** is not watched: the Pi watches the devices on its Wi-Fi. A local VPN on the phone could do it: Phase 2.
