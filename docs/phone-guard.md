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

The Pi's own checks, copied to Kotlin (`phone-app/app/src/main/java/com/ps3guardian/app/guard/`):

- the text cleaning of the SMS model (`train_baseline.clean_text`: HTML entities, ftfy's simple fixes);
- the SMS text model (TF-IDF of character pieces and a logistic regression, trained on the same 6,053 public messages with the same script) and the India rules;
- the sender ID with TRAI's rules and the two sender rules switched on on the Pi (`cap`, `brand`);
- the link checker: link parsing with the Public Suffix List, official websites, brand imitation, short and chat links, free hosting, and the link model (the same file as the Pi's);
- the scam types and the 25 playbooks' steps;
- Llama's prompt for messages and the checks on its answer (`home-hub/advisor/prompt.py`, `home-hub/advisor/validator.py`), for Llama on the phone (update 44).

Their data (patterns, lists, models, playbooks, Llama's prompt and checks: 3.5 MB) is written into `phone-app/app/src/main/assets/guard/` by `home-hub/scripts/export_phone_guard.py`, from the same Python modules the Pi runs. `home-hub/tests/test_phone_guard.py` fails if a rule, a list, a playbook or the Llama prompt changes on the Pi and the export is not run again.

**Stays on the Pi:** the public phishing list (392,000 websites), the file checker, the network monitor and the explanations of network alerts. Llama's model (1 GB) is not in the app: the phone copies it from its own Pi (update 44). Without the list, the phone's link checker is the one measured "with no lists" in [results/results_url.md](../results/results_url.md): 81% of brand-new phishing sites flagged, 1.1% of popular websites called dangerous.

## Does the phone decide as the Pi does?

Checked on a computer: the phone's Kotlin code (run on the JVM by `phone-app/guard-check/`) against the Pi's Python code (`home-hub/scripts/check_phone_guard.py`), both without the phishing list and with the sender rules `cap` and `brand`. Same SMS model file, 16,272 test messages:

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

- The app copies the Pi's own model files, `llama3_2.pte` and `tokenizer.model` (about 1 GB), from the paired Pi, over the pinned HTTPS connection with the pairing token (`GET /llama`, `home-hub/app/llama_files.py`). It checks each file's SHA-256 against the Pi's and keeps them in its private storage. The model is never in the app or the repository.
- It runs them with ExecuTorch's Android library, release 1.5.1, the release the Pi's model was exported with (`org.pytorch:executorch-android`), on the phone's Arm CPU (XNNPACK). Greedy, as on the Pi; at most 80 new pieces of text in English and 192 in Hindi (64 and 160 before prompt v5).
- Only when the Pi cannot be reached. The phone's alert comes at once; a few seconds later Llama's text replaces it while it is on screen, ending "(Explained by Llama 3.2 on this phone, in N s.)". At home the Pi explains, as before. **Share to PS3 Guardian** with a message's text does the same.
- Llama sees what it sees on the Pi: the scanner result, the scam type, the playbook's checked fact and the scammer's goal, the warning signs, and who the message claims to be (from the fixed list). Since update 47 also what the message says, in fixed words (below). Never the message text or the sender. Its answer passes the Pi's checks: a sentence with a number, a link, an organisation, a rule or a claim that the evidence does not have is dropped, and if nothing is left the playbook's text stays.
- The model is loaded for an alert and leaves the phone's memory after 3 minutes without one.

**The same prompt and checks as the Pi's**, compared on a computer (`home-hub/scripts/check_phone_guard.py`, the phone's Kotlin code run by `phone-app/guard-check/`):

| What | How many | The same on the phone |
| --- | --- | --- |
| Llama's prompt for each flagged test message that Llama would explain (the whole prompt, in English and in Hindi) | 8,833 | 8,833 |
| Who the message claims to be (all 16,272 test messages) | 16,272 | 16,272 |
| Answers through the answer checker: Llama's 100 graded answers from the Pi, the worked examples in both languages, and variants that add numbers, links, organisations, rules, hedges and contradictions or cut the answer short | 9,850 | 9,850 (what is shown, and every reason for dropping a sentence) |

**What can differ:** Llama's words. The phone's CPU does its arithmetic with other kernels than the Pi 4's, and at a near-tie greedy decoding can then pick another word, as seen between Arm and x86 builds ([step3-fast-advisor.md](step3-fast-advisor.md)); the checks hold either answer to the same evidence. The phone also counts pieces of text where the Pi counts tokens: a Devanagari letter can be a few tokens in one piece, so a Hindi answer can run a little longer before it is cut.

**Speed on the Galaxy S25** (22 November, the test scam with the phone's Wi-Fi off; the numbers are the app's list lines, the token counts and times from ExecuTorch's runner):

| | Whole explanation | Loading the model | Reading the prompt (678 tokens) | Writing (54 tokens) |
| --- | --- | --- | --- | --- |
| First alert (model loaded for it) | 5.2 s | 1.3 s | 2.6 s (about 260 tokens/s) | 1.2 s |
| Next alert (model still loaded) | 3.6 s | — | 2.0 s (about 340 tokens/s) | 1.5 s (about 36 tokens/s) |

The Pi 4 takes 18–31 s for a new explanation, although it reuses the fixed start of the prompt; the phone reads the whole prompt each time and is still five to eight times faster. Llama's explanation of that test on the phone, as shown in the alert: "This message pretends to be from SBI to steal your net-banking login, card details or OTP through a fake KYC page. Genuine banks do not send links from 10-digit mobile numbers, and this link is not on an official .bank.in website."

As on the Pi, only flagged messages are explained: a message the phone judges safe gets no alert, so there is nothing for Llama to explain.

## What the message says (update 47)

**Why:** Llama saw the scam type and the warning signs, not the message, so every message of a type got much the same explanation: a message threatening to cut the electricity could be told it "pretends to be your bank".

**How:** `home-hub/detectors/sms/says.py` finds what the message itself claims (an account, card or SIM blocked, electricity cut off, a prize, a parcel, a refund, a job, a loan, police, an investment, reward points; in English or Hindi), the amount, a deadline, and what it asks (an OTP, paying, installing an app, calling someone, updating details, opening a link). It names each in fixed words, at most 4, in that order: "says your electricity will be cut off", "mentions ₹25,000", "asks you to pay money". Only flagged messages get them.

- Llama's case lists them under "The message:" (prompt v5, with new worked examples). Nothing the scammer wrote reaches Llama except an amount, and Llama's answer is still held to its case by the checks.
- The phone has the same patterns (exported to `sms.json`) and finds the same phrases, so Llama on the phone gets the same case.
- Until Llama's text arrives, the alert and its notification show them as one sentence: "The message says your bank account will be blocked, says you must act now, asks you to update or verify your details and has a link to open."
- An OTP is only "talked about": a bank's own OTP message uses the same words as a scam that asks for it, and the warning signs say which it is. "Rs.0" and "Rs. 0.45" are not amounts.

**How often:** 175 of the 201 different flagged messages in the India set get at least one phrase (98 get two or more); 725 of the 1,081 flagged messages in the public set.

**The same on the phone and the Pi, after v5** (the same comparison as above):

| Set | Messages | All the same | Llama prompts the same |
| --- | --- | --- | --- |
| India | 2,043 | 2,043 | 1,053 of 1,053 |
| Public | 6,053 | 6,053 | 570 of 570 |
| Edge cases | 176 | 168 (all 176 verdicts; the 8 are the known mis-encoded texts) | 137 of 137 |
| Links | 8,000 | 8,000 | 7,073 of 7,073 |

The 100 answers graded by hand ([llama-grading.md](llama-grading.md)) were written with prompt v4; v5's answers have to be graded again.

## Install and test (updates 43 and 44)

1. Update the Pi (update 44) and restart it: it now gives its Llama files to paired phones.
2. Copy the new `phone-app` folder to the Android Studio computer (as in [android-companion.md](android-companion.md), Part B) and press **Run ▶** with the phone connected. It updates the app in place (version 2.2): settings, pairing and the list stay. The first build downloads ExecuTorch's library (about 8 MB).
3. Open the app: under the title it says **Phone Guard is on**.
4. **Copy Llama** (once, on the Pi's Wi-Fi, paired): tap **Get Llama from the Pi (about 1 GB)** (in app 3.0: Settings → Explanations → **Add from your Home Hub**), then **Copy**. Keep the screen open; it takes a few minutes and ends "Llama 3.2 1B is now on this phone (… MB), checked against the Pi's." If it stops, tap the button again: it goes on from where it stopped.
5. **Test without the Pi:** switch the phone's Wi-Fi off (mobile data may stay on). Tap **Send a test scam** (in app 3.0: Settings → Advanced; its timings are at the bottom of the alert's screen and in Settings → Advanced → Activity log): the alert comes at once, ending "(Checked on this phone.)", and the list shows "DANGEROUS (…) on this phone, N ms" and "the Pi did not answer". A few seconds later the alert's text becomes Llama's, ending "(Explained by Llama 3.2 on this phone, in N s.)", and the list shows "Llama on this phone explained it in N s, …" with the model's load time and the tokens read and written. A real SMS from another phone gives the same.
6. **Back home:** switch Wi-Fi on. Messages kept while away go to the Pi (for its phishing list, its Llama and the study's counts). An alert still on screen gets the Pi's text; one already dismissed is not shown again.

## Limits

- **Llama on the phone needs one copy from the Pi** (about 1 GB, on the Pi's Wi-Fi). Uninstalling the app deletes it; updating the app keeps it. Network alerts are explained only on the Pi: they are about the home network.
- **Llama's words on the phone can differ a little from the Pi's** (see above). Its speed was measured on one phone, the S25, with the test scam.
- **The phone runs the Pi's model, Llama 3.2 1B,** although the S25 has room for Llama 3.2 3B (about 3.7 GB while running, too much for the Pi 4). Phase 2: 3B on the phone, if its graded answers on the same 100 cases are better at an acceptable speed. It stays on the phone's Arm CPU, through ExecuTorch.
- **No phishing list on the phone:** a reported phishing site that the rules and the link model miss is caught only by the Pi, when the phone is home. Phase 2: copy the list to the phone when it is home.
- **Files** shared to the app are checked only by the Pi.
- **Mojibake** is not repaired on the phone (see above).
- **The phone's own internet traffic** is not watched: the Pi watches the devices on its Wi-Fi. A local VPN on the phone could do it: Phase 2.
