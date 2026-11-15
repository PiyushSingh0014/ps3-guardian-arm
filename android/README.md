# PS3 Guardian Android companion

A small Android app that reads every incoming SMS **with its sender ID** (for example `JD-HDFCBK-S`, or a phone number), sends both to the Pi (`POST /sms`), and shows a scam alert when the Pi flags the message. The Pi logs each message so the detector can be measured on real traffic. When the Pi cannot be reached, the SMS is kept on the phone and sent once it can.

This folder is a complete Android Studio project (Kotlin, package `com.ps3guardian.app` (version 2.0, update 39), minimum Android 8.0 / API 26, target API 36, AGP 9.4, Gradle 9.6, WorkManager 2.12). Open this `android` folder in Android Studio (File → Open), connect the phone by USB and press Run ▶. Step-by-step instructions, including the phone settings: [`docs/android-companion.md`](../docs/android-companion.md).

| File (under `app/src/main/`) | What it does |
| --- | --- |
| `AndroidManifest.xml` | Permissions (receive SMS, internet, notifications) and the SMS receiver |
| `java/com/ps3guardian/app/SmsReceiver.kt` | Called by Android for every SMS: joins the parts of long messages, takes the raw sender ID |
| `Checker.kt` | Sends the SMS to the Pi, keeps a list of recent results, shows the alert; keeps the SMS for later if the Pi cannot be reached |
| `FlushWorker.kt` | Background job: sends the SMS that waited for the Pi (every 15 minutes while any wait, when the app opens, and after any SMS the Pi answered) |
| `ChatListener.kt` | With "Notification access" allowed: reads chat notifications (Messages for RCS and MMS, WhatsApp; each switched on separately) from senders not in your contacts, and checks them like an SMS |
| `ChatApps.kt` | Which apps are read; takes the newest incoming message from a notification; tells a phone number (unknown sender) from a contact or business name |
| `Seen.kt` | Short hashes of recent SMS and checked chats, so a message is not checked twice |
| `PiClient.kt` | The calls to the Pi over HTTPS: `/health`, `/sms` (with the pairing token and the study switch), `/explain/{id}`, `/file`, `/check`, `/alerts`, `/devices` |
| `Tls.kt` | Trusts exactly the Pi's certificate confirmed when pairing (its SHA-256 fingerprint), nothing else |
| `ExplainWorker.kt` | Background job: waits for Llama's explanation on the Pi and updates the alert |
| `Notifier.kt` | The alert notification |
| `Settings.kt` | The Pi address, the pairing token, the phone name, the Pi's certificate fingerprint, the study and chat switches, the recent results, the messages waiting for the Pi (at most 500) |
| `MainActivity.kt`, `res/layout/activity_main.xml` | One screen: address, token, phone name, the study switch, pairing with the Pi, permissions, chats, two tests, recent results (refreshed while open) |
| `res/xml/network_security_config.xml` | No plain HTTP: the app talks to the Pi only over HTTPS |

The rest (Gradle files, launcher icons, theme) is Android Studio's *Empty Views Activity* template. `targetSdk` stays at 36 on purpose: apps targeting Android 17 (API 37) receive OTP-like SMS three hours late.

The app never sends, deletes or changes messages, and it talks only to the Pi. Chat messages (RCS, WhatsApp) never reach other apps as SMS; the app reads them from their notifications only when you switch that on, and only from senders who are not in your contacts.
