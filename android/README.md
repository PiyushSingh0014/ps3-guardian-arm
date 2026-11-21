# Sajag (सजग): the PS3 Guardian Android app

A small Android app that reads every incoming SMS **with its sender ID** (for example `JD-HDFCBK-S`, or a phone number), sends both to the Pi (`POST /sms`), and shows a scam alert when the Pi flags the message. The Pi logs each message so the detector can be measured on real traffic. When the Pi cannot be reached, the SMS is kept on the phone and sent once it can.

From version 3.0 (update 46) the app is called **Sajag**: Home, Alerts, Network and Settings, a screen for every alert, and a set-up in three steps ([docs/android-companion.md](../docs/android-companion.md), Part M). It also checks every message on the phone itself (Phone Guard) and explains alerts with Llama on the phone when the Pi cannot be reached ([docs/phone-guard.md](../docs/phone-guard.md)).

This folder is a complete Android Studio project (Kotlin, package `com.ps3guardian.app` (version 3.0, update 46), minimum Android 8.0 / API 26, target API 36, AGP 9.4, Gradle 9.6, WorkManager 2.12). Open this `android` folder in Android Studio (File → Open), connect the phone by USB and press Run ▶. Step-by-step instructions, including the phone settings: [`docs/android-companion.md`](../docs/android-companion.md).

| File (under `app/src/main/`) | What it does |
| --- | --- |
| `AndroidManifest.xml` | Permissions (receive SMS, internet, notifications) and the SMS receiver |
| `java/com/ps3guardian/app/SmsReceiver.kt` | Called by Android for every SMS: joins the parts of long messages, takes the raw sender ID |
| `Checker.kt` | Checks each message on the phone (Phone Guard), then sends it to the Pi; keeps it for later if the Pi cannot be reached; fills in its History entry and shows the alert |
| `History.kt` | Every checked message, newest first (at most 60), for Home, Alerts and the alert's own screen; the text only of flagged messages, links broken when shown |
| `FlushWorker.kt` | Background job: sends the SMS that waited for the Pi (every 15 minutes while any wait, when the app opens, and after any SMS the Pi answered) |
| `ChatListener.kt` | With "Notification access" allowed: reads chat notifications (Messages for RCS and MMS, WhatsApp; each switched on separately) from senders not in your contacts, and checks them like an SMS |
| `ChatApps.kt` | Which apps are read; takes the newest incoming message from a notification; tells a phone number (unknown sender) from a contact or business name |
| `Seen.kt` | Short hashes of recent SMS and checked chats, so a message is not checked twice |
| `PiClient.kt` | The calls to the Pi over HTTPS: `/health`, `/sms` (with the pairing token and the study switch), `/explain/{id}`, `/file`, `/check`, `/alerts`, `/devices` |
| `Tls.kt` | Trusts exactly the Pi's certificate confirmed when pairing (its SHA-256 fingerprint), nothing else |
| `ExplainWorker.kt` | Background job: waits for Llama's explanation on the Pi and updates the alert |
| `Notifier.kt` | The alert notification: "Dangerous · …", the explanation, **What to do** and **Call 1930** |
| `Settings.kt` | The Pi address, the pairing token, the phone name, the Pi's certificate fingerprint, the study and chat switches, the recent results, the messages waiting for the Pi (at most 500) |
| `MainActivity.kt`, `HomePage.kt`, `AlertsPage.kt`, `NetworkPage.kt`, `SettingsPage.kt`, `Rows.kt` | The four pages and the bar that switches them (`res/layout/activity_main.xml`, `page_*.xml`) |
| `AlertActivity.kt`, `ShareActivity.kt` | One alert's screen: verdict, what is happening, what to do, why, the message; a shared text or file opens on it too |
| `SetupActivity.kt`, `Helpers.kt` | The set-up (permissions, pairing, Llama) and the dialogs it shares with Settings |
| `Ui.kt`, `res/values/colors.xml`, `styles.xml`, `res/font/` | Colours (charcoal and ivory; red, yellow, green only for verdicts), type (Figtree; सजग in Rozha One, both SIL Open Font License, texts in `assets/licenses/`) and small helpers |
| `res/xml/network_security_config.xml` | No plain HTTP: the app talks to the Pi only over HTTPS |

The Gradle files come from Android Studio's *Empty Views Activity* template; the launcher icon is सजग's first letter, स, in Rozha One. `targetSdk` stays at 36 on purpose: apps targeting Android 17 (API 37) receive OTP-like SMS three hours late.

The app never sends, deletes or changes messages, and it talks only to the Pi. Chat messages (RCS, WhatsApp) never reach other apps as SMS; the app reads them from their notifications only when you switch that on, and only from senders who are not in your contacts.
