# File checker: results

How it works and how to use it: [docs/file-checker.md](../docs/file-checker.md).

## Harmless test files (7 November 2026)

`python scripts/make_file_samples.py ~/ps3-file-samples` makes 19 files, then `python scripts/check_files.py ~/ps3-file-samples` checks them. They were made for this project and carry the signs of harmful files and nothing else: no real app, macro, program or website is in them.

**All 19 as expected: 4 safe, 15 dangerous**, in 0.1 s for all 19 on the development machine.

| File | Imitates | Verdict | First reason |
| --- | --- | --- | --- |
| `ps3-test-ticket.pdf` | an ordinary PDF | safe | a real PDF: no hidden code, launch actions, embedded files or dangerous links were found |
| `ps3-test-train-link.pdf` | a PDF with a link to IRCTC | safe | the same |
| `ps3-test-letter.docx` | an ordinary Word letter | safe | a real Office file: no macros, remote templates, hidden programs or dangerous links were found |
| `ps3-test-photo.png` | a photo | safe | a photo or picture: no hidden program was found |
| `ps3-test-kyc-link.pdf` | a "KYC" PDF with a link to a fake SBI website | dangerous | the document links to a dangerous website: the website address uses SBI's name, but it is not SBI's official website |
| `ps3-test-kyc-letter.docx` | the same in Word | dangerous | the same |
| `ps3-test-autorun.pdf` | JavaScript that runs when the PDF opens (it only shows a message box) | dangerous | the PDF runs hidden code (JavaScript) as soon as it is opened |
| `ps3-test-hidden-code.pdf` | the same, hidden in a compressed object stream and written `/J#61vaScript` | dangerous | the same |
| `ps3-test-launch.pdf` | a launch action (it names a program that does not exist) | dangerous | the PDF can start a program on your device |
| `ps3-test-attachment.pdf` | an app file inside a PDF | dangerous | the PDF hides an app or a program inside it |
| `ps3-test-macro.docm` | a macro (a placeholder without code) | dangerous | the document contains macros: small programs that run once you allow them |
| `ps3-test-remote-template.docx` | a template loaded from a made-up website | dangerous | the document loads a template from the internet when opened, a way to bring in harmful code |
| `ps3-test-dde.docx` | a DDE field | dangerous | the document asks Office to start a program (DDE) |
| `Wedding_Invitation.apk` | the "wedding invitation" app: a made-up manifest asking to read SMS and contacts and control the screen, no code | dangerous | the file is an Android app (APK), not a document or a photo |
| `Wedding_Invitation.pdf` | the same app, renamed `.pdf` | dangerous | the file says it is .pdf, but it is really an Android app (APK) |
| `Wedding_Card.pdf.apk` | the same app with a double ending | dangerous | the file is an Android app (APK), not a document or a photo |
| `ps3-test-photos.zip` | a zip "of photos" with the app inside | dangerous | the zip file holds an app or a program |
| `ps3-test-setup.exe` | a Windows program header, without code | dangerous | the file is a Windows program, not a document or a photo |
| `ps3-test-login.html` | a bank sign-in page saved as a file | dangerous | the file is a web page with a password box: a fake sign-in page that opens without any website |

- **What this shows:** every check works from the file's bytes to the advice, on the page, through `POST /file` and in the tests (`tests/test_files.py`: these files, plus password-locked zips and PDFs, a member too big to unpack, a web page named `.pdf`, the chat rule for app file names, and that the log never keeps a file's name).
- **What it does not show:** how many real harmful files are caught. The test files are built to carry the signs; no real malware was used, and none should be copied to the Pi.

## Not measured yet

- **False alarms on everyday files:** about 50 of the team's own PDFs, Office files and photos, checked on the Pi with `python scripts/check_files.py ~/normal-files --quiet`.
- **Time per file on the Pi:** the last line of the same command.
- **Real chats:** whether WhatsApp's notification shows a document's name, which the warning for app files from saved contacts needs.
