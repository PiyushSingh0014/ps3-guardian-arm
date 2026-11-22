# File checker: results

How it works and how to use it: [docs/file-checker.md](../docs/file-checker.md).

## Harmless test files

`python home-hub/scripts/make_file_samples.py ~/ps3-file-samples` makes 21 files, then `python home-hub/scripts/check_files.py ~/ps3-file-samples` checks them. They were made for this project and carry the signs of harmful files and nothing else: no real app, macro, program or website is in them.

**All 21 as expected: 6 safe, 15 dangerous** (update 30; the first 19 since 7 November 2026, update 29).

| File | Imitates | Verdict | First reason |
| --- | --- | --- | --- |
| `ps3-test-ticket.pdf` | an ordinary PDF | safe | a real PDF: no hidden code, launch actions, hidden apps or dangerous links were found |
| `ps3-test-train-link.pdf` | a PDF with a link to IRCTC | safe | the same |
| `ps3-test-form.pdf` | a fillable form: an amount field formatted by Acrobat's own number helpers | safe | the same, and "the PDF is a form whose only scripts are Acrobat's own helpers for numbers, dates and totals" |
| `ps3-test-scan.pdf` | a scanned page whose picture bytes happen to contain `/JS (` and `/AA <<` | safe | the same |
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

- **What this shows:** every check works from the file's bytes to the advice, on the page, through `POST /file` and in the tests (`home-hub/tests/test_files.py`: these files, plus password-locked zips, encrypted PDFs, a member too big to unpack, a web page named `.pdf`, files inside PDFs, scripts behind other filters, broken PDFs, e-mail links, the chat rule for app file names, and that the log never keeps a file's name).
- **What it does not show:** how many real harmful files are caught. The test files are built to carry the signs; no real malware was used, and none should be copied to the Pi.

## Everyday files on the Pi (13 November 2026, updates 29 to 31)

The team's own files on the Pi, `python home-hub/scripts/check_files.py ~/normal-files --quiet`: 61 files, one of them over 25 MB (not checked). 60 checked in 2.6 s, reading included: about 43 ms per file.

| File type | Files | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- | --- |
| PDF | 37 | 31 | 6 | 0 |
| Word, Excel or PowerPoint | 9 | 9 | 0 | 0 |
| Photo or picture | 7 | 7 | 0 | 0 |
| Text | 6 | 2 | 0 | 4 |
| Old-style Office file | 1 | 1 | 0 | 0 |

- **The 4 dangerous files are right.** They are the team's own smishing datasets (CSV), lists of real scam messages with their links. They are not everyday files and are no false alarms.
- **The 6 suspicious PDFs** are an e-book, two IEEE papers, a KiCad schematic (twice, as a copy) and a lab report:
  - 4 for "hidden code (JavaScript)". Update 29 also read the PDF's stream data, its pictures, fonts and page text. Random bytes contain `/JS` about 0.06 times per MB and `/AA` 0.08 times (measured on 64 MB of random bytes), so a PDF with 10 MB of pictures has about a 45% chance of a "/JS" that is no key. Update 30 reads only the dictionaries. The rerun showed that this explained one of them; the other two do have scripts (below).
  - 2 for "carries another file inside it". That key is too long to appear by chance, so these PDFs do have a file inside. Update 30 checks such files like files of their own.
- **Copies:** some files were in the folder twice (`- Copy`). Since update 30, `check_files.py` counts copies once.

**The same folder with update 30** (13 November): 56 different files (4 copies left out, 1 too big), 0.8 s, 15 ms per file.

| File type | Files | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- | --- |
| PDF | 35 | 33 | 1 | 1 |
| Word, Excel or PowerPoint | 9 | 9 | 0 | 0 |
| Photo or picture | 7 | 7 | 0 | 0 |
| Text | 4 | 2 | 0 | 2 |
| Old-style Office file | 1 | 1 | 0 | 0 |

- **The 2 dangerous text files** are smishing datasets again: right.
- **Gone:** the IEEE paper's "JavaScript", most likely a chance match in its stream data. The two PDFs with a file inside are safe: the files inside were checked and are harmless.
- **The 2 PDFs still flagged have real scripts, and both are harmless.** `--details` showed them:
  - the e-book, suspicious: 521 scripts like `this.zoom=100;this.pageNum=162`, its table of contents as page jumps;
  - a KiCad schematic, dangerous: KiCad writes a document script that defines a menu function, and on every part a call like `ShM([["Reference designator = RV1"], ["Value = R_Potentiometer"], ...])`, which shows the part's details when clicked. Because the document script runs when the PDF opens, update 30 called it "runs hidden code as soon as it is opened".
- **Without the datasets, 54 everyday files: 52 safe, 2 flagged (3.7%), both for harmless scripts.** Update 31 recognises page jumps and KiCad's menus (KiCad 8 to 10), and a document script that only defines functions no longer counts as running on opening. With KiCad's own script text, KiCad 9 and 10 schematics come out safe, a changed menu function is suspicious, and a phishing address in a part's menu is dangerous.

**The same folder with update 31** (13 November): 56 different files, 1.1 s, 20 ms per file on the Pi.

| File type | Files | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- | --- |
| PDF | 35 | 34 | 1 | 0 |
| Word, Excel or PowerPoint | 9 | 9 | 0 | 0 |
| Photo or picture | 7 | 7 | 0 | 0 |
| Text | 4 | 2 | 0 | 2 |
| Old-style Office file | 1 | 1 | 0 | 0 |

- **The KiCad schematic is safe**, and the e-book's scripts count as harmless.
- **The e-book is still suspicious, now for a link.** One of its 86 web links has a name the link model finds unusual for a real company. That warning was there before too, behind the script warning (scores 0.6 and 0.65). The link model alone flags 7.6% of popular websites as suspicious ([results_url.md](results_url.md)), so a document with many links is more likely to get one. Since update 32, `--details` shows which website it is.

| Everyday files, without the smishing datasets | Safe | Suspicious | Dangerous |
| --- | --- | --- | --- |
| Update 29 (56 files, copies counted each time) | 50 | 6 | 0 |
| Update 30 (54 different files) | 52 | 1 | 1 |
| Update 31 (54 different files) | **53** | **1** (a link in an e-book) | **0** |

These are the files the fixes were made from, so the last row is not an independent measurement. The 521 PDFs below are: no false alarm with updates 30 and 31.

## Ordinary PDFs from other programs (update 29 against updates 30 and 31)

521 PDFs on the development machine: 501 different ones that came with it, mostly TeX Live's manuals (made by pdfTeX, LuaTeX, XeTeX and others), and 20 made for this test: LibreOffice with and without its document inside, Chromium, matplotlib with noisy pictures, and the same rewritten by qpdf with object streams and with encryption. 102 of the 521 use object streams.

| PDFs | Files | Update 29 | Update 30 |
| --- | --- | --- | --- |
| On the development machine | 501 | 2 dangerous: an e-mail link (`mailto:name@…`) read as a website hidden behind an "@" | 0 |
| Made for this test | 20 | 2 suspicious: LibreOffice's "hybrid PDF", which carries its own document inside | 0: the document inside is checked and found harmless |

- **Speed:** under 1 ms for most PDFs, 69 ms for the slowest (6.7 MB), on the development machine.
- None of the 521 had JavaScript, so the rule for Acrobat's form helpers was tested only on the made-up form.

## Harmful test files rewritten by another program

The harmful test PDFs were rewritten by qpdf, as another PDF writer would store them:

- **With object streams** (the script, the actions and the links moved into compressed object streams): the script that runs on opening, the launch action, the app inside and the phishing link are all still dangerous.
- **Encrypted** (AES-256 and RC4, opening without a password, as harmful PDFs sometimes are to hide from scanners): the script that runs on opening and the launch action are still dangerous, and the app inside is suspicious. The phishing link is missed: links are scrambled in an encrypted PDF, and since update 30 they are no longer read as noise. Every answer for an encrypted PDF says that only its outside could be checked.

## Not measured yet

- **Real chats:** whether WhatsApp's notification shows a document's name, which the warning for app files from saved contacts needs.
