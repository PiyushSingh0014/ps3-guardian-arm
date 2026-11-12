"""Is a file that came in a chat dangerous? Checked on the Pi, in memory, never stored.

What it looks at, none of which needs to understand the person's own content:
  * what the file really is, from its first bytes, against its name: an app (APK) or a program
    named like a PDF or a photo is disguised;
  * apps (APK): sent in a chat they are dangerous, and the permissions in the app's manifest say
    what it could do (read SMS: steal OTPs);
  * PDFs: the signs pdfid looks for (JavaScript and whether it runs on opening, launch
    commands, files inside, which are checked too), read from the dictionaries only, also in
    object streams and behind #xx-escaped names; Acrobat's own form helpers are no code; links;
  * Office files: macros, remote templates and objects, DDE, hidden programs, and its links;
  * archives (zip): what is inside, one level deep;
  * web pages saved as files (HTML, SVG): sign-in forms, scripts, links.
Links go through the link checker, like the links in an SMS. Reasons never contain the file's
name or a link: both are chosen by the sender, and reasons are passed to Llama.
"""
import base64
import io
import re
import zipfile
import zlib
from dataclasses import dataclass, field

from advisor.findings import Finding, verdict_from_score
from detectors.url.links import parse_link

from .names import APP_EXT, ARCHIVE_EXT, DOC_EXT, IMAGE_EXT, MEDIA_EXT, PROGRAM_EXT, WEB_EXT, extension, name_tricks

MAX_BYTES = 25 * 1024 * 1024          # bigger files are refused by the app (HTTP 413)
MAX_INFLATE = 50 * 1024 * 1024        # all decompressed data of one file: against zip bombs
MAX_MEMBER = 25 * 1024 * 1024
MAX_STREAMS = 400                     # object streams unpacked per PDF
MAX_LINKS = 20
MAX_REASONS = 4
MAX_SCRIPTS = 200                     # JavaScript values read per PDF
MAX_EMBEDDED = 20                     # files inside one PDF that are checked

TYPE_WORDS = {"pdf": "a PDF", "apk": "an Android app (APK)", "office": "a Word, Excel or PowerPoint file",
              "odf": "an OpenDocument file", "ole": "an old-style Office file", "jar": "a Java program",
              "exe": "a Windows program", "elf": "a Linux program", "script": "a script (a small program)",
              "zip": "a zip archive", "rar": "a RAR archive", "7z": "a 7-Zip archive", "image": "a photo or picture",
              "media": "a video or audio file", "html": "a web page", "svg": "an SVG picture", "text": "a text file",
              "unknown": "a file of a type the Pi does not know"}
DOC_TYPES = {"pdf", "office", "odf", "ole", "text"}
PICTURE_TYPES = {"image", "media"}
PROGRAM_TYPES = {"apk", "exe", "elf", "jar", "script"}

# What an app's permission lets it do, in words, for those that apps stealing OTPs and money need.
PERMISSIONS = {
    "READ_SMS": "read your SMS", "RECEIVE_SMS": "read your SMS", "SEND_SMS": "send SMS",
    "BIND_ACCESSIBILITY_SERVICE": "control your screen",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "read your notifications",
    "READ_CONTACTS": "read your contacts",
    "CALL_PHONE": "make calls", "READ_CALL_LOG": "see your calls", "PROCESS_OUTGOING_CALLS": "see your calls",
    "SYSTEM_ALERT_WINDOW": "draw over other apps",
    "REQUEST_INSTALL_PACKAGES": "install other apps",
    "BIND_DEVICE_ADMIN": "become a device administrator",
    "QUERY_ALL_PACKAGES": "see all your apps",
}

_PDF_KEYS = rb"/(JS|JavaScript|OpenAction|AA|Launch|EmbeddedFiles?|RichMedia|XFA|AcroForm|URI|SubmitForm|GoToE|GoToR|ObjStm|Encrypt)(?![A-Za-z0-9])"
_PDF_KEY_RE = re.compile(_PDF_KEYS)
_PDF_HEXNAME_RE = re.compile(rb"/[A-Za-z0-9]*#[0-9A-Fa-f]{2}[A-Za-z0-9#]*")
_PDF_STREAM_RE = re.compile(rb">>[ \t\r\n\f\x00]{0,20}stream(?:\r\n|\n|\r)")   # data follows its dictionary
_PDF_OBJ_RE = re.compile(rb"(?<![0-9])(\d{1,10})[ \t\r\n\f\x00]+\d{1,5}[ \t\r\n\f\x00]+obj(?![A-Za-z0-9])")
_PDF_OBJ_END_RE = re.compile(rb"(?<![0-9])(\d{1,10})[ \t\r\n\f\x00]+\d{1,5}[ \t\r\n\f\x00]+$")
_PDF_LENGTH_RE = re.compile(rb"/Length\s*(\d{1,10})\b(?!\s+\d+\s+R)")
_PDF_FILTER_RE = re.compile(rb"/Filter\s*(\[[^\]]{0,300}\]|/[A-Za-z0-9]+)")
_PDF_OBJSTM_RE = re.compile(rb"/Type\s*/ObjStm(?![A-Za-z0-9])")
_PDF_EMBEDDED_RE = re.compile(rb"/Type\s*/EmbeddedFile(?![A-Za-z0-9])")
_PDF_REF_RE = re.compile(rb"\s*(\d{1,10})\s+\d{1,5}\s+R(?![A-Za-z0-9])")
_PDF_DICT_RE = re.compile(rb"\s*<<")
_PDF_JS_KEY_RE = re.compile(rb"/JS(?![A-Za-z0-9])\s*")
_PDF_JS_ACTION_RE = re.compile(rb"/S\s*/JavaScript(?![A-Za-z0-9])")
_PDF_DOC_JS_RE = re.compile(rb"/JavaScript\s*(?:\d+\s+\d+\s+R|<<)")      # the document's own scripts
_PDF_OPEN_RE = re.compile(rb"/OpenAction(?![A-Za-z0-9])")
_PDF_AA_RE = re.compile(rb"/AA(?![A-Za-z0-9])")
_PDF_OPEN_KEY_RE = re.compile(rb"/(?:O|PO|PV)(?=\s*(?:\d|<<))")           # actions for "opened" or "shown"
_PDF_NEXT_RE = re.compile(rb"/Next(?![A-Za-z0-9])")
_PDF_EF_RE = re.compile(rb"/EF\s*<<(.{0,400}?)>>", re.S)
_PDF_EF_REF_RE = re.compile(rb"/(?:F|UF|DOS|Mac|Unix)\s*(\d{1,10})\s+\d{1,5}\s+R")
_PDF_ESCAPE_RE = re.compile(rb"\\(?:([nrtbf()\\])|([0-7]{1,3})|(\r\n|\n|\r))")
# Acrobat's own form helpers (AFNumber_Format(2, 0, 0, 0, "", true); and the like) with nothing but
# fixed values as arguments: they format numbers, dates and totals, and cannot run other code.
_JS_VALUE = r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|-?\d+(?:\.\d+)?|true|false|null)"""
_JS_VALUES = r"(?:" + _JS_VALUE + r"\s*(?:,\s*" + _JS_VALUE + r"\s*)*)?"
_JS_ARG = r"(?:" + _JS_VALUE + r"|new\s+Array\s*\(\s*" + _JS_VALUES + r"\)|\[\s*" + _JS_VALUES + r"\])"
_AF_CALL = (r"AF(?:Number|Percent|Date|Time|Special|Simple|Range)_[A-Za-z]+\s*\(\s*(?:" + _JS_ARG
            + r"\s*(?:,\s*" + _JS_ARG + r"\s*)*)?\)")
_AF_ONLY_RE = re.compile(r"\s*(?:" + _AF_CALL + r"\s*;?\s*)+")
_PDF_URI_RE = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){1,2000})\)")
_PDF_URI_HEX_RE = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]{2,4000})>")
_PDF_NAME_RE = re.compile(rb"/(?:UF|F)\s*\(((?:\\.|[^\\)]){1,300})\)")
_PERMISSION_RE = re.compile(r"android\.permission\.([A-Z_]{3,60})")
_REL_RE = re.compile(rb"<Relationship\b[^>]*>", re.I)
_ATTR_RE = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')
_DDE_RE = re.compile(rb"(?i)(?:<w:instrText[^>]*>\s*|instr=\"\s*)DDE(?:AUTO)?\b")
_PROGRAM_NAME_RE = re.compile(rb"(?i)[\w\- ]{1,80}\.(exe|scr|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|jar|lnk|apk|msi)\x00")
_NOT_WEB_RE = re.compile(r"(?i)(?:mailto|tel|sms|callto|fax|javascript|data|cid|geo|urn|news|file):")
_SCHEME_RE = re.compile(r"(?i)^(?!https?://)[a-z][a-z0-9+.-]{1,20}://")
_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s\"'<>()\]\[{}\\^`|]{3,500}")
_HREF_RE = re.compile(r"(?i)(?:href|action|src|xlink:href)\s*=\s*[\"']?(https?://[^\s\"'<>]{3,500})")


@dataclass
class Sign:
    score: float
    reason: str
    category: str


@dataclass
class _State:
    links: list = field(default_factory=list)          # URLs found, in order
    inflated: int = 0                                   # bytes decompressed so far
    notes: list = field(default_factory=list)          # things the check could not do
    evidence: list = field(default_factory=list)       # what was found, for check_files.py --details


def real_type(data):
    """What the file is, from its first bytes (the name does not count)."""
    head = data[:16]
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        try:
            names = set(zipfile.ZipFile(io.BytesIO(data)).namelist())
        except (zipfile.BadZipFile, ValueError, OSError):
            return "zip"
        if "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names):
            return "apk"
        if "[Content_Types].xml" in names:
            return "office"
        if "mimetype" in names:
            return "odf"
        if "META-INF/MANIFEST.MF" in names and any(n.endswith(".class") for n in names):
            return "jar"
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"MZ"):
        return "exe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if (head.startswith(b"\xff\xd8\xff") or head.startswith(b"\x89PNG\r\n\x1a\n") or head[:6] in (b"GIF87a", b"GIF89a")
            or (head.startswith(b"RIFF") and data[8:12] == b"WEBP") or data[4:12] in (b"ftypheic", b"ftypmif1", b"ftypheix")
            or (head.startswith(b"BM") and len(data) > 26 and data[14] in (12, 40, 108, 124))):
        return "image"
    if data[4:8] == b"ftyp" or head.startswith(b"ID3") or head.startswith(b"OggS") or head.startswith(b"\x1aE\xdf\xa3"):
        return "media"
    if b"%PDF-" in data[:1024]:                  # readers accept some bytes before the header
        return "pdf"
    sample = data[:4096].decode("utf-8", "ignore").lower()
    if "<svg" in sample:
        return "svg"
    if "<html" in sample or "<!doctype html" in sample or "<script" in sample or "<form" in sample:
        return "html"
    if sample.startswith("#!"):
        return "script"
    if data[:4096] and sum(b < 9 or 13 < b < 32 for b in data[:4096]) <= len(data[:4096]) // 50:
        return "text"                             # almost no control characters
    return "unknown"


def _type_of_ext(ext):
    if ext == "pdf":
        return "pdf"
    if ext in DOC_EXT:
        return "document"
    if ext in IMAGE_EXT | MEDIA_EXT:
        return "picture"
    if ext in APP_EXT:
        return "apk"
    if ext in PROGRAM_EXT:
        return "program"
    if ext in ARCHIVE_EXT:
        return "archive"
    if ext in WEB_EXT:
        return "web"
    return ""


class FileChecker:
    def __init__(self, url_detector=None):
        self.url = url_detector

    def check(self, data: bytes, name: str = "", language: str = "en", evidence=None) -> Finding:
        """evidence: a list to receive what was found inside (key counts, the start of a script)."""
        st = _State()
        kind = real_type(data)
        signs = self._signs(data, name, kind, st, depth=0)
        verdicts = self._link_signs(st)
        signs += verdicts["signs"]
        signs.sort(key=lambda s: -s.score)
        score = signs[0].score if signs else 0.05
        verdict = verdict_from_score(score)
        entities = {"file_type": TYPE_WORDS.get(kind, kind), "size_kb": round(len(data) / 1024)}
        if verdicts["links"]:
            entities["links"] = verdicts["links"]
        if verdicts["brand"]:
            entities["claims_to_be"], entities["claims_kind"] = verdicts["brand"]
        st.notes = list(dict.fromkeys(st.notes))
        if evidence is not None:
            evidence.extend(st.evidence)
        if verdict == "safe":
            reasons = [_safe_reason(kind)] + st.notes
            category = "none"
        else:
            reasons, seen = [], set()
            for s in signs:
                if s.score >= 0.5 and s.reason not in seen:
                    seen.add(s.reason)
                    reasons.append(s.reason)
            reasons = reasons[:MAX_REASONS] + st.notes[:1]
            category = signs[0].category
        return Finding(source="file", verdict=verdict, score=round(score, 3), category=category,
                       reasons=reasons, entities=entities, language=language)

    # --- the checks ----------------------------------------------------
    def _signs(self, data, name, kind, st, depth):
        signs = []
        ext = extension(name)
        claimed = _type_of_ext(ext)
        tricks = name_tricks(name)
        for t in tricks:
            signs.append(Sign(0.95, t, "app_file"))
        what = TYPE_WORDS.get(kind, "a file")
        if kind in PROGRAM_TYPES or (kind == "ole" and ext == "msi"):
            if claimed in ("pdf", "document", "picture", "web"):
                signs.append(Sign(0.98, f"the file says it is .{ext}, but it is really {what}", "app_file"))
            elif kind == "apk":
                signs.append(Sign(0.97, "the file is an Android app (APK), not a document or a photo", "app_file"))
            else:
                signs.append(Sign(0.95, f"the file is {what}, not a document or a photo", "app_file"))
        elif claimed in ("pdf", "document", "picture") and kind in ("html", "svg", "zip", "rar", "7z"):
            signs.append(Sign(0.85, f"the file says it is .{ext}, but it is really {what}", "harmful_document"))
        elif claimed in ("apk", "program") and kind not in PROGRAM_TYPES:
            signs.append(Sign(0.95, f"the file is named as a program or app (.{ext})", "app_file"))

        if kind == "apk":
            signs += self._apk(data)
        elif kind == "pdf":
            signs += self._pdf(data, st, depth)
        elif kind == "office":
            signs += self._office(data, st)
        elif kind == "odf":
            signs += self._odf(data, st)
        elif kind == "ole":
            signs += self._ole(data)
        elif kind == "zip":
            signs += self._zip(data, st, depth)
        elif kind in ("rar", "7z"):
            signs.append(Sign(0.5, f"the Pi cannot look inside {what}; archives like this are used to hide apps "
                                   "and programs", "harmful_document"))
        elif kind in ("html", "svg"):
            signs += self._web(data, kind, st)
        elif kind == "text":
            st.links += _URL_RE.findall(data[:2_000_000].decode("utf-8", "ignore"))
        return signs

    def _apk(self, data):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            info = z.getinfo("AndroidManifest.xml")
            manifest = z.read(info) if info.file_size <= MAX_MEMBER else b""
        except (KeyError, zipfile.BadZipFile, ValueError, OSError, RuntimeError, zlib.error, NotImplementedError):
            return []
        found = set()
        for text in (manifest.decode("utf-16-le", "ignore"), manifest[1:].decode("utf-16-le", "ignore"),
                     manifest.decode("latin-1")):
            found.update(_PERMISSION_RE.findall(text))
        words = []
        for p in PERMISSIONS:
            if p in found and PERMISSIONS[p] not in words:
                words.append(PERMISSIONS[p])
        if not words:
            return []
        words = words[:4]
        listed = words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]
        return [Sign(0.96, f"the app asks to {listed}: what apps that steal OTPs and money need", "app_file")]

    def _decode(self, head, raw, st, limit):
        """A stream's data unpacked (Flate, ASCIIHex, ASCII85, alone or chained), or None for
        other filters (pictures, encryption), data that does not unpack, or more than `limit`."""
        m = _PDF_FILTER_RE.search(head)
        out = raw
        for f in re.findall(rb"/([A-Za-z0-9]+)", m.group(1)) if m else []:
            if f in (b"FlateDecode", b"Fl"):
                room = min(limit + 1, MAX_INFLATE - st.inflated)
                if room <= 0:
                    return None
                try:
                    out = zlib.decompressobj().decompress(out, room)
                except zlib.error:
                    return None
                st.inflated += len(out)
            elif f in (b"ASCIIHexDecode", b"AHx"):
                hexed = re.sub(rb"[^0-9A-Fa-f]", b"", out.split(b">", 1)[0])
                out = bytes.fromhex((hexed + b"0" * (len(hexed) % 2)).decode())
            elif f in (b"ASCII85Decode", b"A85"):
                body = out.strip()
                body = (body[2:] if body.startswith(b"<~") else body).split(b"~>", 1)[0]
                try:
                    out = base64.a85decode(re.sub(rb"\s", b"", body))
                except ValueError:
                    return None
            else:
                return None
        return out if len(out) <= limit else None

    def _pdf(self, data, st, depth=0):
        # Keys, actions and links live in the PDF's dictionaries, never in stream data (pictures,
        # fonts, page text), whose random bytes would look like "/JS" or "/AA" by chance. So the
        # check reads the dictionaries, plus the objects packed in object streams.
        structure, streams = _pdf_split(data)
        packed, inside = {}, []
        for head, start, end in streams.values():
            if len(inside) >= MAX_STREAMS:
                break
            if not _PDF_OBJSTM_RE.search(_norm(head)):
                continue
            body = self._decode(head, data[start:end], st, MAX_MEMBER)
            if body:
                inside.append(body)
                for num, text in _objstm_objects(_norm(head), body):
                    packed.setdefault(num, text)
        raw = b"\n".join([structure] + inside)
        text = _norm(raw)
        objects = _PdfObjects(structure, packed)
        counts = {}
        for k in _PDF_KEY_RE.findall(text):
            key = k.decode()
            key = "EmbeddedFile" if key.startswith("EmbeddedFile") else key
            counts[key] = counts.get(key, 0) + 1
        locked = bool(counts.get("Encrypt"))         # its strings are scrambled: links would be noise
        for u in [] if locked else _PDF_URI_RE.findall(raw):
            st.links.append(_pdf_string(u))
        for u in [] if locked else _PDF_URI_HEX_RE.findall(raw):
            try:
                st.links.append(bytes.fromhex(re.sub(rb"\s", b"", u).decode()).decode("latin-1"))
            except ValueError:
                pass
        signs = []
        script, first = "none", ""
        if counts.get("JS") or counts.get("JavaScript"):
            script, first = self._pdf_scripts(text, objects, streams, data, st)
        on_open = script == "code" and _pdf_runs_on_open(text, objects)
        if counts.get("Launch"):
            signs.append(Sign(0.95, "the PDF can start a program on your device", "harmful_document"))
        if on_open:
            signs.append(Sign(0.9, "the PDF runs hidden code (JavaScript) as soon as it is opened", "harmful_document"))
        elif script == "code":
            signs.append(Sign(0.65, "the PDF contains hidden code (JavaScript)", "harmful_document"))
        elif script == "form":
            st.notes.append("the PDF is a form whose only scripts are Acrobat's own helpers for numbers, dates "
                            "and totals")
        inner = []
        if counts.get("EmbeddedFile"):
            names = [_pdf_string(r) for r in _PDF_NAME_RE.findall(raw)]
            app = any(extension(x) in APP_EXT | PROGRAM_EXT for x in names)
            if app:
                signs.append(Sign(0.95, "the PDF hides an app or a program inside it", "app_file"))
            inner = self._pdf_embedded(text, streams, data, st, depth, signs)
            if not inner and not app:
                signs.append(Sign(0.6, "the PDF carries another file inside it", "harmful_document"))
        if counts.get("RichMedia"):
            signs.append(Sign(0.6, "the PDF contains embedded media that can run code", "harmful_document"))
        if counts.get("SubmitForm"):
            signs.append(Sign(0.55, "the PDF has a form that sends what you type to a website", "phishing_document"))
        if counts.get("GoToE") or counts.get("GoToR"):
            signs.append(Sign(0.5, "the PDF opens another file when you click it", "harmful_document"))
        if locked:
            st.notes.append("the PDF is encrypted, so only its outside could be checked")
        line = "PDF keys: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "none")
        if script != "none":
            line += f"; scripts: {script}" + (", run on opening" if on_open else "")
            if first:
                line += ", first: " + " ".join(first.split())[:80]
        if inner:
            line += "; inside: " + ", ".join(TYPE_WORDS.get(k, k) for k in inner)
        st.evidence.append(line)
        return signs

    def _pdf_scripts(self, text, objects, streams, data, st):
        """What the PDF's JavaScript is: 'form' when every script is one of Acrobat's own form
        helpers (AFNumber_Format and the like, which only format numbers, dates and totals),
        'code' when there is other code or a script that could not be read, 'none' when all are
        empty. Also the start of the first other code, for check_files.py --details."""
        codes, unread = [], False
        for m in _PDF_JS_KEY_RE.finditer(text):
            if len(codes) >= MAX_SCRIPTS:
                break
            value = self._pdf_value(text, m.end(), objects, streams, data, st)
            if value is None:
                unread = True
            else:
                codes.append(value)
        if not codes:
            unread = True                       # /JavaScript, but no script that could be read
        texts = [t for t in (_js_text(c).strip() for c in codes) if t]
        other = [t for t in texts if not _AF_ONLY_RE.fullmatch(t)]
        if unread or other:
            return "code", (other[0] if other else "")
        return ("form" if texts else "none"), ""

    def _pdf_value(self, text, i, objects, streams, data, st, hops=0):
        """The string at text[i]: (literal), <hex>, or a reference to a string or a stream."""
        c = text[i:i + 1]
        if c == b"(":
            return _pdf_literal(text, i)
        if c == b"<" and text[i + 1:i + 2] != b"<":
            j = text.find(b">", i)
            hexed = re.sub(rb"[^0-9A-Fa-f]", b"", text[i + 1:j if j >= 0 else i + 1])
            return bytes.fromhex((hexed + b"0" * (len(hexed) % 2)).decode())
        r = _PDF_REF_RE.match(text, i)
        if r is None or hops > 1:
            return None
        num = int(r.group(1))
        if num in streams:
            head, start, end = streams[num]
            return self._decode(head, data[start:end], st, 2 * 1024 * 1024)
        obj = objects.get(num)
        k = len(obj) - len(obj.lstrip())
        return self._pdf_value(obj, k, objects, streams, data, st, hops + 1) if obj.strip() else None

    def _pdf_embedded(self, text, streams, data, st, depth, signs):
        """The files inside a PDF, checked like files of their own (one level deep): an app,
        a document with macros or a fake sign-in page is found inside, and a harmless file
        (LibreOffice puts the document itself in a "hybrid PDF") is no warning. Returns the kinds."""
        if depth > 0:
            return []
        nums = [int(x) for ef in _PDF_EF_RE.findall(text) for x in _PDF_EF_REF_RE.findall(ef)]
        nums += [k for k, (head, _, _) in streams.items() if _PDF_EMBEDDED_RE.search(_norm(head))]
        kinds, seen = [], set()
        for num in nums:
            if num in seen or num not in streams or len(seen) >= MAX_EMBEDDED:
                continue
            seen.add(num)
            head, start, end = streams[num]
            body = self._decode(head, data[start:end], st, MAX_MEMBER)
            if body is None:
                continue
            kind = real_type(body) if body else "empty"
            kinds.append(kind)
            if not body:
                continue
            found = self._signs(body, "", kind, st, depth=1)
            signs += [Sign(s.score, "inside the PDF: " + s.reason, s.category) for s in found]
            if kind == "unknown":
                signs.append(Sign(0.6, "the PDF carries another file inside it, of a type the Pi does not know",
                                  "harmful_document"))
            elif not found:
                st.notes.append(f"the PDF carries {TYPE_WORDS.get(kind, 'a file')} inside it, which was checked too")
        return kinds

    def _zip_read(self, z, info, st):
        if info.file_size > MAX_MEMBER or st.inflated + info.file_size > MAX_INFLATE or info.flag_bits & 0x1:
            return None
        try:
            out = z.read(info)
        except (zipfile.BadZipFile, ValueError, OSError, RuntimeError, zlib.error, NotImplementedError):
            return None
        st.inflated += len(out)
        return out

    def _office(self, data, st):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            infos = z.infolist()[:2000]
        except (zipfile.BadZipFile, ValueError, OSError):
            return []
        signs = []
        names = [i.filename for i in infos]
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            signs.append(Sign(0.9, "the document contains macros: small programs that run once you allow them",
                              "harmful_document"))
        for info in infos:
            n = info.filename.lower()
            if n.endswith(".rels"):
                body = self._zip_read(z, info, st) or b""
                for rel in _REL_RE.findall(body):
                    attrs = {k.decode().lower(): v.decode("utf-8", "ignore") for k, v in _ATTR_RE.findall(rel)}
                    typ, external = attrs.get("type", ""), attrs.get("targetmode", "").lower() == "external"
                    if not external:
                        continue
                    if typ.endswith("/attachedTemplate"):
                        signs.append(Sign(0.95, "the document loads a template from the internet when opened, a way "
                                                "to bring in harmful code", "harmful_document"))
                    elif typ.endswith("/oleObject") or typ.endswith("/frame"):
                        signs.append(Sign(0.9, "the document loads an object from the internet when opened",
                                          "harmful_document"))
                    elif typ.endswith("/hyperlink"):
                        st.links.append(attrs.get("target", ""))
            elif n.endswith("document.xml") or n.endswith(".xml") and n.startswith(("xl/worksheets/", "ppt/slides/")):
                body = self._zip_read(z, info, st) or b""
                if _DDE_RE.search(body):
                    signs.append(Sign(0.9, "the document asks Office to start a program (DDE)", "harmful_document"))
            elif "/embeddings/" in n and "oleobject" in n:
                body = self._zip_read(z, info, st) or b""
                if _PROGRAM_NAME_RE.search(body):
                    signs.append(Sign(0.95, "the document hides a program inside an embedded object", "app_file"))
        return signs

    def _odf(self, data, st):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            infos = z.infolist()[:2000]
        except (zipfile.BadZipFile, ValueError, OSError):
            return []
        signs = []
        if any(i.filename.startswith(("Basic/", "Scripts/")) for i in infos):
            signs.append(Sign(0.9, "the document contains macros: small programs that run once you allow them",
                              "harmful_document"))
        for info in infos:
            if info.filename == "content.xml":
                body = (self._zip_read(z, info, st) or b"").decode("utf-8", "ignore")
                st.links += _HREF_RE.findall(body)
        return signs

    def _ole(self, data):
        if b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T\x00" in data[:MAX_MEMBER]:
            return [Sign(0.9, "the document contains macros: small programs that run once you allow them",
                         "harmful_document")]
        return []

    def _zip(self, data, st, depth):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            infos = z.infolist()[:2000]
        except (zipfile.BadZipFile, ValueError, OSError):
            return [Sign(0.5, "the zip file is damaged, so the Pi could not look inside", "harmful_document")]
        signs = []
        if any(i.flag_bits & 0x1 for i in infos):
            signs.append(Sign(0.6, "the zip file is locked with a password, a trick to slip harmful files past "
                                   "checks", "harmful_document"))
        if any(extension(i.filename) in APP_EXT | PROGRAM_EXT for i in infos):
            signs.append(Sign(0.98, "the zip file holds an app or a program", "app_file"))
        if depth == 0:
            checked = 0
            for info in infos:
                if checked >= 20 or info.is_dir():
                    continue
                if _type_of_ext(extension(info.filename)) not in ("pdf", "document", "web", "apk", "program"):
                    continue
                body = self._zip_read(z, info, st)
                if not body:
                    continue
                checked += 1
                inner = self._signs(body, info.filename, real_type(body), st, depth=1)
                signs += [Sign(s.score, "inside the zip: " + s.reason, s.category) for s in inner]
        return signs

    def _web(self, data, kind, st):
        text = data[:2_000_000].decode("utf-8", "ignore")
        low = text.lower()
        st.links += _HREF_RE.findall(text)
        st.links += re.findall(r"(?i)http-equiv\s*=\s*[\"']?refresh[^>]*url\s*=\s*(https?://[^\s\"'>]+)", text)
        signs = []
        if kind == "svg":
            if "<script" in low or re.search(r"\son\w+\s*=", low):
                signs.append(Sign(0.8, "the picture (SVG) contains code", "harmful_document"))
            return signs
        password = bool(re.search(r"<input[^>]+type\s*=\s*[\"']?password", low))
        if password:
            signs.append(Sign(0.9, "the file is a web page with a password box: a fake sign-in page that opens "
                                   "without any website", "phishing_document"))
        if re.search(r"\b(atob|unescape|fromcharcode|eval)\s*\(", low) or re.search(
                r"(window\.|document\.)?location(\.href|\.replace)?\s*[=(]", low):
            signs.append(Sign(0.75, "the web page runs code that can send you to another website",
                              "harmful_document"))
        elif "<script" in low:
            signs.append(Sign(0.6, "the file is a web page that runs code", "harmful_document"))
        elif "<form" in low and not password:
            signs.append(Sign(0.6, "the file is a web page with a form that sends what you type away",
                              "phishing_document"))
        return signs

    def _link_signs(self, st):
        out = {"signs": [], "links": [], "brand": None}
        if self.url is None or not st.links:
            return out
        seen, worst = set(), None
        for raw in st.links:
            u = (raw or "").strip().strip(".,;")
            if not u or len(seen) >= MAX_LINKS or _NOT_WEB_RE.match(u):
                continue                                  # an e-mail address or a phone number is no website
            u = _SCHEME_RE.sub("http://", u, count=1)     # ftp://host and the like: judge the host
            link = parse_link(u if re.match(r"(?i)https?://", u) else "http://" + u)
            if link is None or link.registered in seen:
                continue
            seen.add(link.registered)
            v = self.url.check_link(link)
            out["links"].append({"link": v.shown(), "verdict": v.verdict, "kind": v.kind})
            if worst is None or v.score > worst.score:
                worst = v
        if worst is not None and worst.verdict != "safe":
            why = worst.reasons[0] if worst.reasons else "it looks like a fake website"
            if worst.verdict == "dangerous":
                out["signs"].append(Sign(max(0.9, worst.score), "the document links to a dangerous website: " + why,
                                         "phishing_document"))
            else:
                out["signs"].append(Sign(0.6, "the document links to a suspicious website: " + why,
                                         "phishing_document"))
            if worst.imitates:
                out["brand"] = (worst.brand, worst.brand_kind)
        return out


def _unhex_name(token):
    """'/J#61vaScript' -> '/JavaScript' (PDF names may hide letters as #xx)."""
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), token)


def _pdf_unescape(raw):
    """The bytes of a PDF literal string, its escapes undone (\\n, \\(, \\101, line breaks)."""
    def one(m):
        if m.group(1):
            return {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}.get(m.group(1), m.group(1))
        if m.group(2):
            return bytes([int(m.group(2), 8) & 0xFF])
        return b""
    return _PDF_ESCAPE_RE.sub(one, raw)


def _pdf_string(raw):
    """The text of a PDF (literal) string: escapes undone, as Latin-1."""
    return _pdf_unescape(raw).decode("latin-1")


def _pdf_literal(data, i, limit=500_000):
    """The PDF string that starts with '(' at data[i]: brackets inside may nest, escapes undone."""
    depth, j, end = 0, i, min(len(data), i + limit)
    while j < end:
        c = data[j]
        if c == 0x5C:                               # a backslash escapes the next byte
            j += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                break
        j += 1
    return _pdf_unescape(data[i + 1:j])


def _js_text(code):
    """A script's text: PDF strings are Latin-1, or UTF-16 after a byte-order mark."""
    if code[:2] == b"\xfe\xff":
        return code[2:].decode("utf-16-be", "ignore")
    if code[:2] == b"\xff\xfe":
        return code[2:].decode("utf-16-le", "ignore")
    return code.decode("latin-1")


def _norm(text):
    """PDF names with #xx escapes written out: '/J#61vaScript' -> '/JavaScript'."""
    return _PDF_HEXNAME_RE.sub(lambda m: _unhex_name(m.group(0)), text) if b"#" in text else text


def _pdf_split(data):
    """A PDF without its stream data, and where each stream's data is: {object number:
    (dictionary, start, end)}. A stream starts right after its dictionary ('>> stream') and
    ends after /Length bytes, or at 'endstream' when /Length does not fit."""
    out, streams, pos = [], {}, 0
    for m in _PDF_STREAM_RE.finditer(data):
        if m.start() < pos:                          # inside the previous stream's data
            continue
        dict_end = m.start() + 2
        at = data.rfind(b"obj", pos, dict_end)
        num = None
        if at >= 0:
            k = _PDF_OBJ_END_RE.search(data[max(pos, at - 40):at])
            num = int(k.group(1)) if k else None
        head = data[at + 3 if at >= 0 else max(pos, dict_end - 4000):dict_end]
        start, end = m.end(), -1
        n = _PDF_LENGTH_RE.search(head)
        if n:
            e = start + int(n.group(1))
            if data[e:e + 40].lstrip(b" \t\r\n\f\x00").startswith(b"endstream"):
                end = e
        if end < 0:
            end = data.find(b"endstream", start)
            end = len(data) if end < 0 else end
        out.append(data[pos:dict_end])
        if num is not None:
            streams[num] = (head, start, end)
        pos = end
    out.append(data[pos:])
    return b"".join(out), streams


class _PdfObjects:
    """A PDF object by its number: from the file (the last one wins, as with later edits) or
    from an object stream. Its text, with #xx names written out; empty if not found."""

    def __init__(self, structure, packed):
        self.structure, self.packed, self.index, self.cache = structure, packed, None, {}

    def get(self, num):
        if num in self.cache:
            return self.cache[num]
        if self.index is None:
            self.index = {int(m.group(1)): m.end() for m in _PDF_OBJ_RE.finditer(self.structure)}
        at = self.index.get(num)
        if at is not None:
            end = self.structure.find(b"endobj", at, at + 200_000)
            text = self.structure[at:end if end >= 0 else at + 200_000]
        else:
            text = self.packed.get(num, b"")
        self.cache[num] = text = _norm(text)
        return text


def _objstm_objects(head, body):
    """The objects packed in an object stream: [(number, text)]."""
    first, count = re.search(rb"/First\s+(\d{1,10})", head), re.search(rb"/N\s+(\d{1,7})", head)
    if not first or not count:
        return []
    first = int(first.group(1))
    nums = [int(x) for x in re.findall(rb"\d+", body[:first])[:2 * int(count.group(1))]]
    out = []
    for i in range(0, len(nums) - 1, 2):
        start = first + nums[i + 1]
        end = first + nums[i + 3] if i + 3 < len(nums) else len(body)
        if start < end <= len(body):
            out.append((nums[i], body[start:end]))
    return out


def _pdf_dict_at(text, i, objects):
    """The dictionary at text[i]: written there (up to its first '>>') or the object it names."""
    r = _PDF_REF_RE.match(text, i)
    if r:
        return objects.get(int(r.group(1)))
    d = _PDF_DICT_RE.match(text, i)
    if d:
        end = text.find(b">>", d.end(), d.end() + 20_000)
        return text[d.end():end if end >= 0 else d.end() + 20_000]
    return b""


def _pdf_is_script(text, i, objects):
    """Is the action at text[i] JavaScript, or followed by JavaScript (its /Next)?"""
    action = _pdf_dict_at(text, i, objects)
    for _ in range(3):
        if _PDF_JS_ACTION_RE.search(action):
            return True
        n = _PDF_NEXT_RE.search(action)
        if not n:
            return False
        rest = action[n.end():n.end() + 400].lstrip()
        if rest.startswith(b"["):
            refs = re.findall(rb"(\d{1,10})\s+\d{1,5}\s+R", rest.split(b"]", 1)[0])[:10]
            return any(_PDF_JS_ACTION_RE.search(objects.get(int(x))) for x in refs)
        action = _pdf_dict_at(action, n.end(), objects)
    return False


def _pdf_runs_on_open(text, objects):
    """Does a script run by itself when the PDF opens: the document's own scripts (its
    /JavaScript name tree), the OpenAction, or a page or field action for 'opened' or 'shown'
    (/O, /PO, /PV)? Actions for typing in a field or for printing do not count."""
    if _PDF_DOC_JS_RE.search(text):
        return True
    if any(_pdf_is_script(text, m.end(), objects) for m in _PDF_OPEN_RE.finditer(text)):
        return True
    for n, m in enumerate(_PDF_AA_RE.finditer(text)):
        if n >= 2000:
            break
        actions = _pdf_dict_at(text, m.end(), objects)
        if any(_pdf_is_script(actions, k.end(), objects) for k in _PDF_OPEN_KEY_RE.finditer(actions)):
            return True
    return False


def _safe_reason(kind):
    return {"pdf": "a real PDF: no hidden code, launch actions, hidden apps or dangerous links were found",
            "office": "a real Office file: no macros, remote templates, hidden programs or dangerous links were found",
            "odf": "a real OpenDocument file: no macros or dangerous links were found",
            "ole": "an old-style Office file without macros",
            "zip": "a zip file with nothing dangerous inside",
            "image": "a photo or picture: no hidden program was found",
            "media": "a video or audio file: no hidden program was found",
            "text": "a text file without dangerous links",
            "html": "a web page without code, forms or dangerous links",
            "svg": "a picture without code or dangerous links"}.get(
        kind, "no danger signs were found, though the Pi does not know this file type")
