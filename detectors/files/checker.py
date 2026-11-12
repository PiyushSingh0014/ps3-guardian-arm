"""Is a file that came in a chat dangerous? Checked on the Pi, in memory, never stored.

What it looks at, none of which needs to understand the person's own content:
  * what the file really is, from its first bytes, against its name: an app (APK) or a program
    named like a PDF or a photo is disguised;
  * apps (APK): sent in a chat they are dangerous, and the permissions in the app's manifest say
    what it could do (read SMS: steal OTPs);
  * PDFs: the signs pdfid looks for (JavaScript, actions that run on opening, launch commands,
    embedded files), also inside compressed parts and behind #xx-escaped names; and its links;
  * Office files: macros, remote templates and objects, DDE, hidden programs, and its links;
  * archives (zip): what is inside, one level deep;
  * web pages saved as files (HTML, SVG): sign-in forms, scripts, links.
Links go through the link checker, like the links in an SMS. Reasons never contain the file's
name or a link: both are chosen by the sender, and reasons are passed to Llama.
"""
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
MAX_STREAMS = 400
MAX_LINKS = 20
MAX_REASONS = 4

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
_PDF_STREAM_RE = re.compile(rb"stream\r?\n")
_PDF_URI_RE = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){1,2000})\)")
_PDF_URI_HEX_RE = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]{2,4000})>")
_PDF_NAME_RE = re.compile(rb"/(?:UF|F)\s*\(((?:\\.|[^\\)]){1,300})\)")
_PERMISSION_RE = re.compile(r"android\.permission\.([A-Z_]{3,60})")
_REL_RE = re.compile(rb"<Relationship\b[^>]*>", re.I)
_ATTR_RE = re.compile(rb'(\w+)\s*=\s*"([^"]*)"')
_DDE_RE = re.compile(rb"(?i)(?:<w:instrText[^>]*>\s*|instr=\"\s*)DDE(?:AUTO)?\b")
_PROGRAM_NAME_RE = re.compile(rb"(?i)[\w\- ]{1,80}\.(exe|scr|bat|cmd|js|jse|vbs|vbe|wsf|hta|ps1|jar|lnk|apk|msi)\x00")
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

    def check(self, data: bytes, name: str = "", language: str = "en") -> Finding:
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
            signs += self._pdf(data, st)
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

    def _inflate(self, chunk, st):
        room = MAX_INFLATE - st.inflated
        if room <= 0:
            return b""
        try:
            out = zlib.decompressobj().decompress(chunk, room)
        except zlib.error:
            return b""
        st.inflated += len(out)
        return out

    def _pdf(self, data, st):
        parts = [data]
        n = 0
        for m in _PDF_STREAM_RE.finditer(data):
            if n >= MAX_STREAMS or st.inflated >= MAX_INFLATE:
                break
            start = m.end()
            end = data.find(b"endstream", start)
            if end < 0:
                break
            head = data[max(0, m.start() - 400):m.start()]
            if b"Fl" in head and b"/DCTDecode" not in head and b"/JPXDecode" not in head:
                out = self._inflate(data[start:end], st)
                if out:
                    parts.append(out)
                    n += 1
        counts = {}
        for part in parts:
            extra = b" ".join(_unhex_name(t) for t in _PDF_HEXNAME_RE.findall(part))
            for chunk in (part, extra):
                for k in _PDF_KEY_RE.findall(chunk):
                    key = k.decode()
                    key = "EmbeddedFile" if key.startswith("EmbeddedFile") else key
                    counts[key] = counts.get(key, 0) + 1
            for raw in _PDF_URI_RE.findall(part):
                st.links.append(_pdf_string(raw))
            for raw in _PDF_URI_HEX_RE.findall(part):
                try:
                    st.links.append(bytes.fromhex(raw.decode().replace(" ", "").replace("\n", "")).decode("latin-1"))
                except ValueError:
                    pass
        signs = []
        code = counts.get("JS", 0) + counts.get("JavaScript", 0)
        auto = counts.get("OpenAction", 0) + counts.get("AA", 0)
        if counts.get("Launch"):
            signs.append(Sign(0.95, "the PDF can start a program on your device", "harmful_document"))
        if code and auto:
            signs.append(Sign(0.9, "the PDF runs hidden code (JavaScript) as soon as it is opened", "harmful_document"))
        elif code:
            signs.append(Sign(0.65, "the PDF contains hidden code (JavaScript)", "harmful_document"))
        if counts.get("EmbeddedFile"):
            names = [_pdf_string(r) for part in parts for r in _PDF_NAME_RE.findall(part)]
            if any(extension(x) in APP_EXT | PROGRAM_EXT for x in names):
                signs.append(Sign(0.95, "the PDF hides an app or a program inside it", "app_file"))
            else:
                signs.append(Sign(0.6, "the PDF carries another file inside it", "harmful_document"))
        if counts.get("RichMedia"):
            signs.append(Sign(0.6, "the PDF contains embedded media that can run code", "harmful_document"))
        if counts.get("SubmitForm"):
            signs.append(Sign(0.55, "the PDF has a form that sends what you type to a website", "phishing_document"))
        if counts.get("GoToE") or counts.get("GoToR"):
            signs.append(Sign(0.5, "the PDF opens another file when you click it", "harmful_document"))
        if counts.get("Encrypt") and len(parts) == 1:
            st.notes.append("the PDF is password-protected, so only its outside could be checked")
        return signs

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
            if not u or len(seen) >= MAX_LINKS:
                continue
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


def _pdf_string(raw):
    """The text of a PDF (literal) string: escapes undone, as Latin-1."""
    s = re.sub(rb"\\([nrtbf()\\])", lambda m: {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}.get(
        m.group(1), m.group(1)), raw)
    s = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), s)
    return s.decode("latin-1")


def _safe_reason(kind):
    return {"pdf": "a real PDF: no hidden code, launch actions, embedded files or dangerous links were found",
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
