"""File names: endings that mean an app or a program, and names made to hide them.

Shared by the file checker and by the chat check, which sees only the name a chat app shows
in its notification ("Wedding_Invitation.apk"), never the file itself.
"""
import re

APP_EXT = {"apk", "apks", "xapk", "apkm"}                        # Android apps
PROGRAM_EXT = {"exe", "scr", "com", "pif", "bat", "cmd", "msi", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
               "hta", "jar", "lnk", "cpl", "reg", "sh", "bin", "elf", "dll"}
DOC_EXT = {"pdf", "doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm",
           "odt", "ods", "odp", "rtf", "txt", "csv"}
IMAGE_EXT = {"jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "bmp", "tif", "tiff"}
MEDIA_EXT = {"mp4", "mov", "3gp", "mkv", "webm", "mp3", "m4a", "aac", "ogg", "opus", "wav", "amr"}
ARCHIVE_EXT = {"zip", "rar", "7z", "tar", "gz", "tgz"}
WEB_EXT = {"html", "htm", "shtml", "xhtml", "mht", "mhtml", "svg"}

# In a chat, only these endings count as a file name: ".js" or ".com" also end ordinary words
# and addresses ("node.js", "amazon.com").
_CHAT_FILE_RE = re.compile(r"(?<![\w/.:@-])([^\s/\\:*?\"<>|]{1,150}\.(apk|apks|xapk|apkm|exe|scr|msi|bat))(?!\w|\.\w)",
                           re.I)
_RTL = "\u202e"                          # right-to-left override: "invoice<RLO>fdp.apk" shows as "invoicekpa.pdf"


def extension(name):
    """The last ending of a file name, lower case: 'Card.PDF.apk' -> 'apk'."""
    base = (name or "").strip().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    base = base.replace(_RTL, "")
    return base.rsplit(".", 1)[-1].strip().lower() if "." in base else ""


def name_tricks(name):
    """What a file name does to look harmless, as plain-language reasons (never the name itself)."""
    n = (name or "").strip()
    out = []
    if _RTL in n:
        out.append("the file name uses a hidden character that turns its ending around, so an app can look "
                   "like a PDF or a photo")
    parts = [p.strip().lower() for p in n.replace(_RTL, "").split(".")]
    if len(parts) >= 3 and parts[-1] in APP_EXT | PROGRAM_EXT and parts[-2] in DOC_EXT | IMAGE_EXT | MEDIA_EXT:
        out.append(f"the name shows .{parts[-2]} but the file really ends in .{parts[-1]}, a trick to look like "
                   "a document or a photo")
    return out


def app_file_in_text(text):
    """The ending of an app or program file named in a chat message ('apk'), or None. Links are
    left to the link checker: a name inside a web address does not count."""
    for m in _CHAT_FILE_RE.finditer(text or ""):
        before = (text or "")[max(0, m.start() - 8):m.start()].lower()
        if "http" in before or "www." in before:
            continue
        return m.group(2).lower()
    return None
