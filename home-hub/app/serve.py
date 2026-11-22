"""Serve the app on HTTPS for the phones and the page, and on plain HTTP for lab devices and for the
Pi itself. Run by scripts/run_pi.sh (update 39):

    python -m app.serve --cert ~/.ps3_tls_cert.pem --key ~/.ps3_tls_key.pem
    python -m app.serve --fingerprint ~/.ps3_tls_cert.pem      # the certificate's fingerprint

Both ports serve one app object in one process, so the alerts, the explanation jobs and the token
guard are shared. GUARDIAN_TLS=1 (set here before the app is built) makes the app refuse plain HTTP
from other machines except POST /iot, the ESP32's readings: the phones' token and messages travel
only over HTTPS. The certificate is self-signed, so the app pins it: when a phone pairs, its owner
compares the fingerprint the app shows with the one the Pi prints (see docs/android-companion.md).
"""
import argparse
import asyncio
import base64
import contextlib
import hashlib
import os
import re
import signal
import sys

HTTPS_PORT = 8443
HTTP_PORT = 8000


def fingerprint(cert_path):
    """SHA-256 of the certificate (DER), as 16 groups of 4 hex digits: what the Android app shows."""
    with open(cert_path, encoding="ascii") as f:
        pem = f.read()
    body = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S)
    if not body:
        raise ValueError(f"{cert_path}: no certificate in it")
    digest = hashlib.sha256(base64.b64decode("".join(body.group(1).split()))).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def configs(app, cert, key, host="0.0.0.0", https_port=HTTPS_PORT, http_port=HTTP_PORT):
    import uvicorn
    tls = uvicorn.Config(app, host=host, port=https_port, ssl_certfile=cert, ssl_keyfile=key)
    plain = uvicorn.Config(app, host=host, port=http_port, lifespan="off")
    return tls, plain


def servers_for(configs_):
    """uvicorn servers that leave the signals to serve_all: each would otherwise take Ctrl+C and
    systemctl's stop for itself, and only one of the two would stop."""
    import uvicorn

    class Server(uvicorn.Server):
        def install_signal_handlers(self):          # older uvicorn
            pass

        @contextlib.contextmanager
        def capture_signals(self):                  # newer uvicorn
            yield

    return [Server(c) for c in configs_]


async def serve_all(servers):
    loop = asyncio.get_running_loop()

    def stop(*_):
        for s in servers:
            s.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop)
    await asyncio.gather(*(s.serve() for s in servers))
    if any(not s.started for s in servers):         # a port in use, a bad certificate: let systemd see it
        raise SystemExit(1)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cert", help="the certificate (PEM)")
    ap.add_argument("--key", help="its private key (PEM)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--https-port", type=int, default=HTTPS_PORT)
    ap.add_argument("--http-port", type=int, default=HTTP_PORT)
    ap.add_argument("--fingerprint", metavar="CERT", help="print this certificate's fingerprint and stop")
    a = ap.parse_args(argv)
    if a.fingerprint:
        print(fingerprint(a.fingerprint))
        return 0
    if not (a.cert and a.key):
        ap.error("give --cert and --key (scripts/run_pi.sh makes them)")
    os.environ["GUARDIAN_TLS"] = "1"
    os.environ["GUARDIAN_HTTPS_PORT"] = str(a.https_port)
    os.environ["GUARDIAN_TLS_FINGERPRINT"] = fingerprint(a.cert)
    from app.server import app                      # built after GUARDIAN_TLS is set
    asyncio.run(serve_all(servers_for(configs(app, a.cert, a.key, a.host, a.https_port, a.http_port))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
