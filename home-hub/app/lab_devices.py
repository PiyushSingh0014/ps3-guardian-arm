"""Lab devices on the Pi's hotspot (the ESP32 of the IoT Pro Kit): their readings, and the
harmless test modes the Pi page can switch on to show the network monitor at work.

A device posts its readings every 15 s (POST /iot, with the pairing token) and gets back
the mode the page asked for. The page lists the devices (GET /iot) and switches modes
(POST /iot/mode). Test modes only imitate what malware does on a network; nothing is
attacked, and every test stops by itself:

    dga       looks up made-up, random-looking names (they do not exist)  -> "DGA names"
    phishing  looks up a fake bank-site name (it does not exist)          -> "phishing look-up"
    tunnel    looks up long random sub-names under one made-up name       -> "DNS tunnel"
    beacon    fetches http://example.com/ every 60 s, like clockwork      -> "beacon" (only after
              the monitor's first 2 hours with the device: it learns the device's normal first)

Readings and names come from the devices, so they are checked here and shown on the page
as text only. State is kept in memory: after a restart, devices reappear within 15 s.
"""
import math
import re
import threading
import time

# mode -> (what the page shows, how long the test runs, minutes)
MODES = {
    "normal": ("Normal", 0),
    "dga": ("Looks up made-up names (DGA)", 5),
    "phishing": ("Looks up a fake bank site", 5),
    "tunnel": ("Hides data in DNS look-ups (tunnel)", 5),
    "beacon": ("Checks in like clockwork (beacon)", 15),
}
NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
KEY = re.compile(r"^[a-z0-9_]{1,24}$")
MAX_DEVICES, MAX_READINGS = 20, 20
FORGET_S = 24 * 3600                 # a device not heard from for a day is dropped


def clean_readings(raw):
    """{name: number or true/false}, at most 20; anything else raises ValueError."""
    if not isinstance(raw, dict) or len(raw) > MAX_READINGS:
        raise ValueError(f"readings must be an object with at most {MAX_READINGS} values")
    out = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not KEY.match(k):
            raise ValueError("reading names: lowercase letters, digits and _, at most 24")
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, (int, float)) and math.isfinite(v) and abs(v) < 1e9:
            out[k] = v if isinstance(v, int) else round(v, 3)
        else:
            raise ValueError(f"reading {k}: a number or true/false")
    return out


class LabDevices:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.devices = {}                  # name -> {"ip", "last_seen", "readings", "mode"}
        self.wanted = {}                   # name -> (mode, until): what the page asked for

    def _wanted(self, name, now):
        mode, until = self.wanted.get(name, ("normal", 0.0))
        if mode != "normal" and now >= until:            # the test is over
            self.wanted.pop(name, None)
            mode, until = "normal", 0.0
        return {"mode": mode, "seconds_left": max(0, round(until - now)) if mode != "normal" else 0}

    def report(self, name, ip, readings, mode="normal"):
        """A device's readings; returns the mode it should be in."""
        if not NAME.match(name or ""):
            raise ValueError("device name: letters, digits, _ and -, at most 32")
        now = self.clock()
        with self.lock:
            for k in [k for k, d in self.devices.items() if now - d["last_seen"] > FORGET_S]:
                self.devices.pop(k)
                self.wanted.pop(k, None)
            if name not in self.devices and len(self.devices) >= MAX_DEVICES:
                raise ValueError(f"at most {MAX_DEVICES} lab devices")
            self.devices[name] = {"ip": ip, "last_seen": now, "readings": dict(readings),
                                  "mode": mode if mode in MODES else "normal"}
            return self._wanted(name, now)

    def set_mode(self, name, mode):
        """The page asks a device to start a test (or stop: "normal")."""
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        now = self.clock()
        with self.lock:
            if name not in self.devices:
                raise KeyError(name)
            if mode == "normal":
                self.wanted.pop(name, None)
            else:
                self.wanted[name] = (mode, now + MODES[mode][1] * 60)
            return self._wanted(name, now)

    def listing(self):
        now = self.clock()
        with self.lock:
            out = []
            for name in sorted(self.devices):
                d, w = self.devices[name], self._wanted(name, now)
                out.append({"device": name, "ip": d["ip"], "seen_s_ago": round(now - d["last_seen"]),
                            "readings": dict(d["readings"]), "mode": d["mode"],
                            "wanted": w["mode"], "seconds_left": w["seconds_left"]})
            return out
