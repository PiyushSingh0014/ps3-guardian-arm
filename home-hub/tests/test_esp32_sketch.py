"""The ESP32 sketch's loop, run on a PC with a simulated clock and a fake Pi (iot-lab-device/sim).

Each test mode must really make its look-ups or check-ins. The first version of the sketch
ended every test the moment it started (a stale clock reading), and only the device showed it.
Needs a C++ compiler (g++); skipped without one.
"""
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(os.path.dirname(ROOT), "iot-lab-device", "sim")
SKETCH = os.path.join(os.path.dirname(ROOT), "iot-lab-device", "ps3_lab_device")


@pytest.fixture(scope="module")
def sim(tmp_path_factory):
    gxx = shutil.which("g++")
    if gxx is None:
        pytest.skip("g++ is not installed")
    d = tmp_path_factory.mktemp("esp32sim")
    shutil.copy(os.path.join(SKETCH, "ps3_lab_device.ino"), d / "sketch_body.inc")
    shutil.copy(os.path.join(SKETCH, "secrets.example.h"), d / "secrets.h")
    exe = d / "sim"
    subprocess.run([gxx, "-std=gnu++17", "-O0", "-w", "-I", os.path.join(SIM, "stubs"), "-I", str(d),
                    os.path.join(SIM, "sim.cpp"), "-o", str(exe)], check=True, capture_output=True)
    return str(exe)


def run(sim, mode):
    out = subprocess.run([sim, mode], check=True, capture_output=True, text=True, timeout=60).stdout
    summary = re.search(r"SUMMARY test=\w+ reports=(\d+) lookups=(\d+) checkins=(\d+)", out)
    return out, [int(x) for x in summary.groups()]


@pytest.mark.parametrize("mode,lookups,checkins", [("dga", 50, 0), ("phishing", 10, 0), ("tunnel", 75, 0),
                                                   ("beacon", 0, 5)])
def test_each_test_mode_does_its_steps(sim, mode, lookups, checkins):
    out, (reports, n_lookups, n_checkins) = run(sim, mode)
    assert reports >= 27                                   # every 15 s for 7 minutes
    assert (n_lookups, n_checkins) == (lookups, checkins), out[-2000:]
    assert "Test over" not in out.split("Test started")[1].split("[test]")[0]   # not ended at once
    assert "back to normal" in out                         # and it stops when the Pi says so


def test_reports_carry_the_readings(sim):
    out, _ = run(sim, "dga")
    first = re.search(r'Reporting to the Pi every 15 s, for example: (\{.*\})', out).group(1)
    assert '"device":"esp32-lab"' in first and '"pressure_hpa":973.5' in first and '"knob":1234' in first
