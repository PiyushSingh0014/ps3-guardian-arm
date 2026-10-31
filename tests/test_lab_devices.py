"""Lab devices (the ESP32): readings in, test modes out, and the page's view of them."""
import json
import time

import pytest
from fastapi.testclient import TestClient

from advisor.advise import Advisor
from app.lab_devices import MODES, LabDevices, clean_readings
from app.server import create_app
from detectors.sms.detector import SmsDetector

TOKEN = "pair1234"
GOOD = {"device": "esp32-lab", "mode": "normal",
        "readings": {"temp_c": 27.4, "humidity": 61, "pressure_hpa": 1008.25, "obstacle": 1, "rssi": -52}}


class Clock:
    def __init__(self):
        self.t = 1_793_460_000.0

    def __call__(self):
        return self.t


@pytest.fixture(scope="module")
def detector():
    return SmsDetector(url_detector=None)


@pytest.fixture
def setup(detector, tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_TOKEN", TOKEN)
    clock = Clock()
    alerts, state = tmp_path / "net_alerts.jsonl", tmp_path / "devices.json"
    app = create_app(detector=detector, advisor=Advisor(), net_alerts=str(alerts),
                     lab=LabDevices(clock=clock), net_state=str(state))
    return TestClient(app), clock, alerts, state


def post(c, body=GOOD, token=TOKEN, **kw):
    return c.post("/iot", json=body, headers={"X-Guardian-Token": token} if token else {}, **kw)


def test_reports_need_the_pairing_token(setup, monkeypatch):
    c = setup[0]
    assert post(c, token=None).status_code == 401
    assert post(c, token="wrong").status_code == 401
    assert post(c).json() == {"mode": "normal", "seconds_left": 0}
    monkeypatch.delenv("GUARDIAN_TOKEN")
    assert post(c).status_code == 503


@pytest.mark.parametrize("readings", [
    {"Temp": 1}, {"temp_c": "hot"}, {"temp_c": [1]}, {f"r{i}": i for i in range(21)}, {"x" * 25: 1}])
def test_bad_readings_are_refused(setup, readings):
    assert post(setup[0], {**GOOD, "readings": readings}).status_code == 422


def test_not_a_number_is_refused(setup):
    body = json.dumps(GOOD).replace("27.4", "NaN")       # Python's JSON reader accepts NaN
    r = setup[0].post("/iot", content=body, headers={"X-Guardian-Token": TOKEN, "Content-Type": "application/json"})
    assert r.status_code == 422


def test_bad_device_names_are_refused(setup):
    for name in ["", "esp 32", "<b>x</b>", "x" * 33]:
        assert post(setup[0], {**GOOD, "device": name}).status_code == 422


def test_a_test_mode_reaches_the_device_and_stops_by_itself(setup):
    c, clock = setup[0], setup[1]
    assert c.post("/iot/mode", json={"device": "esp32-lab", "mode": "dga"}).status_code == 404   # not reported yet
    post(c)
    assert c.post("/iot/mode", json={"device": "esp32-lab", "mode": "attack"}).status_code == 422
    assert c.post("/iot/mode", json={"device": "esp32-lab", "mode": "dga"}).json() == {"mode": "dga", "seconds_left": 300}
    clock.t += 60
    assert post(c).json() == {"mode": "dga", "seconds_left": 240}
    clock.t += 241
    assert post(c).json() == {"mode": "normal", "seconds_left": 0}
    c.post("/iot/mode", json={"device": "esp32-lab", "mode": "beacon"})
    assert c.post("/iot/mode", json={"device": "esp32-lab", "mode": "normal"}).json()["mode"] == "normal"


def test_page_view_with_readings_alerts_and_learning(setup):
    c, clock, alerts, state = setup
    post(c, {**GOOD, "mode": "dga"})
    finding = {"source": "net", "verdict": "dangerous", "score": 0.85, "category": "dga_domains",
               "reasons": ["testclient looked up 5 different random-looking website names"],
               "entities": {"device": "testclient", "peer": "random names"}, "language": "en"}
    other = {**finding, "entities": {"device": "10.42.0.99", "peer": "random names"}}
    alerts.write_text(json.dumps({"time": "2026-10-31 20:00:00", "finding": finding}) + "\n"
                      + json.dumps({"time": "2026-10-31 20:01:00", "finding": other}) + "\n")
    state.write_text(json.dumps({"testclient": {"first_ms": int(time.time() * 1000) - 600_000, "peers": []}}))
    body = c.get("/iot").json()
    assert set(body["modes"]) == set(MODES)
    d = body["devices"][0]
    assert d["device"] == "esp32-lab" and d["ip"] == "testclient" and d["mode"] == "dga" and d["wanted"] == "normal"
    assert d["readings"]["pressure_hpa"] == 1008.25
    assert [a["headline"] for a in d["alerts"]] == ["DANGEROUS: Malware looking for its controller (random website names)"]
    assert d["learning_until"]                                   # first seen 10 minutes ago: still learning
    state.write_text(json.dumps({"testclient": {"first_ms": int(time.time() * 1000) - 3 * 3600_000}}))
    assert c.get("/iot").json()["devices"][0]["learning_until"] is None


def test_devices_are_limited_and_forgotten():
    clock = Clock()
    lab = LabDevices(clock=clock)
    for i in range(20):
        lab.report(f"d{i}", "10.42.0.2", {})
    with pytest.raises(ValueError):
        lab.report("d20", "10.42.0.2", {})
    clock.t += 25 * 3600
    lab.report("d20", "10.42.0.2", {})                          # the silent ones are forgotten
    assert [d["device"] for d in lab.listing()] == ["d20"]


def test_clean_readings_keeps_numbers_and_flags():
    assert clean_readings({"a": 1, "b": 2.34567, "c": True}) == {"a": 1, "b": 2.346, "c": True}
