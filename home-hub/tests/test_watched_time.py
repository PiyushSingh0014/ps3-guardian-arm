"""The monitor's watched time per day (data/net/days.json), kept on a clock of its own."""
import json
import time

import pytest

from detectors.net import monitor


class Engine:
    flows = 0


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def local(d, h, m, s=0):
    return time.mktime((2026, 11, d, h, m, s, 0, 0, -1))


def watch(tmp_path, packets=None, up=True, start=local(3, 23, 50)):
    clock, counter = Clock(start), {"n": 1000}
    w = monitor.WatchedTime(Engine(), "wlan0", str(tmp_path / "days.json"), clock=clock,
                            packets=packets or (lambda iface: counter["n"]), up=lambda iface: up)
    return w, clock, counter


def days(tmp_path):
    with open(tmp_path / "days.json", encoding="utf-8") as f:
        return json.load(f)


def test_a_quiet_night_is_written_down_on_its_own_days(tmp_path, capsys):
    # Before update 26 the time was written down only when a flow arrived: a quiet night went
    # to the next morning, all of it on that day.
    w, clock, _ = watch(tmp_path)
    w.engine.flows, w.alerts = 40, 1                # traffic in the first minute only
    while clock.t < local(4, 2, 0):
        clock.t += w.wait_s()
        assert w.tick() is False
        assert time.localtime(clock.t).tm_mday == 3 or clock.t >= local(4, 0, 0)
    d = days(tmp_path)
    assert d["_started"] == "2026-11-03 23:50:00"                                  # when this count began
    assert d["2026-11-03"]["minutes"] == pytest.approx(10.0, abs=0.05)            # 23:50 to midnight
    assert (d["2026-11-03"]["active_minutes"], d["2026-11-03"]["flows"], d["2026-11-03"]["alerts"]) == (1.0, 40, 1)
    assert 120 <= d["2026-11-04"]["minutes"] <= 126 and d["2026-11-04"]["active_minutes"] == 0.0
    printed = capsys.readouterr().out
    assert "[net] 23:51 40 flows so far (40 in the last 1 min), 1 alerts" in printed   # a minute after starting
    assert "[net] 00:06 40 flows so far (0 in the last 15 min), 1 alerts" in printed   # and every 15 min, quiet or not


def test_ticks_never_cross_midnight(tmp_path):
    w, clock, _ = watch(tmp_path, start=local(3, 23, 58))
    clock.t += w.wait_s()                           # the first status line, a minute after start
    w.tick()
    assert w.wait_s() == local(4, 0, 0) + 1 - clock.t <= 61


def test_time_with_the_wifi_off_is_not_watched(tmp_path, capsys):
    w, clock, _ = watch(tmp_path, up=False)
    clock.t += 60
    w.tick()
    assert not (tmp_path / "days.json").exists()
    assert "(the Wi-Fi is off: not counted as watched)" in capsys.readouterr().out


def test_a_stuck_capture_is_not_watched_and_restarts(tmp_path, capsys):
    w, clock, counter = watch(tmp_path)
    clock.t += 60
    counter["n"] += 900                             # the first minute: packets but no flow yet is fine
    assert w.tick() is False and days(tmp_path)["2026-11-03"]["minutes"] == 1.0
    for expect in (False, True):                    # then two stretches with packets and no flow at all
        clock.t += 300
        counter["n"] += 1000
        assert w.tick() is expect
    clock.t += 30
    w.tick(final=True)
    assert days(tmp_path)["2026-11-03"]["minutes"] == 1.0          # none of that counted
    out = capsys.readouterr().out
    assert "the Wi-Fi carried 1000 packets in 5 min but the capture saw no flow\n" in out
    assert "saw no flow: restarting the capture" in out


def test_packets_with_flows_or_an_idle_wifi_are_fine(tmp_path):
    w, clock, counter = watch(tmp_path)
    for flows, packets in ((25, 5000), (0, 3), (0, 0)):          # busy, then quiet
        clock.t += 300
        w.engine.flows += flows
        counter["n"] += packets
        assert w.tick() is False
    w2, clock2, _ = watch(tmp_path / "x", packets=lambda iface: None)   # counters unreadable
    clock2.t += 600
    assert w2.tick() is False


def test_run_live_keeps_watching_while_no_flow_comes(tmp_path, monkeypatch):
    # The flow loop waits for flows; the clock of WatchedTime does not.
    monkeypatch.setattr(monitor, "TICK_S", 1)
    monkeypatch.setattr(monitor, "FIRST_STATUS_S", 1)
    monkeypatch.setattr(monitor, "iface_up", lambda iface: True)
    monkeypatch.setattr(monitor, "iface_packets", lambda iface: None)
    seen = []

    def quiet():
        time.sleep(2.5)                             # no traffic for a while, then the stream ends
        seen.append(days(tmp_path)[time.strftime("%Y-%m-%d")]["minutes"])
        return
        yield

    class E(Engine):
        gateway = "10.42.0.1"

        def feed(self, rec):
            return []

        def save(self):
            pass

    monitor.run(quiet(), E(), None, show=False, iface="wlan0", days=str(tmp_path / "days.json"))
    assert seen and seen[0] > 0                     # written down during the quiet time itself
