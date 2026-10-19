"""Tests for the dynamic stage's verdict logic (crash attribution, stale
evidence, custom-run grading, ladder tail, input validation). All device /
Proxyman / signing I/O is stubbed; only the decision logic runs."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from pipeline import capture, device, dynamic, instrument
from pipeline.config import CONFIG
from pipeline.dynamic import ConfigRun
from pipeline.models import BypassStage, CrashClass, Outcome, WorkState
from pipeline.oracle import OracleInput, decide

DEVICE_IP = "192.168.1.116"
ROW = {"app_id": "123", "bundle_id": "com.example.bank"}


# ---- fakes ------------------------------------------------------------------

class FakeDB:
    def __init__(self):
        self.outcomes: list[tuple] = []
        self.runs: list[tuple] = []
        self.probes: list[tuple] = []
        self.touched = False

    def get_acquisition(self, app_id):
        self.touched = True
        return {"ipa_path": "/nonexistent/decrypted.ipa"}

    def clear_dynamic_runs(self, app_id):
        self.touched = True

    def clear_pinning_probe(self, app_id):
        pass

    def add_dynamic_run(self, *a, **k):
        self.runs.append(a)

    def add_pinning_probe(self, *a, **k):
        self.probes.append(a)

    def save_outcome(self, app_id, outcome, stage, pinned, state):
        self.outcomes.append((outcome, stage, pinned, state))

    def set_bundle_id(self, app_id, bid):
        pass


class FakeDriver:
    def __init__(self, dr):
        self.dr = dr
        self.calls: list[dict] = []

    def drive(self, bundle_id, duration, login, prefer="auto", stop_check=None):
        self.calls.append({"bundle_id": bundle_id, "stop_check": stop_check})
        return self.dr


def _dr(launched=True, crash_report="", died=False, login_status="none"):
    """Shape of device.DriveResult after the concurrent device.py change."""
    return SimpleNamespace(launched=launched, login_status=login_status,
                           crashed=bool(crash_report) or died,
                           crash_report=crash_report, died=died)


def _entry(url):
    return {"_clientAddress": DEVICE_IP,
            "request": {"url": url, "method": "GET", "headers": []},
            "response": {"status": 200, "headers": [], "content": {"text": ""}}}


def _har_text(urls):
    return json.dumps({"log": {"entries": [_entry(u) for u in urls]}})


def _run(config, ran=True, crashed=False, hosts=None, reached=None, login="none"):
    hosts = set(hosts or [])
    return ConfigRun(config, ran, crashed, CrashClass.NONE if not crashed else CrashClass.UNKNOWN,
                     hosts, bool(hosts) if reached is None else reached, login)


@pytest.fixture
def run_env(tmp_path, monkeypatch):
    """Stub everything around _run_config_impl except the decision logic.
    Returns a dict the test mutates to choose what the HAR export 'writes'."""
    env = {"har_urls": [], "export_ok": True}
    monkeypatch.setattr(dynamic, "CONFIG", SimpleNamespace(
        paths=SimpleNamespace(results_dir=tmp_path),
        test_device=SimpleNamespace(client_ip=DEVICE_IP),
        signing=CONFIG.signing, runtime=CONFIG.runtime))
    monkeypatch.setattr(instrument, "build", lambda *a, **k: (True, str(tmp_path / "signed.ipa"), ""))
    monkeypatch.setattr(device, "install_ipa", lambda *a, **k: (True, ""))
    monkeypatch.setattr(device, "flush_crash_reports", lambda: None, raising=False)
    monkeypatch.setattr(device, "uninstall", lambda *a, **k: None)
    monkeypatch.setattr(capture, "check_connection", lambda: True)
    monkeypatch.setattr(capture, "clear_session", lambda: None)
    monkeypatch.setattr(capture, "export_session", lambda p, retries=3: None)

    def fake_export_har(path, retries=3):
        if not env["export_ok"]:
            return False
        path.write_text(_har_text(env["har_urls"]))
        return True
    monkeypatch.setattr(capture, "export_har", fake_export_har)
    env["results_dir"] = tmp_path
    return env


# ---- crash attribution (fix 3) ----------------------------------------------

def test_live_death_is_never_suppressed_by_traffic(run_env):
    # App talked to its API first, then killed itself on a tamper check: the
    # liveness watch is trustworthy and must win over "it reached the network".
    run_env["har_urls"] = ["https://api.example.com/v1"]
    drv = FakeDriver(_dr(launched=True, died=True))
    run = dynamic.run_config("123", "com.example.bank", "x.ipa", "dylib", drv)
    assert run.crashed is True
    assert run.ran is False
    assert run.hosts == {"api.example.com"}
    assert "liveness" in run.run_log


def test_crash_report_after_traffic_is_teardown_noise(run_env):
    run_env["har_urls"] = ["https://api.example.com/v1"]
    drv = FakeDriver(_dr(launched=True, crash_report="Exception Type: EXC_CRASH (SIGABRT)"))
    run = dynamic.run_config("123", "com.example.bank", "x.ipa", "dylib", drv)
    assert run.crashed is False
    assert run.ran is True
    assert "ignored a crash report" in run.run_log


def test_crash_report_with_only_apple_background_traffic_counts_as_crash(run_env):
    # Old bug: reached_any_network counted gsp.apple.com, so `reached` was always
    # True and every post-launch crash report was dismissed.
    run_env["har_urls"] = ["https://gsp.apple.com/z", "https://p12.icloud.com/x"]
    drv = FakeDriver(_dr(launched=True, crash_report="Exception Type: EXC_CRASH (SIGABRT)"))
    run = dynamic.run_config("123", "com.example.bank", "x.ipa", "dylib", drv)
    assert run.reached_network is False
    assert run.crashed is True
    assert run.ran is False
    assert "crash report" in run.run_log


def test_clean_run_is_not_crashed(run_env):
    run_env["har_urls"] = ["https://api.example.com/v1"]
    drv = FakeDriver(_dr(launched=True))
    run = dynamic.run_config("123", "com.example.bank", "x.ipa", "stage0", drv)
    assert run.crashed is False and run.ran is True and run.crash_class is CrashClass.NONE


def test_drive_result_without_died_attribute_still_works(run_env):
    # Defensive against the old DriveResult shape (no `died`).
    run_env["har_urls"] = []
    dr = SimpleNamespace(launched=True, login_status="none", crashed=True, crash_report="SIGABRT")
    run = dynamic.run_config("123", "com.example.bank", "x.ipa", "dylib", FakeDriver(dr))
    assert run.crashed is True


# ---- stale evidence (fix 6) -------------------------------------------------

def test_stale_har_is_removed_before_export(run_env):
    har_path = run_env["results_dir"] / "123_dylib.har"
    har_path.write_text(_har_text(["https://stale.example.com/"]))
    sess = run_env["results_dir"] / "123_dylib.proxymansessionv2"
    sess.write_bytes(b"old")
    run_env["export_ok"] = False   # this run's export fails
    run = dynamic.run_config("123", "com.example.bank", "x.ipa", "dylib", FakeDriver(_dr()))
    assert run.hosts == set()
    assert run.reached_network is False
    assert not har_path.exists()
    assert not sess.exists()
    assert "HAR export failed" in run.run_log


# ---- stop_check threading (fix 8) -------------------------------------------

def test_stop_check_reaches_the_driver(run_env):
    cb = lambda: False  # noqa: E731
    drv = FakeDriver(_dr())
    dynamic.run_config("123", "com.example.bank", "x.ipa", "stage0", drv, stop_check=cb)
    assert drv.calls[0]["stop_check"] is cb


def test_stop_check_threads_through_detect_pinning_and_run_custom(monkeypatch):
    seen = []

    def fake_run_config(app_id, bundle_id, ipa, config, driver, **kw):
        seen.append((config, kw.get("stop_check")))
        return _run(config, hosts={"api.example.com"})
    monkeypatch.setattr(dynamic, "run_config", fake_run_config)
    cb = lambda: False  # noqa: E731
    dynamic.detect_pinning(FakeDB(), ROW, FakeDriver(None), stop_check=cb)
    dynamic.run_custom(FakeDB(), ROW, FakeDriver(None), ["ssks", "sideloadfix"], stop_check=cb)
    assert seen and all(s is cb for _, s in seen)
    assert [c for c, _ in seen] == ["pinning:clean", "pinning:bypass", "custom:ssks,sideloadfix"]


# ---- run_custom input validation (fix 7) ------------------------------------

@pytest.mark.parametrize("bad", [["../../etc"], ["ssks", "x/../../work"], ["SSKS"], [""], ["ssks;rm"]])
def test_run_custom_rejects_unknown_ids_before_touching_anything(bad, monkeypatch):
    db = FakeDB()
    called = []
    monkeypatch.setattr(dynamic, "run_config", lambda *a, **k: called.append(1))
    with pytest.raises(ValueError, match="unknown dylib id"):
        dynamic.run_custom(db, ROW, FakeDriver(None), bad)
    assert not db.touched and not called


def test_validate_dylib_ids_accepts_catalog_ids():
    ids = sorted(it["id"] for it in instrument.dylib_catalog())
    assert dynamic.validate_dylib_ids(ids) == ids


def test_label_regex_rejects_traversal():
    with pytest.raises(ValueError):
        dynamic._check_label("custom:../x")
    with pytest.raises(ValueError):
        dynamic._check_label("")
    assert dynamic._check_label("custom:ssks,sideloadfix") == "custom:ssks,sideloadfix"


# ---- run_custom grading (fix 9) ---------------------------------------------

def test_custom_outcome_helper_only_traffic_is_not_pinned():
    run = _run("custom:sideloadfix", hosts={"api.example.com"})
    assert dynamic.custom_outcome(run, ["sideloadfix"]) == \
        (Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE)


def test_custom_outcome_with_bypass_dylib_is_bypassed():
    run = _run("custom:ssks,sideloadfix", hosts={"api.example.com"})
    assert dynamic.custom_outcome(run, ["ssks", "sideloadfix"]) == \
        (Outcome.BYPASSED, BypassStage.DYLIB, True, WorkState.POSITIVE)
    for bid in ("frida", "evasion"):
        assert dynamic.custom_outcome(run, [bid, "sideloadfix"])[0] is Outcome.BYPASSED


def test_custom_outcome_crash_and_silence():
    assert dynamic.custom_outcome(_run("c", ran=False, crashed=True), ["ssks"])[0] is Outcome.TAMPER_DETECTED
    assert dynamic.custom_outcome(_run("c", reached=True), ["ssks"])[0] is Outcome.PINNED_UNBYPASSED
    assert dynamic.custom_outcome(_run("c"), ["ssks"])[0] is Outcome.INCONCLUSIVE


def test_run_custom_saves_not_pinned_for_helper_only_selection(monkeypatch):
    monkeypatch.setattr(dynamic, "run_config",
                        lambda *a, **k: _run(a[3], hosts={"api.example.com"}))
    db = FakeDB()
    dynamic.run_custom(db, ROW, FakeDriver(None), ["sideloadfix"])
    assert db.outcomes[-1] == (Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE)
    db = FakeDB()
    dynamic.run_custom(db, ROW, FakeDriver(None), ["ssks", "sideloadfix"])
    assert db.outcomes[-1] == (Outcome.BYPASSED, BypassStage.DYLIB, True, WorkState.POSITIVE)


# ---- detect_pinning: bypass-run crash (fix 5) --------------------------------

def _pinning_runs(clean: ConfigRun, byp: ConfigRun):
    def fake_run_config(app_id, bundle_id, ipa, config, driver, **kw):
        return clean if config == "pinning:clean" else byp
    return fake_run_config


def test_bypass_run_crash_is_inconclusive_not_not_pinned(monkeypatch):
    clean = _run("pinning:clean", hosts={"cdn.example.com"})
    byp = _run("pinning:bypass", ran=False, crashed=True)
    monkeypatch.setattr(dynamic, "run_config", _pinning_runs(clean, byp))
    db = FakeDB()
    res = dynamic.detect_pinning(db, ROW, FakeDriver(None))
    assert res["crashed_bypass"] is True
    assert res["crashed"] is False
    assert res["pinned"] == [] and res["not_pinned"] == [] and res["hard_pinned"] == []
    assert res["reliable"] is False
    assert db.outcomes[-1] == (Outcome.INCONCLUSIVE, BypassStage.DYLIB, False, WorkState.UNTESTED)
    assert db.probes == []


def test_clean_run_crash_is_still_tamper_detected(monkeypatch):
    clean = _run("pinning:clean", ran=False, crashed=True)
    byp = _run("pinning:bypass", hosts={"api.example.com"})
    monkeypatch.setattr(dynamic, "run_config", _pinning_runs(clean, byp))
    db = FakeDB()
    res = dynamic.detect_pinning(db, ROW, FakeDriver(None))
    assert res["crashed"] is True
    assert db.outcomes[-1][0] is Outcome.TAMPER_DETECTED


def test_pinning_happy_path_still_bypassed(monkeypatch):
    clean = _run("pinning:clean", hosts={"cdn.example.com"})
    byp = _run("pinning:bypass", hosts={"cdn.example.com", "api.example.com"})
    monkeypatch.setattr(dynamic, "run_config", _pinning_runs(clean, byp))
    db = FakeDB()
    res = dynamic.detect_pinning(db, ROW, FakeDriver(None))
    assert res["crashed_bypass"] is False
    assert res["pinned"] == ["api.example.com"] and res["not_pinned"] == ["cdn.example.com"]
    assert db.outcomes[-1][0] is Outcome.BYPASSED


# ---- process_app ladder tail (fix 10) ----------------------------------------

def test_stage0_baseline_does_not_mask_all_bypass_rungs_crashed():
    runs = [
        _run("stage0", ran=True, reached=False),           # baseline ran clean, no traffic
        _run("dylib", ran=False, crashed=True),
        _run("control", ran=False, crashed=True),
        _run("evasion", ran=False, crashed=True),
    ]
    all_crashed, any_ran, reached = dynamic.ladder_tail_inputs(runs)
    assert all_crashed is True and any_ran is False
    r = decide(OracleInput(stage0_app_hosts=set(), per_config_hosts=[
        (BypassStage.DYLIB, set()), (BypassStage.EVASION, set())],
        all_configs_crashed=all_crashed, any_config_ran=any_ran, reached_any_network=reached))
    assert r.label is Outcome.TAMPER_DETECTED


def test_ladder_tail_one_bypass_rung_ran():
    runs = [_run("stage0"), _run("dylib", ran=False, crashed=True),
            _run("control"), _run("renamed_dylib", ran=True, reached=True)]
    all_crashed, any_ran, reached = dynamic.ladder_tail_inputs(runs)
    assert all_crashed is False and any_ran is True and reached is True


def test_ladder_tail_with_no_bypass_runs_is_not_all_crashed():
    assert dynamic.ladder_tail_inputs([_run("stage0")]) == (False, False, False)


# ---- _launch_probe (fix 4) ---------------------------------------------------

def _probe_env(monkeypatch, tmp_path, running=True, report=""):
    order: list[str] = []
    monkeypatch.setattr(instrument, "build", lambda *a, **k: (True, str(tmp_path / "s.ipa"), ""))
    monkeypatch.setattr(device, "install_ipa", lambda *a, **k: (True, ""))
    monkeypatch.setattr(device, "flush_crash_reports", lambda: order.append("flush"), raising=False)
    monkeypatch.setattr(device, "launch", lambda *a, **k: (order.append("launch"), 42)[1])
    monkeypatch.setattr(device, "is_app_running", lambda b: running)
    monkeypatch.setattr(device, "fetch_crash_report", lambda b: (order.append("fetch"), report)[1])
    monkeypatch.setattr(device, "terminate", lambda *a, **k: None)
    monkeypatch.setattr(device, "uninstall", lambda *a, **k: None)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    return order


def test_launch_probe_flushes_reports_before_launch(monkeypatch, tmp_path):
    order = _probe_env(monkeypatch, tmp_path)
    p = dynamic._launch_probe("123", "com.example.bank", "x.ipa", "sideload:sideloadfix", [], None, 1)
    assert order == ["flush", "launch", "fetch"]
    assert p.survived is True


def test_launch_probe_unknown_liveness_is_not_exited(monkeypatch, tmp_path):
    _probe_env(monkeypatch, tmp_path, running=None)
    p = dynamic._launch_probe("123", "com.example.bank", "x.ipa", "sideload:control", [], None, 1)
    assert p.alive is True and p.crashed is False


def test_launch_probe_definite_exit(monkeypatch, tmp_path):
    _probe_env(monkeypatch, tmp_path, running=False)
    p = dynamic._launch_probe("123", "com.example.bank", "x.ipa", "sideload:control", [], None, 1)
    assert p.alive is False and p.survived is False
