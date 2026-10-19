"""Hermetic tests for the device-runner measurement logic (no device):
liveness two-consecutive-False rule, exact crash-report attribution, and
label-tap matching (negation / SSO / priority)."""

import json
from types import SimpleNamespace

import pytest

from pipeline import device
from pipeline.device import AppiumDriver, DriveResult, _watch_liveness, fetch_crash_report


# ---- helpers ----------------------------------------------------------------

class FakeTime:
    """Deterministic clock: sleep() advances time() instantly."""

    def __init__(self):
        self.now = 1000.0

    def time(self):
        return self.now

    def sleep(self, s):
        self.now += max(float(s), 0.0)


def _liveness_sequence(monkeypatch, states):
    """Monkeypatch is_app_running to yield `states` in order (last value repeats)."""
    it = iter(states)
    last = {"v": states[-1]}

    def fake(_bid):
        try:
            last["v"] = next(it)
        except StopIteration:
            pass
        return last["v"]

    monkeypatch.setattr(device, "is_app_running", fake)
    ft = FakeTime()
    monkeypatch.setattr(device, "time", ft)
    return ft


# ---- _watch_liveness --------------------------------------------------------

def test_watch_liveness_two_consecutive_false_declares_dead(monkeypatch):
    _liveness_sequence(monkeypatch, [True, False, False, True])
    assert _watch_liveness("com.x.app", duration=60, grace=0, poll=4) is True


def test_watch_liveness_single_false_is_not_dead(monkeypatch):
    # One False between Trues: a transient miss, the app stays "up".
    _liveness_sequence(monkeypatch, [True, False, True, True, True])
    assert _watch_liveness("com.x.app", duration=20, grace=0, poll=4) is False


def test_watch_liveness_none_is_unknown_and_keeps_polling(monkeypatch):
    # Only unknowns: never declared dead, window runs to the end.
    _liveness_sequence(monkeypatch, [None])
    assert _watch_liveness("com.x.app", duration=20, grace=0, poll=4) is False


def test_watch_liveness_none_does_not_reset_or_count(monkeypatch):
    # False, None, False: the None is neutral, the two Falses still count.
    _liveness_sequence(monkeypatch, [False, None, False, True])
    assert _watch_liveness("com.x.app", duration=60, grace=0, poll=4) is True


def test_watch_liveness_true_resets_counter(monkeypatch):
    _liveness_sequence(monkeypatch, [False, True, False, True, False, True])
    assert _watch_liveness("com.x.app", duration=24, grace=0, poll=4) is False


def test_watch_liveness_honors_stop_check(monkeypatch):
    calls = {"n": 0}
    _liveness_sequence(monkeypatch, [False, False, False])

    def stop():
        calls["n"] += 1
        return True

    assert _watch_liveness("com.x.app", duration=60, grace=0, poll=4, stop_check=stop) is False
    assert calls["n"] == 1


def test_drive_result_has_died_field():
    r = DriveResult(launched=True)
    assert r.died is False and r.crashed is False
    r = DriveResult(launched=True, died=True, crashed=True)
    assert r.died and r.crashed


# ---- fetch_crash_report -----------------------------------------------------

def _crash_env(monkeypatch, tmp_path):
    cfg = SimpleNamespace(paths=SimpleNamespace(work_dir=tmp_path),
                          test_device=SimpleNamespace(udid="FAKE-UDID"))
    monkeypatch.setattr(device, "CONFIG", cfg)
    return tmp_path / "crash"


def _ips(header: dict, body: dict) -> str:
    return json.dumps(header) + "\n" + json.dumps(body, indent=1)


def test_fetch_crash_report_exact_bundle_attribution(monkeypatch, tmp_path):
    dest = _crash_env(monkeypatch, tmp_path)
    seen = {}

    def fake_run_cmd(cmd, timeout=120, **kw):
        seen["cmd"] = cmd
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "Target-2026-10-18-120000.ips").write_text(_ips(
            {"app_name": "Target", "bundleID": "com.example.target", "bug_type": "309"},
            {"procName": "Target", "bundleID": "com.example.target",
             "exception": {"type": "EXC_CRASH", "signal": "SIGKILL"},
             "termination": {"namespace": "SIGNAL", "indicator": "Killed: 9"}}))
        (dest / "JetsamEvent-2026-10-18-120001.ips").write_text(_ips(
            {"bug_type": "298", "os_version": "iPhone OS 18.0"},
            {"processes": [{"name": "Target", "pid": 42}, {"name": "SpringBoard", "pid": 1}],
             "termination": {"namespace": "SIGNAL"}}))
        return SimpleNamespace(returncode=0, stdout="", stderr="", ok=True)

    monkeypatch.setattr(device, "run_cmd", fake_run_cmd)
    out = fetch_crash_report("com.example.target", exe_name="Target")
    assert '"bundleID": "com.example.target"' in out
    assert "JetsamEvent" not in out and '"processes"' not in out
    # Reports are consumed (no -k): each report seen by exactly one fetch.
    assert "-k" not in seen["cmd"]
    assert seen["cmd"][0] == "idevicecrashreport"


def test_fetch_crash_report_rejects_suffix_and_other_apps(monkeypatch, tmp_path):
    dest = _crash_env(monkeypatch, tmp_path)

    def fake_run_cmd(cmd, timeout=120, **kw):
        dest.mkdir(parents=True, exist_ok=True)
        # Another app whose bundle id merely shares the suffix "mail".
        (dest / "Mail-2026-10-18-120000.ips").write_text(_ips(
            {"app_name": "Mail", "bundleID": "com.apple.mobilemail"},
            {"procName": "Mail", "bundleID": "com.apple.mobilemail"}))
        # Legacy text report naming only the suffix, not the full bundle id.
        (dest / "legacy.crash").write_text("Process: mail [12]\nIdentifier: org.other.mail\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="", ok=True)

    monkeypatch.setattr(device, "run_cmd", fake_run_cmd)
    assert fetch_crash_report("com.example.mail", exe_name="") == ""


def test_fetch_crash_report_legacy_text_requires_full_bundle_id(monkeypatch, tmp_path):
    dest = _crash_env(monkeypatch, tmp_path)

    def fake_run_cmd(cmd, timeout=120, **kw):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "legacy.crash").write_text(
            "Process: Target [12]\nIdentifier: com.example.target\nException Type: EXC_BAD_ACCESS\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="", ok=True)

    monkeypatch.setattr(device, "run_cmd", fake_run_cmd)
    assert "EXC_BAD_ACCESS" in fetch_crash_report("com.example.target", exe_name="")


def test_fetch_crash_report_procname_match_needs_exe_name(monkeypatch, tmp_path):
    dest = _crash_env(monkeypatch, tmp_path)

    def fake_run_cmd(cmd, timeout=120, **kw):
        dest.mkdir(parents=True, exist_ok=True)
        # Body carries only procName (no bundleID): attributable only when the
        # executable name is known; never via the bundle-id suffix.
        (dest / "x.ips").write_text(_ips({"bug_type": "309"}, {"procName": "TargetExe"}))
        return SimpleNamespace(returncode=0, stdout="", stderr="", ok=True)

    monkeypatch.setattr(device, "run_cmd", fake_run_cmd)
    assert fetch_crash_report("com.example.targetexe", exe_name="") == ""
    assert "TargetExe" in fetch_crash_report("com.example.targetexe", exe_name="TargetExe")


# ---- is_app_running tri-state (devicectl path) ------------------------------

def test_is_app_running_unknown_on_transient_failure(monkeypatch, tmp_path):
    _crash_env(monkeypatch, tmp_path)
    monkeypatch.setattr(device, "pmd3_available", lambda: False)
    monkeypatch.setattr(device, "run_cmd", lambda *a, **k: SimpleNamespace(
        returncode=124, stdout="", stderr="timeout", ok=False))
    assert device.is_app_running("com.example.target") is None
    # Non-timeout failure but no procs.json written -> still unknown.
    monkeypatch.setattr(device, "run_cmd", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout="", stderr="", ok=False))
    assert device.is_app_running("com.example.target") is None


def test_is_app_running_devicectl_exact_match(monkeypatch, tmp_path):
    _crash_env(monkeypatch, tmp_path)
    monkeypatch.setattr(device, "pmd3_available", lambda: False)
    monkeypatch.setattr(device, "_installed_exe_name", lambda bid: "")
    procs_path = tmp_path / "procs.json"

    def fake_run_cmd(cmd, timeout=60, **kw):
        procs_path.write_text(json.dumps({"result": {"runningProcesses": [
            {"executable": "file:///private/var/containers/Bundle/Application/X/Target.app/Target",
             "processIdentifier": 7},
            {"executable": "file:///System/Library/CoreServices/SpringBoard.app/SpringBoard"},
            {"bundleIdentifier": "com.other.app", "executable": "/x/targetish.app/targetish"},
        ]}}))
        return SimpleNamespace(returncode=0, stdout="", stderr="", ok=True)

    monkeypatch.setattr(device, "run_cmd", fake_run_cmd)
    assert device.is_app_running("com.example.Target") is True
    # Same suffix as a path component only (no /Name.app/Name): not running.
    assert device.is_app_running("com.example.targetish") is False
    assert device.is_app_running("com.example.nothere") is False


# ---- _tap_label -------------------------------------------------------------

class StubElement:
    def __init__(self, label, displayed=True, enabled=True, log=None):
        self.label = label
        self.displayed = displayed
        self.enabled = enabled
        self.log = log if log is not None else []
        self.id = f"elem-{label}"

    def get_attribute(self, name):
        return self.label if name in ("label", "name") else None

    def is_displayed(self):
        return self.displayed

    def is_enabled(self):
        return self.enabled

    def click(self):
        self.log.append(self.label)


class StubDriver:
    """find_elements(by, 'XCUIElementType<T>') -> the stub elements registered for T."""

    def __init__(self, **by_type):
        self.by_type = by_type
        self.log = []
        for els in by_type.values():
            for e in els:
                e.log = self.log

    def find_elements(self, by, value):
        t = value.replace("XCUIElementType", "")
        return list(self.by_type.get(t, []))


def _ad() -> AppiumDriver:
    """AppiumDriver instance; the tap tests need the appium package importable."""
    pytest.importorskip("appium", reason="Appium-Python-Client not installed")
    return AppiumDriver()


def _drv(**kw):
    return StubDriver(**{k: [StubElement(x) for x in v] for k, v in kw.items()})


def test_tap_label_skips_negations():
    d = _drv(Button=["Don't Allow", "Allow"])
    assert _ad()._tap_label(d, ("Allow",)) is True
    assert d.log == ["Allow"]

    d = _drv(Button=["Disagree", "I Agree"])
    assert _ad()._tap_label(d, ("Agree",)) is True
    assert d.log == ["I Agree"]

    d = _drv(Button=["Don't Allow"])
    assert _ad()._tap_label(d, ("Allow",)) is False
    assert d.log == []


def test_tap_label_wanted_negation_may_tap_negation():
    d = _drv(Button=["Not now", "Continue"])
    assert _ad()._tap_label(d, ("Not now",)) is True
    assert d.log == ["Not now"]


def test_tap_label_bare_entry_skips_sso_variant():
    d = _drv(Button=["Continue with Google", "Continue with Apple"])
    assert _ad()._tap_label(d, ("Continue",)) is False
    d = _drv(Button=["Continue with Google", "Continue"])
    assert _ad()._tap_label(d, ("Continue",)) is True
    assert d.log == ["Continue"]
    # A wanted label that itself contains "with" taps the SSO button.
    d = _drv(Button=["Continue with Google"])
    assert _ad()._tap_label(d, ("Continue with Google",)) is True


def test_tap_label_priority_order_wins_over_element_order():
    # "Continue" appears first in the tree, but "Agree and continue" is wanted first.
    d = _drv(Button=["Continue", "Agree and continue"])
    ok = _ad()._tap_label(d, ("Agree and continue", "Continue"))
    assert ok and d.log == ["Agree and continue"]


def test_tap_label_word_boundary_substring():
    d = _drv(Button=["Log in with email"])
    # "log in" -> SSO-like " with " variant is skipped for the bare label...
    assert _ad()._tap_label(d, ("Log in",)) is False
    # ...but a non-SSO phrase containing the word is a valid substring hit.
    d = _drv(Button=["Tap to allow notifications"])
    assert _ad()._tap_label(d, ("Allow",)) is True
    # "agreement" must not match "agree" (word boundary).
    d = _drv(Button=["View agreement"])
    assert _ad()._tap_label(d, ("Agree",)) is False


def test_tap_label_statictext_exact_only():
    d = _drv(StaticText=['Tap "Agree and continue" to accept the terms', "Agree and continue"])
    assert _ad()._tap_label(d, ("Agree and continue",)) is True
    assert d.log == ["Agree and continue"]
    d = _drv(StaticText=['Tap "Agree and continue" to accept the terms'])
    assert _ad()._tap_label(d, ("Agree and continue",)) is False


def test_tap_label_skips_hidden_or_disabled():
    hidden = StubElement("Continue", displayed=False)
    disabled = StubElement("Continue", enabled=False)
    live = StubElement("Continue")
    d = StubDriver(Button=[hidden, disabled, live])
    assert _ad()._tap_label(d, ("Continue",)) is True
    assert d.log == ["Continue"] and live.log is d.log
