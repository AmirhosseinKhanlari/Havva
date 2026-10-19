"""Storage probe: WAL-aware SQLite, key tiers, cookies, observer trail, verdicts,
and the inspect_storage flow's inconclusive paths."""
from __future__ import annotations

import sqlite3
import struct
import tempfile
from pathlib import Path
from types import SimpleNamespace

from pipeline import storage_scan as ss


def test_sqlite_wal_contents_are_seen():
    root = Path(tempfile.mkdtemp())
    (root / "Library").mkdir()
    db = root / "Library/store.sqlite"
    con = sqlite3.connect(db)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE session (id INTEGER, accessToken TEXT)")
    con.commit()
    # Written during the "run": lives in the -wal file until a checkpoint.
    con.execute("INSERT INTO session VALUES (1, 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')")
    con.commit()
    assert (root / "Library/store.sqlite-wal").stat().st_size > 0   # WAL holds the row
    try:
        findings, stores = ss.scan_container(root)      # connection still open: no checkpoint
    finally:
        con.close()
    types = [f["type"] for f in findings]
    assert any("sensitive column" in t and "accessToken" in t for t in types)
    assert any("JWT" in t for t in types), types
    assert stores["SQLite / Core Data"] >= 2                    # db + wal counted, scanned once
    assert not any("not readable" in t for t in types)


def test_key_tiers_and_boundaries():
    assert ss._key_severity("accessToken") == "medium"
    assert ss._key_severity("refresh_token") == "medium"
    assert ss._key_severity("userPassword") == "high"
    assert ss._key_severity("pinCode") == "high" and ss._key_severity("PIN_CODE") == "high"
    assert ss._key_severity("pin") == "high" and ss._key_severity("user_pin") == "high"
    assert ss._key_severity("pinCount") is None and ss._key_severity("pinImage") is None
    assert ss._key_severity("pinned") is None and ss._key_severity("secretary") is None
    assert ss._key_severity("deviceToken") is None             # push token: not a credential
    assert ss._key_severity("cookieConsent") is None           # 'cookie' then camelCase: not a key
    assert ss._key_severity("sessionId") == "medium"
    assert ss._SENSITIVE_KEY.search("clientSecret")


def _cookie_file(cookies):
    """Build a minimal .binarycookies with one page."""
    recs = []
    for dom, name, path, val, flags in cookies:
        strings = (dom + "\0").encode() + (name + "\0").encode() + (path + "\0").encode() + (val + "\0").encode()
        hdr_len = 56
        u = hdr_len
        n = u + len(dom) + 1
        p = n + len(name) + 1
        v = p + len(path) + 1
        size = hdr_len + len(strings)
        rec = struct.pack("<IIIIIIII", size, 0, flags, 0, u, n, p, v) + b"\0" * 8 + struct.pack("<dd", 0.0, 0.0) + b"\0" * 8
        rec = rec[:hdr_len] + strings
        recs.append(rec)
    offs, body, cur = [], b"", 8 + 4 * len(recs) + 4
    for r in recs:
        offs.append(cur); body += r; cur += len(r)
    page = b"\x00\x00\x01\x00" + struct.pack("<I", len(recs)) + b"".join(struct.pack("<I", o) for o in offs) + b"\0\0\0\0" + body
    return b"cook" + struct.pack(">I", 1) + struct.pack(">I", len(page)) + page


def test_binarycookies_parsed_and_graded():
    raw = _cookie_file([("api.example.com", "session_token", "/", "abc123", 1 | 4),
                        ("www.example.com", "theme", "/", "dark", 0)])
    cs = ss.parse_binarycookies(raw)
    assert [c["name"] for c in cs] == ["session_token", "theme"]
    assert cs[0]["secure"] and cs[0]["httponly"] and not cs[1]["secure"]
    root = Path(tempfile.mkdtemp()); (root / "Library/Cookies").mkdir(parents=True)
    (root / "Library/Cookies/Cookies.binarycookies").write_bytes(raw)
    findings, _ = ss.scan_container(root)
    assert any("cookie 'session_token'" in f["type"] and f["severity"] == "medium" for f in findings)
    assert ss.parse_binarycookies(b"not cookies") == []


_TRAIL = """\
Oct 19 10:00:00 iPhone Bank(StorageObserver)[9] <Notice>: STORAGEOBS LOADED com.example.bank
Oct 19 10:00:06 iPhone Bank[9] <Notice>: STORAGEOBS BEGIN 1
Oct 19 10:00:06 iPhone Bank[9] <Notice>: STORAGEOBS FILE NSFileProtectionCompleteUntilFirstUserAuthentication 120 Library/Preferences/com.example.bank.plist
Oct 19 10:00:06 iPhone Bank[9] <Notice>: STORAGEOBS KEYCHAIN class=genp acc=dk agrp=TEAM.com.example.bank svce=auth labl=- acct_len=12
Oct 19 10:00:06 iPhone Bank[9] <Notice>: STORAGEOBS END 1 files=1 keychain=1
Oct 19 10:00:16 iPhone Bank[9] <Notice>: STORAGEOBS BEGIN 2
Oct 19 10:00:16 iPhone Bank[9] <Notice>: STORAGEOBS FILE NSFileProtectionNone 300 Library/Preferences/com.example.bank.plist
Oct 19 10:00:16 iPhone Bank[9] <Notice>: STORAGEOBS FILE NSFileProtectionComplete 9000 Documents/notes.sqlite
Oct 19 10:00:16 iPhone Bank[9] <Notice>: STORAGEOBS KEYCHAIN class=genp acc=ck agrp=TEAM.com.example.bank svce=auth labl=- acct_len=12
Oct 19 10:00:16 iPhone Bank[9] <Notice>: STORAGEOBS KEYCHAIN class=inet acc=dku agrp=TEAM.com.example.bank svce=- labl=legacy acct_len=5
Oct 19 10:00:16 iPhone Bank[9] <Notice>: STORAGEOBS END 2 files=2 keychain=2
"""


def test_observer_trail_last_dump_wins_and_merges():
    obs = ss.parse_observer(_TRAIL)
    assert obs["loaded"] and obs["dumps"] == 2
    assert obs["files"]["Library/Preferences/com.example.bank.plist"] == "NSFileProtectionNone"
    assert len(obs["keychain"]) == 2
    f = [{"store": "NSUserDefaults", "file": "Library/Preferences/com.example.bank.plist",
          "type": "sensitive key: accessToken", "severity": "medium", "detail": "x"},
         {"store": "SQLite / Core Data", "file": "Documents/notes.sqlite",
          "type": "SQLite table 'n' (3 rows)", "severity": "info", "detail": ""}]
    out, stores = ss.apply_observer(f, {"NSUserDefaults": 1}, obs)
    # NSFileProtectionNone bumps a real finding one level and tags it.
    assert out[0]["severity"] == "high" and "[NSFileProtectionNone]" in out[0]["type"]
    assert out[0]["protection"] == "NSFileProtectionNone"
    assert out[1]["severity"] == "info" and out[1]["protection"] == "NSFileProtectionComplete"
    kc = [x for x in out if x["store"] == "Keychain"]
    assert len(kc) == 2 and stores["Keychain"] == 2
    assert any(x["severity"] == "high" and "AlwaysThisDeviceOnly" in x["type"] for x in kc)
    assert any(x["severity"] == "info" and "AfterFirstUnlock" in x["type"] for x in kc)
    # No trail: findings untouched.
    assert ss.apply_observer(f, {}, ss.parse_observer(""))[0] == f


def test_verdict_tiers():
    V = ss.verdict_of
    assert V([{"severity": "high", "type": "Private key block"}])[0] == "credentials_exposed"
    assert V([{"severity": "medium", "type": "sensitive key: accessToken"}])[0] == "tokens_in_files"
    assert V([{"severity": "medium", "type": "email in stored value"}])[0] == "pii_in_files"
    assert V([{"severity": "info", "type": "3 value(s) stored in a file"}])[0] == "data_only"
    assert V([])[0] == "clean"
    assert "classes unknown" in V([{"severity": "info", "type": "x"}], observed=False)[1]
    assert "classes unknown" not in V([{"severity": "info", "type": "x"}], observed=True)[1]


# ---- inspect_storage flow -----------------------------------------------------

class _DB:
    def __init__(self):
        self.saved = []

    def get_acquisition(self, app_id):
        return {"ipa_path": "/x/decrypted.ipa"}

    def save_storage_probe(self, app_id, verdict, note, findings, stores):
        self.saved.append((verdict, note, findings, stores))

    def set_bundle_id(self, *a):
        pass


def _env(monkeypatch, tmp_path, launched=True, pulled=True, trail=""):
    from pipeline import device, dynamic, instrument
    from pipeline.config import CONFIG
    monkeypatch.setattr(dynamic, "CONFIG", SimpleNamespace(
        paths=SimpleNamespace(work_dir=tmp_path, results_dir=tmp_path),
        signing=CONFIG.signing, runtime=CONFIG.runtime, test_device=CONFIG.test_device))
    monkeypatch.setattr(instrument, "build", lambda *a, **k: (True, str(tmp_path / "s.ipa"), ""))
    monkeypatch.setattr(device, "install_ipa", lambda *a, **k: (True, ""))
    monkeypatch.setattr(device, "uninstall", lambda *a, **k: None)

    def fake_syslog(seconds=None, during=None, grep="", **k):
        if during:
            during()
        return trail
    monkeypatch.setattr(device, "capture_syslog", fake_syslog)

    def fake_pull(bundle_id, sub, dest):
        if not pulled:
            return False, "device is locked (unlock it and re-run)"
        d = Path(dest) / sub
        d.mkdir(parents=True, exist_ok=True)
        if sub == "Library":
            (d / "Preferences").mkdir(exist_ok=True)
            import plistlib
            (d / "Preferences/app.plist").write_bytes(plistlib.dumps({"accessToken": "abc", "theme": "dark"}))
        return True, ""
    monkeypatch.setattr(device, "pull_container_ex", fake_pull)
    driver = SimpleNamespace(drive=lambda *a, **k: SimpleNamespace(
        launched=launched, crashed=False, died=False, login_status="none"))
    return dynamic, driver


def test_inspect_storage_launch_failure_is_inconclusive(monkeypatch, tmp_path):
    dynamic, driver = _env(monkeypatch, tmp_path, launched=False)
    db = _DB()
    res = dynamic.inspect_storage(db, {"app_id": "1", "bundle_id": "com.example.bank"}, driver=driver)
    assert res["verdict"] == "inconclusive" and "did not launch" in res["note"]
    assert db.saved[-1][0] == "inconclusive"


def test_inspect_storage_pull_failure_names_the_cause(monkeypatch, tmp_path):
    dynamic, driver = _env(monkeypatch, tmp_path, pulled=False, trail=_TRAIL)
    db = _DB()
    res = dynamic.inspect_storage(db, {"app_id": "1", "bundle_id": "com.example.bank"}, driver=driver)
    assert res["verdict"] == "inconclusive" and "locked" in res["note"]
    # Keychain inventory still surfaces from the observer.
    assert any(f["store"] == "Keychain" for f in res["findings"])


def test_inspect_storage_grades_pulled_container_with_observer(monkeypatch, tmp_path):
    dynamic, driver = _env(monkeypatch, tmp_path, trail=_TRAIL)
    db = _DB()
    res = dynamic.inspect_storage(db, {"app_id": "1", "bundle_id": "com.example.bank"}, driver=driver)
    # accessToken in a plist -> tokens tier; the observer's always-readable
    # Keychain item lifts it to credentials_exposed.
    assert res["verdict"] == "credentials_exposed"
    assert any("accessToken" in f["type"] for f in res["findings"])
    assert res["stores"].get("Keychain") == 2


def test_inspect_storage_without_observer_says_classes_unknown(monkeypatch, tmp_path):
    dynamic, driver = _env(monkeypatch, tmp_path, trail="")
    db = _DB()
    res = dynamic.inspect_storage(db, {"app_id": "1", "bundle_id": "com.example.bank"}, driver=driver)
    assert res["verdict"] == "tokens_in_files" and "classes unknown" in res["note"]
