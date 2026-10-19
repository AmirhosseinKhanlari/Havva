"""Smoke tests for the DB backbone: schema, upsert, metadata, work queues."""

import json

from pipeline.db import Database
from pipeline.models import (
    BypassStage, DefenseProfile, Outcome, PinLayer, Stage, TlsStack, WorkState,
)


def _db(tmp_path):
    return Database(tmp_path / "test.db")


def test_upsert_and_metadata_roundtrip(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("123", "us", bundle_id="com.x.y", name="X",
                  all_categories=["Finance", "Business"], raw_json='{"k":1}')
    with db.connect() as c:
        row = c.execute("SELECT * FROM apps WHERE app_id='123'").fetchone()
    assert row["bundle_id"] == "com.x.y"
    assert json.loads(row["all_categories"]) == ["Finance", "Business"]
    assert row["stage"] == "crawled"


def test_upsert_ignores_unknown_fields(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us", not_a_real_column="oops", name="Ok")
    with db.connect() as c:
        row = c.execute("SELECT name FROM apps WHERE app_id='1'").fetchone()
    assert row["name"] == "Ok"


def test_static_profile_and_pinned_queue(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.ipa")
    prof = DefenseProfile(pins_flag=True, pin_layer=PinLayer.L3_LIBRARY,
                          pin_library="TrustKit", tls_stack=TlsStack.NATIVE,
                          appattest_flag=True)
    db.save_static_profile("1", prof)
    needing = db.apps_needing(Stage.DYNAMIC_DONE)
    assert [r["app_id"] for r in needing] == ["1"]  # pinned app awaits dynamic


def test_outcome_removes_from_dynamic_queue(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.ipa")
    db.save_static_profile("1", DefenseProfile(pins_flag=True))
    db.save_outcome("1", Outcome.BYPASSED, BypassStage.DYLIB, pinned=True,
                    work_state=WorkState.POSITIVE)
    assert db.apps_needing(Stage.DYNAMIC_DONE) == []


def test_untested_outcome_stays_in_queue(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.ipa")
    db.save_static_profile("1", DefenseProfile(pins_flag=True))
    db.save_outcome("1", Outcome.INCONCLUSIVE, BypassStage.NONE, pinned=False,
                    work_state=WorkState.UNTESTED)
    assert [r["app_id"] for r in db.apps_needing(Stage.DYNAMIC_DONE)] == ["1"]


def test_add_column_if_missing_is_idempotent(tmp_path):
    db = _db(tmp_path)
    db.add_column_if_missing("outcome", "notes", "TEXT")
    db.add_column_if_missing("outcome", "notes", "TEXT")  # no error second time
    with db.connect() as c:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(outcome)")}
    assert "notes" in cols


def test_attestation_queue_only_appattest_apps(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.upsert_app("2", "us")
    db.save_acquisition("1", WorkState.POSITIVE)
    db.save_acquisition("2", WorkState.POSITIVE)
    db.save_static_profile("1", DefenseProfile(appattest_flag=True))
    db.save_static_profile("2", DefenseProfile(appattest_flag=False))
    needing = [r["app_id"] for r in db.apps_needing(Stage.ATTESTATION_DONE)]
    assert needing == ["1"]


# ---- audit 2026-10-18: acquisition versions, retry budget, NULL handling ----

def test_acquisition_versions_do_not_touch_canonical_row(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us", bundle_id="com.a")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.decrypted.ipa")
    db.save_acquisition_version("1", "842", WorkState.DONE_NEGATIVE, error="version 842 not found")
    db.save_acquisition_version("1", "900", WorkState.POSITIVE, ipa_path="/x/1-v900.decrypted.ipa")
    ac = db.get_acquisition("1")
    assert ac["decrypt_status"] == int(WorkState.POSITIVE)
    assert ac["ipa_path"] == "/x/1.decrypted.ipa"
    vers = {v["version_id"]: v for v in db.get_acquisition_versions("1")}
    assert vers["842"]["status"] == int(WorkState.DONE_NEGATIVE)
    assert vers["900"]["ipa_path"] == "/x/1-v900.decrypted.ipa"
    # upsert on the same version replaces
    db.save_acquisition_version("1", "842", WorkState.POSITIVE, ipa_path="/x/1-v842.decrypted.ipa")
    assert len(db.get_acquisition_versions("1")) == 2


def test_acquire_queue_skips_after_max_attempts(tmp_path, monkeypatch):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.upsert_app("2", "us")
    assert {r["app_id"] for r in db.apps_needing(Stage.ACQUIRED)} == {"1", "2"}
    for _ in range(5):
        db.record_acquisition_attempt("1", "timeout")
    assert db.get_acquisition("1")["attempts"] == 5
    assert db.get_acquisition("1")["last_error"] == "timeout"
    assert [r["app_id"] for r in db.apps_needing(Stage.ACQUIRED)] == ["2"]
    # a bigger budget via env brings it back
    monkeypatch.setenv("ACQUIRE_MAX_ATTEMPTS", "10")
    assert {r["app_id"] for r in db.apps_needing(Stage.ACQUIRED)} == {"1", "2"}
    assert db.apps_needing(Stage.ACQUIRED, max_attempts=3) and \
        [r["app_id"] for r in db.apps_needing(Stage.ACQUIRED, max_attempts=3)] == ["2"]
    # a save_acquisition upsert must not reset the attempt counter
    db.save_acquisition("1", WorkState.UNTESTED, error="again")
    assert db.get_acquisition("1")["attempts"] == 5


def test_save_analysis_stores_sql_null_for_none(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_analysis("1", {"info_plist": {"a": 1}, "binary_type": None})
    with db.connect() as c:
        row = c.execute("SELECT info_plist, binary_type, dependencies, "
                        "typeof(binary_type) t FROM analysis WHERE app_id='1'").fetchone()
    assert json.loads(row["info_plist"]) == {"a": 1}
    assert row["binary_type"] is None and row["t"] == "null"
    assert row["dependencies"] is None


def test_app_id_for_bundle(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("310633997", "us", bundle_id="net.whatsapp.WhatsApp")
    assert db.app_id_for_bundle("net.whatsapp.WhatsApp") == "310633997"
    assert db.app_id_for_bundle("com.nope") is None
    assert db.app_id_for_bundle("") is None


def test_iap_bypass_inconclusive_stores_null_tamperable(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_iap_bypass("1", "inconclusive", {"tamperable": None, "error": "unparseable"}, 3)
    assert db.get_iap_bypass("1")["tamperable"] is None
    db.save_iap_bypass("1", "bypassable", {"tamperable": True}, 3)
    assert db.get_iap_bypass("1")["tamperable"] == 1


# ---- acquire.py keying / versioned results / failure patterns ----

def _acquire_env(monkeypatch):
    """acquire.py with a reachable, bootstrapped decrypt device and appstore mode
    (CONFIG is a frozen dataclass, so swap the module's reference)."""
    import types
    import pipeline.acquire as acq
    from pipeline.config import CONFIG
    dd = types.SimpleNamespace(is_bootstrapped=True, online=lambda timeout=2.5: True,
                               ssh_host="10.0.0.1", ssh_port=22)
    monkeypatch.setattr(acq, "CONFIG", types.SimpleNamespace(
        decrypt_device=dd, acquire_mode="appstore", paths=CONFIG.paths))
    return acq


def test_acquire_one_reuses_corpus_app_id_for_bundle(tmp_path, monkeypatch):
    acq = _acquire_env(monkeypatch)
    db = _db(tmp_path)
    db.upsert_app("555", "us", bundle_id="com.example.app", name="Ex")
    seen = {}

    def fake_decrypt_one(app_id, row, *a, **kw):
        seen["key"] = app_id
        return WorkState.POSITIVE, f"/ipas/{app_id}.decrypted.ipa", ""
    monkeypatch.setattr(acq, "decrypt_one", fake_decrypt_one)

    state, path, err = acq.acquire_one(db, bundle_id="com.example.app")
    assert state == WorkState.POSITIVE and seen["key"] == "555"
    with db.connect() as c:
        assert c.execute("SELECT COUNT(*) FROM apps").fetchone()[0] == 1
    assert db.get_acquisition("555")["ipa_path"] == "/ipas/555.decrypted.ipa"
    assert db.get_acquisition("com.example.app") is None


def test_acquire_one_versioned_never_clobbers_canonical(tmp_path, monkeypatch):
    acq = _acquire_env(monkeypatch)
    db = _db(tmp_path)
    db.upsert_app("555", "us", bundle_id="com.example.app")
    db.save_acquisition("555", WorkState.POSITIVE, ipa_path="/ipas/555.decrypted.ipa")
    monkeypatch.setattr(acq, "decrypt_one", lambda app_id, row, *a, **kw:
                        (WorkState.DONE_NEGATIVE, "", "version 842 not found in app history"))
    state, _, _ = acq.acquire_one(db, app_id="555", app_ver_id="842")
    assert state == WorkState.DONE_NEGATIVE
    ac = db.get_acquisition("555")
    assert ac["decrypt_status"] == int(WorkState.POSITIVE)       # untouched
    assert ac["ipa_path"] == "/ipas/555.decrypted.ipa"
    v = db.get_acquisition_versions("555")
    assert len(v) == 1 and v[0]["version_id"] == "842" and v[0]["status"] == int(WorkState.DONE_NEGATIVE)


def test_acquire_one_counts_transient_attempts(tmp_path, monkeypatch):
    acq = _acquire_env(monkeypatch)
    db = _db(tmp_path)
    db.upsert_app("555", "us", bundle_id="com.example.app")
    monkeypatch.setattr(acq, "decrypt_one", lambda app_id, row, *a, **kw:
                        (WorkState.UNTESTED, "", "timeout"))
    acq.acquire_one(db, app_id="555")
    acq.acquire_one(db, app_id="555")
    ac = db.get_acquisition("555")
    assert ac["attempts"] == 2 and ac["last_error"] == "timeout"


def test_permanent_failure_patterns_are_anchored_and_errorish_only():
    from pipeline.acquire import _error_lines, is_permanent_failure, is_too_large
    # a container UUID containing 404 in progress output is NOT a permanent failure
    out = ("[*] installing to /var/containers/Bundle/Application/3F2A404B-1C3D-4E5F/x.app\n"
           "[*] waiting\n[*] still waiting\n[*] done\n")
    assert not is_permanent_failure(out)
    assert is_permanent_failure("[!] error: app not found in storefront US")
    assert is_permanent_failure("fetch failed: HTTP 404 for item")
    assert is_permanent_failure("status: 404")
    assert not is_permanent_failure("error: id 4041 bad")           # word boundary
    assert not is_permanent_failure("error: HTTP 4040")
    # prose in a non-error line is ignored; the same words in an error line fire
    assert not is_permanent_failure("note: this build is not available for preview\n[*] a\n[*] b\n[*] c\n")
    assert is_permanent_failure("✗ item not available in this storefront")
    assert is_permanent_failure("error: app does not exist")
    # final status lines count even without an error keyword
    assert is_permanent_failure("[*] start\n[*] working\nno such app: com.x")
    assert not is_too_large("the container exceeds nothing here\n[*] a\n[*] b\n[*] c")
    assert is_too_large("error: app is too large for the device")
    assert is_too_large("error: size exceeds the 4 GB limit")
    assert _error_lines("") == []
    # transport / device trouble is transient even when worded like a miss
    assert not is_permanent_failure("error: device not found (usbmuxd)")
    assert not is_permanent_failure("ssh: connect to host 10.0.0.5 port 22: host not found")
    # ...but a genuine store miss on its own line still counts
    assert is_permanent_failure("ssh ok\nerror: app not found in storefront")


def test_uninstall_script_requires_exact_bundle_id_match():
    import plistlib
    import subprocess
    import tempfile
    from pathlib import Path
    from pipeline.acquire import _uninstall_script
    script = _uninstall_script("com.foo")
    assert 'grep -qa "$BID"' not in script          # the unanchored regex is gone
    assert "plutil -extract" in script and "CFBundleIdentifier" in script
    assert "MCMMetadataIdentifier" in script
    fn = script.split("find /var/containers")[0]    # the `matches` helper only
    d = Path(tempfile.mkdtemp())
    (d / "exact.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.foo"}))
    (d / "longer.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.foo.bar"}))
    (d / "other.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "comXfoo"}))
    for variant in (fn, fn.replace("command -v plutil >/dev/null 2>&1", "false")):
        rcs = {f: subprocess.run(["sh", "-c", variant + f' matches CFBundleIdentifier "{d / f}"']).returncode
               for f in ("exact.plist", "longer.plist", "other.plist")}
        assert rcs == {"exact.plist": 0, "longer.plist": 1, "other.plist": 1}, rcs


def test_decrypt_ssh_argv_keeps_password_off_argv(tmp_path, monkeypatch):
    import json
    import shutil
    from pathlib import Path
    import pipeline.acquire as acq
    home = tmp_path / "home"
    (home / ".ipadecrypt").mkdir(parents=True)
    (home / ".ipadecrypt" / "config.json").write_text(json.dumps(
        {"device": {"host": "10.0.0.5", "port": 22, "user": "root",
                    "auth": {"method": "password", "password": "s3cret"}}}))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/sshpass")
    argv, env = acq._decrypt_ssh_argv("echo hi")
    assert "s3cret" not in " ".join(argv)
    assert argv[:2] == ["sshpass", "-e"]
    assert env["SSHPASS"] == "s3cret"
    assert argv[-2:] == ["root@10.0.0.5", "echo hi"]


def test_sync_ipadecrypt_host_only_explicit_user_port(tmp_path, monkeypatch):
    import json
    import types
    import pipeline.acquire as acq
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"device": {"host": "10.0.0.1", "port": 2222, "user": "mobile"}}))
    dd = types.SimpleNamespace(ssh_host="10.0.0.9", ssh_port=22, ssh_user="root",
                               bootstrap_config=cfg)
    monkeypatch.setattr(acq, "CONFIG", types.SimpleNamespace(decrypt_device=dd))
    monkeypatch.delenv("DECRYPT_SSH_PORT", raising=False)
    monkeypatch.delenv("DECRYPT_SSH_USER", raising=False)
    acq.sync_ipadecrypt_host()
    dev = json.loads(cfg.read_text())["device"]
    assert dev == {"host": "10.0.0.9", "port": 2222, "user": "mobile"}   # defaults did not clobber
    monkeypatch.setenv("DECRYPT_SSH_PORT", "22")
    monkeypatch.setenv("DECRYPT_SSH_USER", "root")
    acq.sync_ipadecrypt_host()
    dev = json.loads(cfg.read_text())["device"]
    assert dev == {"host": "10.0.0.9", "port": 22, "user": "root"}
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".config.json.")]  # temp cleaned


def test_download_with_ipatool_rejects_stale_staged_file(tmp_path, monkeypatch):
    import types
    import pipeline.acquire as acq
    from pipeline.util import Proc
    work = tmp_path / "work"
    work.mkdir()
    stale = work / "1.enc.ipa"
    stale.write_bytes(b"old")
    monkeypatch.setattr(acq, "CONFIG", types.SimpleNamespace(
        paths=types.SimpleNamespace(work_dir=work),
        ipatool=types.SimpleNamespace(cmd="ipatool")))
    monkeypatch.setattr(acq, "run_cmd", lambda *a, **k: Proc(1, "", "network down"))
    ok, path, err = acq.download_with_ipatool("1", {"bundle_id": "com.x"})
    assert not ok and not stale.exists() and "network down" in err
    # a successful command that produced a file is accepted
    def good(cmd, **k):
        stale.write_bytes(b"fresh")
        return Proc(0, "ok", "")
    monkeypatch.setattr(acq, "run_cmd", good)
    ok, path, err = acq.download_with_ipatool("1", {"bundle_id": "com.x"})
    assert ok and path == str(stale)


# ---- config: .env parsing ----

def test_dotenv_parsing_rules(tmp_path, monkeypatch):
    from pipeline.config import _load_dotenv, _parse_dotenv_line
    assert _parse_dotenv_line("export KEY=VALUE") == ("KEY", "VALUE")
    assert _parse_dotenv_line("KEY=val # comment") == ("KEY", "val")
    assert _parse_dotenv_line("KEY=p#ss") == ("KEY", "p#ss")           # no whitespace: not a comment
    assert _parse_dotenv_line("KEY='a # b'") == ("KEY", "a # b")
    assert _parse_dotenv_line('KEY="x\'y"') == ("KEY", "x'y")
    assert _parse_dotenv_line("KEY='abc\"") == ("KEY", "'abc\"")       # mismatched quotes stay
    assert _parse_dotenv_line('KEY="two words" # note') == ("KEY", "two words")
    assert _parse_dotenv_line("KEY='it''s'") == ("KEY", "'it''s'")        # odd quoting kept raw
    assert _parse_dotenv_line("KEY=") is None
    assert _parse_dotenv_line("KEY=''") is None
    assert _parse_dotenv_line("# comment") is None
    assert _parse_dotenv_line("1BAD=x") is None
    env = tmp_path / ".env"
    env.write_text("export A_KEY=1\nEMPTY_KEY=\nB_KEY=\"two words\" # note\n")
    monkeypatch.delenv("A_KEY", raising=False)
    monkeypatch.delenv("EMPTY_KEY", raising=False)
    monkeypatch.delenv("B_KEY", raising=False)
    _load_dotenv(env)
    import os
    assert os.environ["A_KEY"] == "1"
    assert "EMPTY_KEY" not in os.environ          # defaults apply
    assert os.environ["B_KEY"] == "two words"


# ---- llm_driver: never raises on malformed responses ----

def test_llm_driver_parsing_is_robust(monkeypatch):
    import pipeline.llm_driver as ld
    monkeypatch.setenv("JEV_API_KEY", "k")
    responses = iter([
        None, [], "str", {"answers": None}, {"answers": {"pick": "x"}},
        {"answers": {"pick": {"choice": "opt-1", "confidence": 0.9}}},
        {"answers": {"pick": {"choice": "opt7", "confidence": 0.9}}},
        {"answers": {"pick": {"choice": "opt0", "confidence": "high"}}},
        {"answers": {"pick": {"choice": "opt0", "confidence": float("nan")}}},
        {"answers": {"pick": {"choice": 3, "confidence": 0.9}}},
    ])
    monkeypatch.setattr(ld, "_post", lambda body, timeout=20: next(responses))
    for _ in range(10):
        assert ld.choose_next_control(["Continue", "Help"], "screen") is None
    monkeypatch.setattr(ld, "_post", lambda body, timeout=20:
                        {"answers": {"pick": {"choice": "opt1", "confidence": "0.95"}}})
    assert ld.choose_next_control(["Continue", "Help"], "screen") == "Help"
    goals = iter([None, {"answers": {"goal": {"noul": "yes"}}}, {"answers": {"goal": {"noul": 0.8}}}])
    monkeypatch.setattr(ld, "_post", lambda body, timeout=20: next(goals))
    assert ld.login_goal_reached("s") is False
    assert ld.login_goal_reached("s") is False
    assert ld.login_goal_reached("s") is True


# ---- instrument: traversal guards + p12 password off argv ----

def test_instrument_rejects_traversal(tmp_path):
    import pytest
    from pipeline import instrument
    with pytest.raises(ValueError):
        instrument.DylibSpec("../evil.dylib", "x.dylib", "weak")
    with pytest.raises(ValueError):
        instrument.DylibSpec("a.dylib", "sub/x.dylib", "weak")
    with pytest.raises(ValueError):
        instrument.validate_config_label("../../etc")
    with pytest.raises(ValueError):
        instrument.validate_config_label("a/b")
    assert instrument.validate_config_label("custom:ssks,sideloadfix") == "custom:ssks,sideloadfix"
    assert instrument.validate_config_label("pinning:clean")
    with pytest.raises(ValueError):
        instrument.build("1", tmp_path / "x.ipa", "../x")
    # catalog ids still build valid specs
    assert all(isinstance(s, instrument.DylibSpec) for s in instrument.custom_specs(["ssks", "evasion"]))


def test_ensure_pem_passes_password_via_env(tmp_path, monkeypatch):
    import types
    from pipeline import instrument
    from pipeline.util import Proc
    p12 = tmp_path / "c.p12"; p12.write_bytes(b"x")
    rs = types.SimpleNamespace(pem=tmp_path / "c.pem", p12=p12, p12_password="pw-secret")
    calls = []

    def fake_run(cmd, timeout=60, env=None, **kw):
        calls.append((cmd, env))
        rs.pem.write_text("PEM")
        return Proc(0, "", "")
    monkeypatch.setattr(instrument, "run_cmd", fake_run)
    assert instrument.ensure_pem(rs)
    cmd, env = calls[0]
    assert "pw-secret" not in " ".join(cmd)
    assert "env:HAVVA_P12_PW" in cmd and env["HAVVA_P12_PW"] == "pw-secret"


# ---- aggregate: partial coverage + consistent bypass population ----

def test_aggregate_partial_and_population(tmp_path):
    from pipeline import aggregate
    from pipeline.models import BackendBehavior
    db = _db(tmp_path)
    for i in "123456":
        db.upsert_app(i, "us")
    # pinned, decided: 1 bypassed, 2 pinned_unbypassed ; pinned but UNTESTED: 3 ; not pinned: 4
    db.save_outcome("1", Outcome.BYPASSED, BypassStage.DYLIB, True, WorkState.POSITIVE)
    db.save_outcome("2", Outcome.PINNED_UNBYPASSED, BypassStage.NONE, True, WorkState.DONE_NEGATIVE)
    db.save_outcome("3", Outcome.INCONCLUSIVE, BypassStage.NONE, True, WorkState.UNTESTED)
    db.save_outcome("4", Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.POSITIVE)
    db.add_column_if_missing("attestation", "verdict", "TEXT")
    for aid, beh, verdict in (("1", BackendBehavior.FAIL_CLOSED, "enforced"),
                              ("2", BackendBehavior.FAIL_OPEN, "partial_coverage"),
                              ("3", BackendBehavior.FAIL_OPEN, "replayable")):
        db.save_attestation(aid, True, False, beh, WorkState.POSITIVE)
        with db.connect() as c:
            c.execute("UPDATE attestation SET verdict=? WHERE app_id=?", (verdict, aid))
    m = aggregate.compute(db)
    b = m["bypass"]
    assert b["pinned_tested"] == 2 and b["pinned_untested_excluded"] == 1
    assert b["bypassed"] == 1 and b["bypass_rate_pct_of_pinned_evaluated"] == 50.0
    a = m["attestation"]
    assert a["tested"] == 3
    assert a["fail_closed"] == 1 and a["partial"] == 1 and a["fail_open"] == 1
    assert a["partial_pct_of_tested"] == 33.3
    md = aggregate._markdown(m)
    assert "partial" in md
