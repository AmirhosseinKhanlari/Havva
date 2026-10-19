"""Attestation probe battery after the review: content fingerprints, soft
enforcement, new probes, coverage classes, timing correlation, isSupported."""
from __future__ import annotations

import base64
import json
from types import SimpleNamespace

from pipeline import attest_detect, attestation
from pipeline.attestation import (ASSERTION_B64_PREFIX, ATTESTATION_B64_PREFIX, _coverage_class,
                                  _grade, _materialize_script, _probe_outcome, _response_similar,
                                  assertion_evidence, assertion_fingerprint)
from pipeline.models import BackendBehavior, EnforcementVerdict, Flow


def _flow(url, headers=None, status=200, body="x" * 200, req_body="", started="", method="POST"):
    from pipeline.capture import host_from_url
    return Flow(url=url, method=method, status=status, host=host_from_url(url),
                request_headers={k.lower(): v for k, v in (headers or {}).items()},
                request_body=req_body, response_body=body, started=started)


def _real_assertion_b64():
    # CBOR: a2 69 'signature' 58 46 <70 bytes> 71 'authenticatorData' 58 25 <37 bytes>
    sig = b"\x30\x44\x02\x20" + b"\x11" * 32 + b"\x02\x20" + b"\x22" * 32
    cbor = b"\xa2" + b"\x69signature" + b"\x58" + bytes([len(sig)]) + sig \
        + b"\x71authenticatorData" + b"\x58\x25" + b"\x00" * 37
    return base64.b64encode(cbor).decode()


def test_fingerprints_match_real_cbor_layout():
    b64 = _real_assertion_b64()
    assert b64.startswith(ASSERTION_B64_PREFIX)
    assert assertion_fingerprint('{"assertion":"' + b64 + '"}') == "cbor-assertion"
    att = base64.b64encode(b"\xa3cfmtoapple-appattest" + b"\x00" * 40).decode()
    assert att.startswith(ATTESTATION_B64_PREFIX)
    assert assertion_fingerprint(att) == "cbor-attestation"
    assert assertion_fingerprint("a2697369676e6174757265" + "00" * 40) == "cbor-assertion"
    assert assertion_fingerprint("hello world") is None


def test_evidence_by_content_regardless_of_header_name():
    f = _flow("https://api.example.com/score", headers={"x-proof": _real_assertion_b64()})
    hits = assertion_evidence(f)
    assert "x-proof" in hits and "cbor-assertion" in hits
    g = _flow("https://api.example.com/score", req_body=json.dumps({"p": _real_assertion_b64()}))
    assert "body" in assertion_evidence(g) and "cbor-assertion" in assertion_evidence(g)
    # The usage stage shares the same judgement.
    assert attest_detect._endpoint_found([f]) == "api.example.com"


def test_probe_outcome_distinguishes_full_served_from_degraded():
    gated = {"api.example.com/entitlements"}
    base = [_flow("https://api.example.com/entitlements", headers={"x-assertion": "a" * 40},
                  body=json.dumps({"tier": "pro", "features": [1, 2, 3], "exp": 9, "pad": "x" * 80}))]
    full = [_flow("https://api.example.com/entitlements", headers={"x-assertion": "b" * 40},
                  body=json.dumps({"tier": "pro", "features": [1, 2, 3], "exp": 10, "pad": "y" * 80}))]
    degraded = [_flow("https://api.example.com/entitlements", headers={"x-assertion": "b" * 40},
                      body=json.dumps({"error": "integrity", "code": 7, "pad": "z" * 80}))]
    refused = [_flow("https://api.example.com/entitlements", headers={"x-assertion": "b" * 40},
                     status=403, body="")]
    assert _probe_outcome("tamper", gated, full, True, True, base)[0] is True
    assert _probe_outcome("tamper", gated, degraded, True, True, base)[0] == "degraded"
    assert _probe_outcome("tamper", gated, refused, True, True, base)[0] is False
    # omit: the request must NOT carry an assertion; an empty header counts as omitted.
    omitted = [_flow("https://api.example.com/entitlements", headers={"x-assertion": ""},
                     body=json.dumps({"tier": "pro", "features": [1, 2, 3], "exp": 9, "pad": "x" * 80}))]
    assert _probe_outcome("omit", gated, omitted, True, True, base)[0] is True


def test_response_similarity_rules():
    a = _flow("https://a/x", body=json.dumps({"a": 1, "b": 2, "c": 3}))
    assert _response_similar(a, _flow("https://a/x", body=json.dumps({"a": 9, "b": 8, "c": 7})))
    assert not _response_similar(a, _flow("https://a/x", body=json.dumps({"error": 1})))
    assert not _response_similar(a, _flow("https://a/x", status=503, body="x" * 20))
    assert not _response_similar(_flow("https://a/x", body="y" * 1000), _flow("https://a/x", body="y" * 100))


def test_grade_new_rungs_and_soft():
    ok = {"baseline": True, "tamper": False, "omit": False}
    assert _grade(ok, (2, 2)) is EnforcementVerdict.ENFORCED
    assert _grade({**ok, "bind": True}, (2, 2)) is EnforcementVerdict.UNBOUND_REQUEST
    assert _grade({**ok, "replay": True}, (2, 2)) is EnforcementVerdict.REPLAYABLE
    assert _grade({"baseline": True, "tamper": True, "bind": True}, (2, 2)) is EnforcementVerdict.SIGNATURE_NOT_VERIFIED
    soft = {"baseline": True, "tamper": "degraded", "omit": False}
    assert _grade(soft, (2, 2)) is EnforcementVerdict.SOFT_DEGRADED
    assert attestation._to_behavior(EnforcementVerdict.SOFT_DEGRADED) is BackendBehavior.SOFT_DEGRADED
    # Coverage: a session-bound design is not partial.
    assert _grade(ok, (5, 2), "per_session") is EnforcementVerdict.ENFORCED
    assert _grade(ok, (5, 2), "partial") is EnforcementVerdict.PARTIAL_COVERAGE


def test_coverage_class_recognises_attest_at_login_then_session():
    login = _flow("https://api.example.com/login", headers={"x-assertion": "a" * 40},
                  started="2026-10-19T10:00:00.000Z")
    data1 = _flow("https://api.example.com/feed", headers={"authorization": "Bearer t"},
                  started="2026-10-19T10:00:05.000Z")
    data2 = _flow("https://api.example.com/me", headers={"cookie": "s=1"},
                  started="2026-10-19T10:00:06.000Z")
    assert _coverage_class([login, data1, data2]) == "per_session"
    naked = _flow("https://api.example.com/feed", headers={}, started="2026-10-19T10:00:05.000Z")
    assert _coverage_class([login, naked]) == "partial"
    assert _coverage_class([login]) == "per_request"
    assert _coverage_class([naked]) == "none"


def test_bind_script_is_materialised_with_gated_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(attestation, "CONFIG", SimpleNamespace(paths=SimpleNamespace(work_dir=tmp_path)))
    src = tmp_path / "attest_bind.js"
    src.write_text("const GATED = __GATED__;\n")
    out = _materialize_script(src, {"api.example.com/score", "api.example.com/buy"})
    assert out != src and 'const GATED = ["api.example.com/buy", "api.example.com/score"];' in out.read_text()
    plain = tmp_path / "attest_omit.js"
    plain.write_text("x")
    assert _materialize_script(plain, set()) == plain


def test_probe_build_uses_bypass_config():
    from pipeline import instrument
    specs = instrument.config_specs("attest_probe")
    names = [s.source for s in specs]
    assert any("Gadget" in n or "frida" in n.lower() for n in names)
    assert any("SSLKillSwitch" in n or n == instrument.CONFIG.dylibs.ssks for n in names)


# ---- usage detection: isSupported and timing --------------------------------

def test_is_supported_is_logged_but_not_usage():
    t = attest_detect.parse_trail("OBSERVER_LOADED\nCLASS_PRESENT DCAppAttestService\n"
                                  "HOOK_VERIFIED generateAssertion:clientDataHash:completionHandler:\n"
                                  "CALL DCAppAttestService isSupported=1\n")
    assert t.supported is True and t.appattest_calls == []
    assert attest_detect.classify_confidence(True, True, t.appattest_calls, False).value == "likely"


def test_timing_correlation_names_the_request_after_the_hook():
    syslog = ("Oct 19 10:00:03 iPhone Bank[9] <Notice>: OBSERVER CALL DCAppAttestService generateAssertion\n"
              "Oct 19 10:00:03 iPhone Bank[9] <Notice>: OBSERVER CALL DCAppAttestService isSupported=1\n")
    calls = attest_detect._call_times(syslog, year=2026)
    assert len(calls) == 1
    import datetime as _dt
    local = _dt.datetime(2026, 10, 19, 10, 0, 5).astimezone().isoformat()
    early = _dt.datetime(2026, 10, 19, 9, 59, 0).astimezone().isoformat()
    f_after = _flow("https://api.example.com/score", headers={"x-sig": "zzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
                    started=local)
    f_before = _flow("https://api.example.com/config", headers={}, started=early, method="GET")
    hits = attest_detect._timing_hits([f_before, f_after], calls)
    assert list(hits) == [1] and 1.5 <= hits[1] <= 2.5
    assert attest_detect._endpoint_found([f_before, f_after], syslog) == "api.example.com"
    reqs = attest_detect._attest_requests([f_before, f_after], syslog)
    assert len(reqs) == 1 and "timing(+2s)" in reqs[0]["signal"]


def test_static_attest_sdks_and_appcheck_providers():
    from pipeline.static_classify import ExtractedApp, classify
    p = classify(ExtractedApp(symbols="_OBJC_CLASS_$_FIRAppCheck\n_OBJC_CLASS_$_FIRAppCheckDebugProvider\nDCAppAttestService"))
    assert p.matched_patterns["attest_sdks"] == ["FirebaseAppCheck"]
    assert p.matched_patterns["appcheck_providers"] == ["debug"]
    q = classify(ExtractedApp(strings="ApproovService approov.io"))
    assert q.matched_patterns["attest_sdks"] == ["Approov"]


def test_flow_started_is_carried_from_har():
    from pipeline.capture import har_to_flows
    har = {"log": {"entries": [{"_clientAddress": "1.2.3.4", "startedDateTime": "2026-10-19T10:00:00.000Z",
                                "request": {"url": "https://a.com/x", "method": "GET", "headers": []},
                                "response": {"status": 200, "headers": [], "content": {"text": ""}}}]}}
    assert har_to_flows(har, "1.2.3.4")[0].started == "2026-10-19T10:00:00.000Z"


# ---- tiers from the baseline ----------------------------------------------------

from pipeline.attestation import classify_baseline, tier_of  # noqa: E402

_ATT = base64.b64encode(b"\xa3cfmtoapple-appattest" + b"\x00" * 60).decode()
_TRAIL_ENROLL = ("OBSERVER_LOADED\nCLASS_PRESENT DCAppAttestService\n"
                 "HOOK_VERIFIED attestKey:clientDataHash:completionHandler:\n"
                 "CALL DCAppAttestService generateKey\nCALL DCAppAttestService attestKey\n")
_TRAIL_ASSERT = _TRAIL_ENROLL + "CALL DCAppAttestService generateAssertion\n"


def _enroll(status, body="", host="api.example.com"):
    return _flow(f"https://{host}/attest/enroll", req_body=json.dumps({"attestation": _ATT}),
                 status=status, body=body)


def test_t0_refused_at_enrollment_requires_login_or_attest_wording():
    r = classify_baseline([_enroll(401, '{"error":"attestation invalid"}')], _TRAIL_ENROLL, "success")
    assert r["verdict"] is EnforcementVerdict.REFUSED_AT_ENROLLMENT and r["tier"] == "T0" and not r["proceed"]
    assert r["evidence"]["enrollment_uploads"][0]["status"] == 401
    # Attest-worded refusal counts even when login status is unknown.
    r = classify_baseline([_enroll(403, '{"code":"integrity_check_failed"}')], _TRAIL_ENROLL, "none")
    assert r["verdict"] is EnforcementVerdict.REFUSED_AT_ENROLLMENT
    # A refusal with no login and no wording is not attributable.
    r = classify_baseline([_enroll(401, '{"error":"unauthorized"}')], _TRAIL_ENROLL, "attempted")
    assert r["verdict"] is EnforcementVerdict.INCONCLUSIVE and "login did not complete" in r["reason"]
    # An unrelated refusal (version gate) is never T0.
    r = classify_baseline([_enroll(426, '{"error":"app version too old, please upgrade"}')], _TRAIL_ENROLL, "success")
    assert r["verdict"] is EnforcementVerdict.INCONCLUSIVE and "unrelated" in r["reason"]


def test_proceed_when_gated_endpoints_exist():
    data = _flow("https://api.example.com/entitlements", headers={"x-assertion": "a" * 40})
    r = classify_baseline([_enroll(200), data], _TRAIL_ASSERT, "success")
    assert r["proceed"] and r["verdict"] is None and r["evidence"]["gated_endpoints"] == ["api.example.com/entitlements"]


def test_t3_assertions_unused_and_not_used():
    plain = _flow("https://api.example.com/feed", headers={"authorization": "Bearer t"})
    r = classify_baseline([_enroll(200), plain], _TRAIL_ASSERT, "success")
    assert r["verdict"] is EnforcementVerdict.ASSERTION_UNUSED and r["tier"] == "T3"
    # Without a driven login the same picture is inconclusive, not T3.
    r = classify_baseline([_enroll(200), plain], _TRAIL_ASSERT, "none")
    assert r["verdict"] is EnforcementVerdict.INCONCLUSIVE
    # Observer loaded, no App Attest call at all, logged in: runtime non-adopter.
    r = classify_baseline([plain], "OBSERVER_LOADED\nCLASS_ABSENT DCAppAttestService\n", "success")
    assert r["verdict"] is EnforcementVerdict.NOT_USED and r["tier"] == "not_used"
    # Observer never loaded: tooling, not the app.
    r = classify_baseline([plain], "", "success")
    assert r["verdict"] is EnforcementVerdict.INCONCLUSIVE and "observer trail missing" in r["reason"]


def test_crash_and_login_failure_are_inconclusive_with_reason():
    r = classify_baseline([], _TRAIL_ENROLL, "attempted", crashed=True,
                          crash_reason="uncaught exception: requires an entitlement for keychain-access-groups")
    assert r["verdict"] is EnforcementVerdict.INCONCLUSIVE and "entitlement shim" in r["reason"]
    r = classify_baseline([], "OBSERVER_LOADED\n", "attempted")
    assert r["verdict"] is EnforcementVerdict.INCONCLUSIVE and "login attempted" in r["reason"]


def test_tier_mapping():
    assert tier_of(EnforcementVerdict.REFUSED_AT_ENROLLMENT) == "T0"
    assert tier_of(EnforcementVerdict.ENFORCED) == "T1" and tier_of(EnforcementVerdict.PARTIAL_COVERAGE) == "T1"
    assert tier_of(EnforcementVerdict.SOFT_DEGRADED) == "T1s"
    for v in (EnforcementVerdict.SIGNATURE_NOT_VERIFIED, EnforcementVerdict.NOT_REQUIRED,
              EnforcementVerdict.UNBOUND_REQUEST, EnforcementVerdict.REPLAYABLE, EnforcementVerdict.WEAK_OTHER):
        assert tier_of(v) == "T2"
    assert tier_of(EnforcementVerdict.ASSERTION_UNUSED) == "T3"
    assert tier_of(EnforcementVerdict.INCONCLUSIVE) == ""


def test_process_app_exits_early_on_t0_after_confirming(monkeypatch):
    calls = []

    def fake_run(app_id, bundle_id, decrypted, creds, script, gated=None):
        calls.append(script.stem if script else "baseline")
        return {"flows": [_enroll(401, '{"error":"attestation invalid"}')], "armed": False, "hit": False,
                "launched": True, "error": "", "login_status": "success", "crashed": False,
                "crash_reason": "", "syslog": _TRAIL_ENROLL}
    saved = {}
    monkeypatch.setattr(attestation, "_run_probe", fake_run)
    monkeypatch.setattr(attestation, "_save", lambda db, app_id, verdict, served, cov, state, error="", reasons=None:
                        saved.update(verdict=verdict, reasons=reasons, state=state))

    class _DB:
        def connect(self):
            class _C:
                def __enter__(s2): return s2
                def __exit__(s2, *a): return False
                def execute(s2, *a): return SimpleNamespace(fetchone=lambda: {"ipa_path": "/x.ipa"})
            return _C()
    v = attestation.process_app(_DB(), {"app_id": "1", "bundle_id": "com.example.bank"}, {"*": {"user": "u", "password": "p"}})
    assert v is EnforcementVerdict.REFUSED_AT_ENROLLMENT
    assert calls == ["baseline", "baseline"]        # confirmed once, no probe scripts ran
    assert saved["reasons"]["tier"] == "T0"


def test_default_battery_is_the_core_five():
    names = [n for n, _ in attestation.PROBES]
    assert names == ["baseline", "omit", "tamper", "bind", "replay"]
    assert [n for n, _ in attestation.PROBES_FULL][-2:] == ["noreg", "downgrade"]
    from pipeline import instrument
    assert any("AttestObserver" in s.source for s in instrument.config_specs("attest_probe"))
