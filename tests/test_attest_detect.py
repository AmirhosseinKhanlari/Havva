"""Tests for the pure attestation-usage detection logic (marker trail + ladder)."""

import json

from pipeline.attest_detect import (
    _ASSERT_HEADER_RE, _attest_requests, _endpoint_found, _flow_attest_hits,
    appattest_status, classify_confidence, devicecheck_status, parse_trail,
    static_signals, Trail,
)
from pipeline.models import AttestConfidence, Flow


# ---- confidence ladder ----

def test_confidence_ladder():
    assert classify_confidence(False, False, [], False) is AttestConfidence.NONE
    assert classify_confidence(True, False, [], False) is AttestConfidence.CAPABLE
    assert classify_confidence(False, True, [], False) is AttestConfidence.LIKELY
    assert classify_confidence(False, True, ["DCAppAttestService x"], False) \
        is AttestConfidence.CONFIRMED_ACTIVE
    assert classify_confidence(True, True, ["DCAppAttestService x"], True) \
        is AttestConfidence.CONFIRMED_LOCATED


def test_dynamic_never_downgrades_static():
    assert classify_confidence(True, True, [], False) is AttestConfidence.LIKELY


# ---- marker-trail parsing (the tooling-worked question) ----

def _log(*lines):
    return "\n".join("Sep 28 10:00:00 iPhone App(App)[123] <Notice>: OBSERVER " + l
                     for l in lines)


def test_trail_confirmed_usage():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCAppAttestService",
                         "HOOK_VERIFIED generateAssertion:clientDataHash:completionHandler:",
                         "CALL DCAppAttestService generateAssertion"))
    assert t.loaded and t.class_present and t.verified and t.calls
    assert t.tooling_ok
    assert any("generateAssertion" in c for c in t.calls)
    assert t.present == ["DCAppAttestService"]


def test_trail_armed_but_no_call_is_tooling_ok_negative():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCAppAttestService",
                         "HOOK_VERIFIED generateKeyWithCompletionHandler:"))
    assert t.tooling_ok and not t.calls   # hook worked, just not invoked


def test_trail_class_absent_is_confident_negative():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_ABSENT DCAppAttestService"))
    assert t.tooling_ok and t.class_absent and not t.calls


def test_trail_not_loaded_is_tooling_broken():
    t = parse_trail("unrelated syslog with no markers")
    assert not t.loaded and not t.tooling_ok


def test_trail_hook_failed_not_tooling_ok():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCAppAttestService",
                         "HOOK_FAILED generateAssertion:clientDataHash:completionHandler:"))
    assert t.loaded and t.failed and not t.verified and not t.tooling_ok


# ---- reliability: a dead app cannot yield a reliable negative ----

def test_crashed_run_without_calls_is_not_reliable():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCAppAttestService",
                         "HOOK_VERIFIED generateKeyWithCompletionHandler:"))
    assert t.hooks_armed and t.tooling_ok
    t.crash_report = "some .ips content"
    assert t.crashed
    assert t.hooks_armed            # the hooks did arm ...
    assert not t.tooling_ok         # ... but "present, not called" is unreliable


def test_crashed_run_with_call_is_still_reliable_positive():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCAppAttestService",
                         "HOOK_VERIFIED attestKey:clientDataHash:completionHandler:",
                         "CALL DCAppAttestService attestKey"))
    t.crash_report = "crashed after attesting"
    assert t.crashed and t.calls and t.tooling_ok


def test_launch_failed_is_not_reliable_and_not_crashed():
    t = Trail(launch_failed=True)
    assert not t.tooling_ok and not t.crashed
    t2 = parse_trail(_log("OBSERVER_LOADED", "CLASS_ABSENT DCAppAttestService"))
    t2.launch_failed = True
    assert not t2.tooling_ok


# ---- App Attest vs DeviceCheck separation ----

def _devicecheck_only_trail():
    return parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCDevice",
                            "HOOK_VERIFIED generateTokenWithCompletionHandler:",
                            "CALL DCDevice generateToken"))


def test_devicecheck_only_trail_is_not_appattest_confirmed():
    t = _devicecheck_only_trail()
    assert t.calls == ["DCDevice generateToken"]
    aa_calls = t.appattest_calls
    assert aa_calls == []
    # The ladder is fed App Attest calls only: DeviceCheck alone never confirms.
    assert classify_confidence(False, False, aa_calls, True) is AttestConfidence.NONE
    assert classify_confidence(False, True, aa_calls, False) is AttestConfidence.LIKELY
    dc = devicecheck_status(t)
    assert dc == {"present": True, "called": True, "calls": ["DCDevice generateToken"]}
    aa = appattest_status(t)
    assert aa["present"] is False and aa["called"] is False and aa["calls"] == []


def test_devicecheck_present_not_called():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCDevice",
                         "HOOK_VERIFIED generateTokenWithCompletionHandler:"))
    dc = devicecheck_status(t)
    assert dc["present"] and not dc["called"] and dc["calls"] == []
    assert t.tooling_ok


def test_both_apis_called_separated():
    t = parse_trail(_log("OBSERVER_LOADED", "CLASS_PRESENT DCAppAttestService",
                         "CLASS_PRESENT DCDevice",
                         "HOOK_VERIFIED generateAssertion:clientDataHash:completionHandler:",
                         "HOOK_VERIFIED generateTokenWithCompletionHandler:",
                         "CALL DCAppAttestService generateAssertion",
                         "CALL DCDevice generateToken"))
    assert t.appattest_calls == ["DCAppAttestService generateAssertion"]
    assert t.devicecheck_calls == ["DCDevice generateToken"]
    assert classify_confidence(False, False, t.appattest_calls, False) \
        is AttestConfidence.CONFIRMED_ACTIVE


# ---- static signals: new split keys vs legacy combined key ----

def test_static_signals_new_keys_make_capable_reachable():
    mp = json.dumps({"appattest_entitlement": [
        "com.apple.developer.devicecheck.appattest-environment=production"],
        "appattest_symbols": []})
    ent, sym = static_signals(True, mp)
    assert ent and not sym
    assert classify_confidence(ent, sym, [], False) is AttestConfidence.CAPABLE


def test_static_signals_new_keys_symbols():
    mp = json.dumps({"appattest_entitlement": [], "appattest_symbols": ["DCAppAttestService"]})
    ent, sym = static_signals(True, mp)
    assert sym and not ent
    assert classify_confidence(ent, sym, [], False) is AttestConfidence.LIKELY


def test_static_signals_legacy_key_fallback():
    legacy = json.dumps({"appattest": [
        "DCAppAttestService",
        "com.apple.developer.devicecheck.appattest-environment=production"]})
    assert static_signals(True, legacy) == (True, True)
    legacy_ent_only = json.dumps({"appattest": [
        "com.apple.developer.devicecheck.appattest-environment=development"]})
    assert static_signals(True, legacy_ent_only) == (True, False)
    legacy_sym_only = json.dumps({"appattest": ["DCAppAttestService"]})
    assert static_signals(True, legacy_sym_only) == (False, True)


def test_static_signals_missing_or_garbage():
    assert static_signals(False, None) == (False, False)
    assert static_signals(True, None) == (False, True)
    assert static_signals(True, "not json{") == (False, True)
    assert static_signals(False, json.dumps(["list", "not", "dict"])) == (False, False)


# ---- endpoint correlation ----

def test_endpoint_found_by_assertion_header():
    flows = [
        Flow(url="https://gsp.apple.com/x", method="GET", status=200,
             host="gsp.apple.com", request_headers={"x-app-attest": "z"}),
        Flow(url="https://api.example.com/e", method="POST", status=200,
             host="api.example.com", request_headers={"x-attestation": "blob-blob-blob-blob-blob"}),
    ]
    assert _endpoint_found(flows) == "api.example.com"


def test_endpoint_empty_when_no_assertion_header():
    flows = [Flow(url="https://api.example.com/e", method="GET", status=200,
                  host="api.example.com", request_headers={"accept": "*/*"})]
    assert _endpoint_found(flows) == ""


def test_header_value_is_scanned_not_just_name():
    f = Flow(url="https://api.example.com/e", method="POST", status=200,
             host="api.example.com",
             request_headers={"authorization": "AppCheck eyJhbGciOi"})
    assert _flow_attest_hits(f) == ["authorization"]
    assert _endpoint_found([f]) == "api.example.com"


def test_client_assertion_oauth_body_is_not_attestation():
    body = ("grant_type=client_credentials&client_assertion_type="
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            "&client_assertion=eyJhbGciOiJSUzI1NiJ9.e30.sig&clientAssertion=x")
    f = Flow(url="https://auth.example.com/oauth/token", method="POST", status=200,
             host="auth.example.com",
             request_headers={"content-type": "application/x-www-form-urlencoded"},
             request_body=body)
    assert _flow_attest_hits(f) == []
    assert _endpoint_found([f]) == ""
    assert _attest_requests([f]) == []
    # The plain assertion wording still matches.
    assert _ASSERT_HEADER_RE.search("x-assertion")
    assert _ASSERT_HEADER_RE.search('{"assertion":"..."}')
    assert not _ASSERT_HEADER_RE.search("client_assertion")
    assert not _ASSERT_HEADER_RE.search("client-assertion-type")
    assert not _ASSERT_HEADER_RE.search("clientAssertion")


def test_attest_requests_signal_names_header_and_body():
    f = Flow(url="https://api.example.com/attest", method="POST", status=200,
             host="api.example.com",
             request_headers={"x-attestation": "blob-blob-blob-blob-blob", "accept": "*/*"},
             request_body='{"attestationObject":"..."}')
    reqs = _attest_requests([f])
    assert len(reqs) == 1
    assert reqs[0]["host"] == "api.example.com"
    assert reqs[0]["signal"] == "body, x-attestation"
