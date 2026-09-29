"""Tests for the pure attestation-usage detection logic (marker trail + ladder)."""

from pipeline.attest_detect import (
    _endpoint_found, classify_confidence, parse_trail,
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


# ---- endpoint correlation ----

def test_endpoint_found_by_assertion_header():
    flows = [
        Flow(url="https://gsp.apple.com/x", method="GET", status=200,
             host="gsp.apple.com", request_headers={"x-app-attest": "z"}),
        Flow(url="https://api.example.com/e", method="POST", status=200,
             host="api.example.com", request_headers={"x-attestation": "blob"}),
    ]
    assert _endpoint_found(flows) == "api.example.com"


def test_endpoint_empty_when_no_assertion_header():
    flows = [Flow(url="https://api.example.com/e", method="GET", status=200,
                  host="api.example.com", request_headers={"accept": "*/*"})]
    assert _endpoint_found(flows) == ""
