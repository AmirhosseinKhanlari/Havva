"""Tests for the pure attestation-usage confidence logic."""

from pipeline.attest_detect import (
    _endpoint_found, _methods_from_output, classify_confidence,
)
from pipeline.models import AttestConfidence, Flow


def test_confidence_ladder():
    assert classify_confidence(False, False, [], False) is AttestConfidence.NONE
    assert classify_confidence(True, False, [], False) is AttestConfidence.CAPABLE
    assert classify_confidence(False, True, [], False) is AttestConfidence.LIKELY
    assert classify_confidence(False, True, ["DCAppAttestService x"], False) \
        is AttestConfidence.CONFIRMED_ACTIVE
    assert classify_confidence(True, True, ["DCAppAttestService x"], True) \
        is AttestConfidence.CONFIRMED_LOCATED


def test_dynamic_never_downgrades_static():
    # No runtime call observed, but symbols present -> still LIKELY (not NONE).
    assert classify_confidence(True, True, [], False) is AttestConfidence.LIKELY


def test_methods_parsed_from_frida_output():
    out = ("ATTEST_OBSERVE READY\n"
           "ATTEST_OBSERVE CALL DCAppAttestService generateKeyWithCompletionHandler:\n"
           "ATTEST_OBSERVE CALL DCAppAttestService generateAssertion:clientDataHash:completionHandler:\n"
           "ATTEST_OBSERVE CALL DCAppAttestService generateKeyWithCompletionHandler:\n")  # dup
    methods = _methods_from_output(out)
    assert len(methods) == 2
    assert any("generateAssertion" in m for m in methods)


def test_no_methods_when_no_markers():
    assert _methods_from_output("random frida logs\n") == []


def test_endpoint_found_by_assertion_header():
    flows = [
        Flow(url="https://gsp.apple.com/x", method="GET", status=200,
             host="gsp.apple.com", request_headers={"x-app-attest": "z"}),  # excluded
        Flow(url="https://api.example.com/e", method="POST", status=200,
             host="api.example.com", request_headers={"x-attestation": "blob"}),
    ]
    assert _endpoint_found(flows) == "api.example.com"


def test_endpoint_empty_when_no_assertion_header():
    flows = [Flow(url="https://api.example.com/e", method="GET", status=200,
                  host="api.example.com", request_headers={"accept": "*/*"})]
    assert _endpoint_found(flows) == ""
