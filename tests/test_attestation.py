"""Tests for the pure attestation grading + coverage logic."""

from pipeline.attestation import _coverage, _grade
from pipeline.models import EnforcementVerdict, Flow


def test_inconclusive_when_baseline_not_served():
    assert _grade({"baseline": False}, (0, 0)) is EnforcementVerdict.INCONCLUSIVE


def test_enforced_when_all_probes_refused():
    served = {"baseline": True, "omit": False, "tamper": False,
              "noreg": False, "downgrade": False}
    assert _grade(served, (3, 3)) is EnforcementVerdict.ENFORCED


def test_signature_not_verified_beats_others():
    served = {"baseline": True, "omit": True, "tamper": True,
              "noreg": True, "downgrade": True}
    assert _grade(served, (2, 2)) is EnforcementVerdict.SIGNATURE_NOT_VERIFIED


def test_not_required_when_omit_served_but_tamper_not():
    served = {"baseline": True, "omit": True, "tamper": False}
    assert _grade(served, (2, 2)) is EnforcementVerdict.NOT_REQUIRED


def test_downgradeable():
    served = {"baseline": True, "omit": False, "tamper": False,
              "noreg": False, "downgrade": True}
    assert _grade(served, (1, 1)) is EnforcementVerdict.DOWNGRADEABLE


def test_partial_coverage_when_enforced_but_some_endpoints_unattested():
    served = {"baseline": True, "omit": False, "tamper": False,
              "noreg": False, "downgrade": False}
    assert _grade(served, (5, 2)) is EnforcementVerdict.PARTIAL_COVERAGE


def _flow(url, status=200, body="x" * 100, headers=None):
    return Flow(url=url, method="GET", status=status,
                host=url.split("/")[2], response_body=body,
                request_headers=headers or {})


def test_coverage_counts_attested_endpoints():
    flows = [
        _flow("https://api.example.com/entitlements", headers={"x-app-attest": "abc"}),
        _flow("https://api.example.com/profile", headers={}),          # no assertion
        _flow("https://gsp.apple.com/x", headers={}),                  # excluded
        _flow("https://api.example.com/empty", body="", headers={}),   # trivial body, ignored
    ]
    gated, attested = _coverage(flows)
    assert gated == 2 and attested == 1
