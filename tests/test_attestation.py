"""Tests for the attestation oracle, probe outcome, and grading logic."""
import dataclasses

from pipeline.attestation import (_coverage, _gated_endpoints, _grade, _probe_outcome,
                                  _req_carries_assertion)
from pipeline.models import EnforcementVerdict, Flow

_FIELDS = {f.name for f in dataclasses.fields(Flow)}


def _flow(url, status=200, body="x" * 100, headers=None, req_body=""):
    kw = dict(url=url, method="GET", status=status, host=url.split("/")[2],
              response_body=body, request_headers=headers or {}, request_body=req_body)
    return Flow(**{k: v for k, v in kw.items() if k in _FIELDS})


# ---- grading -----------------------------------------------------------------

def test_inconclusive_when_baseline_not_served():
    assert _grade({"baseline": False}, (0, 0)) is EnforcementVerdict.INCONCLUSIVE


def test_enforced_when_all_probes_definitely_refused():
    served = {"baseline": True, "omit": False, "tamper": False, "noreg": False, "downgrade": False}
    assert _grade(served, (3, 3)) is EnforcementVerdict.ENFORCED


def test_all_probes_inconclusive_is_not_enforced():
    served = {"baseline": True, "omit": None, "tamper": None, "noreg": None, "downgrade": None}
    assert _grade(served, (3, 3)) is EnforcementVerdict.INCONCLUSIVE


def test_enforced_requires_definite_tamper_and_omit_refusal():
    served = {"baseline": True, "omit": None, "tamper": False, "noreg": False, "downgrade": False}
    assert _grade(served, (3, 3)) is EnforcementVerdict.INCONCLUSIVE


def test_signature_not_verified_beats_others():
    served = {"baseline": True, "omit": True, "tamper": True, "noreg": True, "downgrade": True}
    assert _grade(served, (2, 2)) is EnforcementVerdict.SIGNATURE_NOT_VERIFIED


def test_not_required_when_omit_served_but_tamper_not():
    assert _grade({"baseline": True, "omit": True, "tamper": False}, (2, 2)) is EnforcementVerdict.NOT_REQUIRED


def test_downgradeable():
    served = {"baseline": True, "omit": False, "tamper": False, "noreg": False, "downgrade": True}
    assert _grade(served, (1, 1)) is EnforcementVerdict.DOWNGRADEABLE


def test_partial_coverage_when_enforced_but_some_endpoints_unattested():
    served = {"baseline": True, "omit": False, "tamper": False, "noreg": False, "downgrade": False}
    assert _grade(served, (5, 2)) is EnforcementVerdict.PARTIAL_COVERAGE


# ---- assertion detection ------------------------------------------------------

def test_assertion_detected_in_header_name_and_value():
    assert _req_carries_assertion(_flow("https://a.com/x", headers={"x-app-attest": "abc"}))
    assert _req_carries_assertion(_flow("https://a.com/x", headers={"x-proof": "approov-token-zzz"}))


def test_client_assertion_oauth_body_is_not_attestation():
    f = _flow("https://a.com/token", headers={}, req_body="grant_type=jwt&client_assertion=eyJ")
    assert not _req_carries_assertion(f)


# ---- baseline oracle ----------------------------------------------------------

def test_gated_endpoints_only_attested_data_responses():
    flows = [
        _flow("https://api.example.com/entitlements", headers={"x-app-attest": "abc"}),
        _flow("https://api.example.com/profile", headers={}),                 # no assertion
        _flow("https://gsp.apple.com/x", headers={"x-app-attest": "abc"}),   # excluded host
        _flow("https://api.example.com/empty", body="", headers={"x-app-attest": "abc"}),  # trivial
        _flow("https://api.example.com/denied", status=401, headers={"x-app-attest": "abc"}),
    ]
    assert _gated_endpoints(flows) == {"api.example.com/entitlements"}


def test_coverage_counts_attested_endpoints():
    flows = [
        _flow("https://api.example.com/entitlements", headers={"x-app-attest": "abc"}),
        _flow("https://api.example.com/profile", headers={}),
        _flow("https://gsp.apple.com/x", headers={}),
        _flow("https://api.example.com/empty", body="", headers={}),
    ]
    assert _coverage(flows) == (2, 1)


# ---- per-probe outcome (the fail-safe rules) ------------------------------------

GATED = {"api.example.com/entitlements"}


def test_probe_inconclusive_when_not_armed_or_no_hit():
    f = [_flow("https://api.example.com/entitlements", headers={"x-app-attest": "garbage"})]
    assert _probe_outcome("tamper", GATED, f, armed=False, hit=True)[0] is None
    assert _probe_outcome("tamper", GATED, f, armed=True, hit=False)[0] is None
    assert _probe_outcome("tamper", set(), f, armed=True, hit=True)[0] is None


def test_tamper_served_with_garbage_assertion_is_weakness():
    f = [_flow("https://api.example.com/entitlements", headers={"x-app-attest": "garbage"})]
    assert _probe_outcome("tamper", GATED, f, armed=True, hit=True)[0] is True


def test_tamper_refused_is_definite_false():
    f = [_flow("https://api.example.com/entitlements", status=403, body="denied" * 20,
               headers={"x-app-attest": "garbage"})]
    assert _probe_outcome("tamper", GATED, f, armed=True, hit=True)[0] is False


def test_omit_served_only_counts_requests_WITHOUT_assertion():
    cached = [_flow("https://api.example.com/entitlements", headers={"x-app-attest": "cached"})]
    assert _probe_outcome("omit", GATED, cached, armed=True, hit=True)[0] is None  # cached token, no evidence
    bare = [_flow("https://api.example.com/entitlements", headers={})]
    assert _probe_outcome("omit", GATED, bare, armed=True, hit=True)[0] is True


def test_unrelated_2xx_never_counts_as_gated():
    f = [_flow("https://api.example.com/config", headers={}),           # not a gated endpoint
         _flow("https://cdn.example.com/banner", headers={})]
    assert _probe_outcome("omit", GATED, f, armed=True, hit=True)[0] is None
