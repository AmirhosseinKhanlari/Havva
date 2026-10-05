"""Tests for the pure HAR-parsing / host-set logic in capture."""

import base64
import gzip

from pipeline.capture import (
    app_hosts, har_to_flows, host_from_url, is_excluded, reached_any_network,
)


def test_host_from_url():
    assert host_from_url("https://api.example.com/v1/x?y=1") == "api.example.com"
    assert host_from_url("not a url") == ""


def test_is_excluded_matches_subdomains():
    ex = ["apple.com", "icloud.com"]
    assert is_excluded("gsp.apple.com", ex)
    assert is_excluded("apple.com", ex)
    assert not is_excluded("api.example.com", ex)


def _har(entries):
    return {"log": {"entries": entries}}


def _entry(url, status=200, client="192.168.1.116", body="", enc=None):
    content = {"text": body}
    if enc:
        content["encoding"] = enc
    return {
        "_clientAddress": client,
        "request": {"url": url, "method": "GET", "headers": [{"name": "X", "value": "y"}]},
        "response": {"status": status, "headers": [], "content": content},
    }


def test_har_to_flows_and_app_hosts():
    har = _har([
        _entry("https://api.example.com/x"),
        _entry("https://gsp.apple.com/z"),        # excluded
        _entry("https://analytics.example.com/a"),
    ])
    flows = har_to_flows(har, device_ip="192.168.1.116")
    hosts = app_hosts(flows, excluded=["apple.com"])
    assert hosts == {"api.example.com", "analytics.example.com"}
    assert reached_any_network(flows)


def test_device_ip_filter():
    har = _har([
        _entry("https://api.example.com/x", client="192.168.1.116"),
        _entry("https://other.example.com/y", client="10.0.0.9"),  # not the device
    ])
    flows = har_to_flows(har, device_ip="192.168.1.116")
    assert {f.host for f in flows} == {"api.example.com"}


def test_gzip_base64_body_decode():
    payload = b'{"entitlement":"active"}'
    enc = base64.b64encode(gzip.compress(payload)).decode()
    har = _har([_entry("https://api.example.com/sub", body=enc, enc="base64")])
    flows = har_to_flows(har, device_ip="192.168.1.116")
    assert "entitlement" in flows[0].response_body


def test_empty_har():
    assert har_to_flows({}, "1.2.3.4") == []
    assert app_hosts([]) == set()


# ---- Native session trace classification (pinning detection) ----------------

from pipeline.capture import _classify_trace, session_host_outcomes  # noqa: E402


def _trace(host, kinds, details=None):
    details = details or {}
    events = [{"kind": k, "detail": details.get(k, "")} for k in kinds]
    return {"resolvedHost": host, "events": events}


def test_classify_decrypted():
    t = _trace("api.x.com", ["resolved", "connected", "tlsMessage", "tlsComplete", "closed"])
    assert _classify_trace(t) == ("api.x.com", "decrypted")


def test_classify_pinned_when_tls_aborts_before_complete():
    # Connected, TLS started against our cert, then torn down -> pinning.
    t = _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "error", "closed"])
    assert _classify_trace(t) == ("api.bank.com", "pinned")


def test_classify_unresolved_is_not_pinned():
    t = _trace("dead.example", ["error"],
               details={"error": "Could not resolve host: dead.example"})
    assert _classify_trace(t) == ("dead.example", "unresolved")


def test_classify_tunneled_excluded_host_is_unknown_not_pinned():
    # Apple host we chose NOT to intercept: connects, no cert presented
    # (no tlsMessage), no error -> unknown, must never be called pinned.
    t = _trace("gsp.apple.com", ["resolved", "connected", "closed"])
    assert _classify_trace(t) == ("gsp.apple.com", "unknown")


def test_session_host_outcomes_prefers_decrypted_and_drops_excluded(tmp_path):
    import json
    import zipfile
    traces = [
        _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "error"]),   # pinned
        _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "tlsComplete"]),  # decrypted -> wins
        _trace("cdn.x.io", ["resolved", "connected", "tlsMessage", "error"]),        # pinned
        _trace("gsp.apple.com", ["resolved", "connected", "tlsMessage", "error"]),   # excluded -> dropped
    ]
    p = tmp_path / "s.proxymansession"
    with zipfile.ZipFile(p, "w") as z:
        for i, t in enumerate(traces):
            z.writestr(f"ConnectionTraces/trace_{i}", json.dumps(t))
    out = session_host_outcomes(p, excluded=["apple.com"])
    assert out == {"api.bank.com": "decrypted", "cdn.x.io": "pinned"}
