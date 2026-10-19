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
    assert reached_any_network(flows, excluded=["apple.com"])


def test_reached_any_network_ignores_excluded_background_traffic():
    # Apple/iCloud background traffic is always present on the device; it must
    # not make a tamper-exited app look like it "ran and reached the network".
    har = _har([_entry("https://gsp.apple.com/z"), _entry("https://p12-keyvalueservice.icloud.com/x")])
    flows = har_to_flows(har, device_ip="192.168.1.116")
    assert flows  # the flows exist ...
    assert not reached_any_network(flows, excluded=["apple.com", "icloud.com"])  # ... but don't count
    assert reached_any_network(flows + har_to_flows(_har([_entry("https://api.example.com/")]),
                                                    device_ip="192.168.1.116"),
                               excluded=["apple.com", "icloud.com"])


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


def _trace(host, kinds, details=None, state=None):
    details = details or {}
    events = [{"kind": k, "detail": details.get(k, "")} for k in kinds]
    t = {"resolvedHost": host, "events": events}
    if state is not None:
        t["state"] = state
    return t


_TLS_FAIL = {"error": "sslError(handshake failure: certificate verify failed)"}


def test_classify_decrypted():
    t = _trace("api.x.com", ["resolved", "connected", "tlsMessage", "tlsComplete", "closed"])
    assert _classify_trace(t) == ("api.x.com", "decrypted")


def test_classify_pinned_when_tls_aborts_before_complete():
    # Connected, TLS started, then FAILED with a TLS-flavoured reason -> pinned (lead).
    t = _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "error", "closed"],
               details=_TLS_FAIL, state="failed")
    assert _classify_trace(t) == ("api.bank.com", "pinned")


def test_classify_failed_without_tls_reason_is_not_pinned():
    # The ubiquitous upstream 'uncleanShutdown': no TLS reason -> never pinned.
    t = _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "tlsComplete", "error"],
               details={"error": "uncleanShutdown"}, state="failed")
    assert _classify_trace(t) == ("api.bank.com", "unknown")
    # A handshake that only shows 'handshake' in tlsMessage details (every TLS
    # trace does) but no TLS failure reason is not pinned either.
    t = _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "error"],
               details={"tlsMessage": "handshake", "error": "stream ended at an unexpected time"},
               state="failed")
    assert _classify_trace(t)[1] != "pinned"


def test_classify_failed_is_never_decrypted():
    t = _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "tlsComplete", "error"],
               details={"error": "uncleanShutdown"}, state="failed")
    assert _classify_trace(t)[1] != "decrypted"


def test_classify_close_notify_alert_is_benign():
    t = _trace("cdn.x.io", ["resolved", "connected", "tlsMessage", "tlsComplete", "error"],
               details={"error": "sslError(SSL routines: SSLV3_ALERT_CLOSE_NOTIFY)"}, state="failed")
    assert _classify_trace(t)[1] != "pinned"


def test_classify_dns_failure_is_not_pinned_even_if_tls_mentioned():
    t = _trace("api.bank.com", ["resolved", "error"],
               details={"error": "dns error before tls"}, state="failed")
    assert _classify_trace(t) == ("api.bank.com", "connect_failed")


def test_classify_unresolved_is_not_pinned():
    t = _trace("dead.example", ["error"],
               details={"error": "Could not resolve host: dead.example"})
    assert _classify_trace(t) == ("dead.example", "unresolved")


def test_classify_unresolved_when_no_resolved_event_at_all():
    # No 'resolved' DNS event -> unresolved, regardless of detail text.
    t = _trace("dead.example", ["trying", "error"], details={"error": "timeout"}, state="failed")
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
        _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "error"],
               details=_TLS_FAIL, state="failed"),   # pinned
        _trace("api.bank.com", ["resolved", "connected", "tlsMessage", "tlsComplete"],
               state="connected"),  # decrypted -> wins
        _trace("cdn.x.io", ["resolved", "connected", "tlsMessage", "error"],
               details=_TLS_FAIL, state="failed"),        # pinned
        _trace("gsp.apple.com", ["resolved", "connected", "tlsMessage", "error"],
               details=_TLS_FAIL, state="failed"),   # excluded -> dropped
    ]
    p = tmp_path / "s.proxymansession"
    with zipfile.ZipFile(p, "w") as z:
        for i, t in enumerate(traces):
            z.writestr(f"ConnectionTraces/trace_{i}", json.dumps(t))
    out = session_host_outcomes(p, excluded=["apple.com"])
    assert out == {"api.bank.com": "decrypted", "cdn.x.io": "pinned"}



# ---- Export must never reuse a stale file -----------------------------------

from pipeline import capture as _capture  # noqa: E402


def test_export_har_removes_stale_file_when_cli_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(_capture, "run_cmd", lambda *a, **k: None)   # CLI writes nothing
    monkeypatch.setattr(_capture.time, "sleep", lambda s: None)
    p = tmp_path / "x.har"
    p.write_text('{"log":{"entries":[{"request":{"url":"https://stale.example/"}}]}}')
    assert _capture.export_har(p, retries=2) is False
    assert not p.exists()


def test_export_har_returns_true_when_cli_writes(tmp_path, monkeypatch):
    def fake_cli(cmd, timeout=30):
        pathlib.Path(cmd[-1]).write_text('{"log":{"entries":[]}}')
    import pathlib
    monkeypatch.setattr(_capture, "run_cmd", fake_cli)
    p = tmp_path / "x.har"
    assert _capture.export_har(p, retries=1) is True


def test_export_session_ignores_stale_suffixed_file(tmp_path, monkeypatch):
    monkeypatch.setattr(_capture, "run_cmd", lambda *a, **k: None)
    monkeypatch.setattr(_capture.time, "sleep", lambda s: None)
    p = tmp_path / "x.proxymansession"
    stale = tmp_path / "x.proxymansessionv2"
    stale.write_bytes(b"old")
    p.write_bytes(b"old")
    assert _capture.export_session(p, retries=1) is None
    assert not stale.exists() and not p.exists()


def test_export_session_accepts_freshly_written_suffixed_file(tmp_path, monkeypatch):
    def fake_cli(cmd, timeout=30):
        import pathlib
        pathlib.Path(cmd[-1] + "v2").write_bytes(b"PK new")
    monkeypatch.setattr(_capture, "run_cmd", fake_cli)
    p = tmp_path / "x.proxymansession"
    assert _capture.export_session(p, retries=1) == tmp_path / "x.proxymansessionv2"


# ---- https-only host sets, exact client match, syslog TLS rejections --------

from pipeline.capture import cleartext_hosts, tls_rejections  # noqa: E402


def test_app_hosts_ignores_cleartext_flows():
    # A plain-HTTP beacon / OCSP fetch says nothing about pinning.
    har = _har([_entry("http://ocsp.digicert.com/x"), _entry("http://beacon.example.com/p"),
                _entry("https://api.example.com/v1")])
    flows = har_to_flows(har, device_ip="192.168.1.116")
    assert app_hosts(flows, excluded=[]) == {"api.example.com"}
    assert cleartext_hosts(flows, excluded=[]) == {"ocsp.digicert.com", "beacon.example.com"}
    assert reached_any_network(flows, excluded=[])   # it did talk, though


def test_device_ip_filter_is_exact_and_keeps_unattributed_entries():
    har = _har([
        _entry("https://api.example.com/x", client="192.168.1.17"),
        _entry("https://other.example.com/y", client="192.168.1.170"),   # a different host
        _entry("https://port.example.com/z", client="192.168.1.17:54321"),
    ])
    flows = har_to_flows(har, device_ip="192.168.1.17")
    assert {f.host for f in flows} == {"api.example.com", "port.example.com"}
    # No client field at all: kept (unknown is not 'someone else'), never
    # judged by the server address.
    e = _entry("https://noclient.example.com/", client=None)
    del e["_clientAddress"]
    e["serverIPAddress"] = "1.2.3.4"
    assert [f.host for f in har_to_flows(_har([e]), device_ip="192.168.1.17")] == ["noclient.example.com"]


_SYSLOG = """\
Oct 18 22:10:01 iPhone Bank(CFNetwork)[512] <Notice>: Task <A1>.<1> HTTP load failed, 0/0 bytes (error code: -1202 [3:-9802])
Oct 18 22:10:01 iPhone Bank(CFNetwork)[512] <Error>: Task <A1>.<1> finished with error [-1202] Error Domain=NSURLErrorDomain Code=-1202 "The certificate for this server is invalid. You might be connecting to a server that is pretending to be “api.bank.example” which could put your confidential information at risk." UserInfo={NSErrorFailingURLStringKey=https://api.bank.example/v1/login, x=y}
Oct 18 22:10:02 iPhone Bank(libboringssl.dylib)[512] <Error>: boringssl_session_handshake_error_print(44) [C3.1.1.1:2][0x1] Error: 4310442808:error:1000007d:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED:/Library/Caches/...
Oct 18 22:10:03 iPhone Bank(CFNetwork)[512] <Notice>: Task <B2>.<1> HTTP load failed, 0/0 bytes (error code: -999 [1:89])
Oct 18 22:10:04 iPhone OtherApp(CFNetwork)[700] <Notice>: Task <C3>.<1> HTTP load failed, 0/0 bytes (error code: -1202 [3:-9802])
Oct 18 22:10:05 iPhone Bank(CFNetwork)[512] <Notice>: Task <D4>.<1> finished successfully
Oct 18 22:10:06 iPhone Bank(CFNetwork)[512] <Error>: Task <E5>.<1> finished with error [-1202] Error Domain=NSURLErrorDomain Code=-1202 UserInfo={NSErrorFailingURLStringKey=https://gsp.apple.com/x}
"""


def test_tls_rejections_attributed_to_the_app_process():
    r = tls_rejections(_SYSLOG, {"Bank"})
    assert r["rejected"] == 4          # -1202 x3 (one is Apple, host dropped, still a rejection) + boringssl
    assert r["cancelled"] == 1         # the -999
    assert r["codes"]["-1202"] == 3 and r["codes"]["boringssl"] == 1 and r["codes"]["-999"] == 1
    assert r["hosts"] == ["api.bank.example"]   # from the error, Apple host excluded
    assert len(r["samples"]) == 5
    # Another process's rejection is not ours.
    assert tls_rejections(_SYSLOG, {"OtherApp"})["rejected"] == 1
    # No filter: everything counts.
    assert tls_rejections(_SYSLOG)["rejected"] == 5
    # Nothing in, nothing out.
    assert tls_rejections("", {"Bank"})["rejected"] == 0
