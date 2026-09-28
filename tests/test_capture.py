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
