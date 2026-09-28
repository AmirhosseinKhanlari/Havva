"""Tests for the pure IAP-label detection logic (no network)."""

import re

from pipeline.iap import _ATTR_P_RE, _DT_RE, _IAP_RE


def _has_iap(html: str) -> bool:
    attrs = _ATTR_P_RE.findall(html)
    if attrs:
        return any(_IAP_RE.search(a) for a in attrs)
    return bool(_DT_RE.search(html))


def test_price_line_with_iap():
    html = ('<p class="attributes svelte-x">Only for iPhone</p>'
            '<p class="attributes svelte-x">Free · In‑App Purchases</p>')
    assert _has_iap(html)


def test_price_line_without_iap():
    html = ('<p class="attributes svelte-x">Only for iPhone</p>'
            '<p class="attributes svelte-x">Free</p>')
    assert not _has_iap(html)


def test_ignores_related_apps_json_key():
    # The always-present JSON key must NOT trigger a positive.
    html = ('<p class="attributes svelte-x">Free</p>'
            '"inAppPurchases":["x"],"subscriptions":[]')
    assert not _has_iap(html)


def test_localized_label_chinese():
    html = '<p class="attributes s">免费 · App内购买</p>'
    assert _has_iap(html)


def test_dt_fallback_when_no_attr_paragraph():
    html = "<dl><dt>In-App Purchases</dt><dd>Pro</dd></dl>"
    assert _has_iap(html)


def test_no_signal_at_all():
    assert not _has_iap("<html>nothing relevant here</html>")
