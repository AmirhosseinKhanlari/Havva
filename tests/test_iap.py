"""Tests for the IAP-label detection logic (no network: fake sessions)."""

from pipeline.iap import check_has_iap, parse_has_iap


def test_price_line_with_iap():
    html = ('<p class="attributes svelte-x">Only for iPhone</p>'
            '<p class="attributes svelte-x">Free · In‑App Purchases</p>')
    assert parse_has_iap(html) is True


def test_price_line_without_iap():
    html = ('<p class="attributes svelte-x">Only for iPhone</p>'
            '<p class="attributes svelte-x">Free</p>')
    assert parse_has_iap(html) is False


def test_ignores_related_apps_json_key():
    # The always-present JSON key must NOT trigger a positive.
    html = ('<p class="attributes svelte-x">Free</p>'
            '"inAppPurchases":["x"],"subscriptions":[]')
    assert parse_has_iap(html) is False


def test_localized_labels():
    for label in ("App内购买", "App 內購買", "アプリ内課金", "앱 내 구입", "Achats intégrés",
                  "In-App-Käufe", "Compras dentro de la app", "Acquisti in-app",
                  "Покупки в приложении", "Compras dentro do app", "Compras integradas",
                  "In-app-aankopen", "Uygulama İçi Satın Alımlar",
                  "عمليات شراء داخل التطبيق", "Pembelian Dalam Aplikasi"):
        html = f'<p class="attributes s">Free · {label}</p>'
        assert parse_has_iap(html) is True, label


def test_dt_row_checked_even_when_attribute_paragraphs_exist():
    # Earlier code short-circuited on the attributes paragraphs and never looked
    # at the info-list row; both locations must be consulted before a False.
    html = ('<p class="attributes s">Only for iPhone</p>'
            "<dl><dt>In-App Purchases</dt><dd>Pro</dd></dl>")
    assert parse_has_iap(html) is True


def test_dt_fallback_when_no_attr_paragraph():
    html = "<dl><dt>In-App Purchases</dt><dd>Pro</dd></dl>"
    assert parse_has_iap(html) is True
    assert parse_has_iap("<dl><dt>Seller</dt><dd>X</dd></dl>") is False


def test_unrecognized_page_is_unknown_not_false():
    assert parse_has_iap("<html>nothing relevant here</html>") is None
    assert parse_has_iap("") is None


class _Resp:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


class _Session:
    def __init__(self, resp):
        self.resp, self.urls = resp, []

    def get(self, url, headers=None, timeout=None):
        self.urls.append(url)
        return self.resp


def test_http_404_is_unknown_not_no_iap():
    s = _Session(_Resp(404, "not found"))
    assert check_has_iap("1", "jp", s) is None     # must stay iap_checked=0 for retry
    assert check_has_iap("1", "jp", _Session(_Resp(500, "oops"))) is None
    assert check_has_iap("1", "jp", _Session(_Resp(302, ""))) is None


def test_check_requests_english_and_parses_200(monkeypatch):
    import pipeline.iap as iap
    monkeypatch.setattr(iap.time, "sleep", lambda *_: None)
    s = _Session(_Resp(200, '<p class="attributes s">Free · In-App Purchases</p>'))
    assert check_has_iap("123", "JP", s) is True
    assert s.urls[0] == "https://apps.apple.com/jp/app/id123?l=en"
    s2 = _Session(_Resp(200, '<p class="attributes s">Free</p>'))
    assert check_has_iap("123", "us", s2) is False
    # a 200 that is not a product page is unknown, not "no IAP"
    s3 = _Session(_Resp(200, "<html><body>Something else</body></html>"))
    assert check_has_iap("123", "us", s3) is None
