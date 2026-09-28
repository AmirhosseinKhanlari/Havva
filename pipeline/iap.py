"""Detect which apps offer in-app purchases.

Idea from paper 1's check_iap.py: the App Store product page shows an
"In-App Purchases" label (localized) when the app has them, and the page also
embeds a JSON cache ("shoebox") with a hasInAppPurchases field. We check both:
the structured JSON first (robust), then a localized text fallback.

Resumable: only apps not yet checked (iap_checked=0) are fetched. Results go to
apps.has_iap. Concurrent, since it is 7k+ page fetches.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .config import CONFIG
from .db import Database
from .util import get_logger

log = get_logger("iap", CONFIG.paths.log_dir)

_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,ja;q=0.7,ko;q=0.6",
}

# Localized "In-App Purchases" labels shown in the app's info list.
_IAP_TEXT_PATTERNS = [
    r"In.{0,3}App.{0,3}Purchase",     # EN (handles the non-breaking hyphen)
    r"App\s*内购买", r"应用内购买",         # zh
    r"アプリ内課金",                       # ja
    r"앱\s*내\s*구입",                    # ko
    r"Achats\s*intégrés",             # fr
    r"In[\-‐‑]?App[\-‐‑]?Käufe",  # de
    r"Compras\s*(en|dentro de)\s*la\s*app",           # es
    r"Acquisti\s*in[\-‐‑]?app",             # it
    r"Покупки\s*в\s*приложении",       # ru
]
_IAP_RE = re.compile("|".join(_IAP_TEXT_PATTERNS), re.IGNORECASE)
# The app's own info line: <p class="attributes ...">Free · In-App Purchases</p>.
# "attributes" is the stable class; the svelte hash suffix changes over time.
_ATTR_P_RE = re.compile(r'<p[^>]*class="[^"]*attributes[^"]*"[^>]*>(.*?)</p>',
                        re.IGNORECASE | re.DOTALL)
# Fallback: the info-list row header, present only when the app has IAP.
_DT_RE = re.compile(r'<dt[^>]*>\s*(?:' + "|".join(_IAP_TEXT_PATTERNS) + r')',
                    re.IGNORECASE)


def check_has_iap(app_id: str, country: str, session: requests.Session | None = None) -> bool | None:
    """True/False if determined, None on fetch failure (retry later)."""
    url = f"https://apps.apple.com/{country.lower()}/app/id{app_id}"
    getter = session or requests
    try:
        r = getter.get(url, headers=_HEADERS, timeout=20)
        if r.status_code == 404:
            return False
        r.raise_for_status()
        html = r.text
    except requests.RequestException:
        return None
    # Scope to the app's own info line. A plain full-page search is contaminated
    # by the always-present JSON key "inAppPurchases" and the related-apps
    # section, so we look only inside the <p class="attributes"> paragraph, with
    # the info-list <dt> row as a fallback.
    # There are several "attributes" paragraphs (device support, price line, ...);
    # the IAP label lives in the price line, so check them all.
    attrs = _ATTR_P_RE.findall(html)
    if attrs:
        return any(_IAP_RE.search(a) for a in attrs)
    return bool(_DT_RE.search(html))


def run(db: Database, limit: int | None = None, workers: int = 12) -> dict[str, int]:
    db.add_column_if_missing("apps", "iap_checked", "INTEGER DEFAULT 0")
    with db.connect() as c:
        rows = c.execute(
            "SELECT app_id, country FROM apps WHERE COALESCE(iap_checked,0)=0"
        ).fetchall()
    if limit:
        rows = rows[:limit]
    stats = {"checked": 0, "has_iap": 0, "no_iap": 0, "errors": 0}

    session = requests.Session()

    def work(row):
        return row["app_id"], check_has_iap(row["app_id"], row["country"], session)

    results: list[tuple[str, bool | None]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, r) for r in rows]
        for i, fut in enumerate(as_completed(futures), 1):
            results.append(fut.result())
            if i % 200 == 0:
                log.info("iap progress: %d/%d", i, len(rows))
                _flush(db, results); results = []
    _flush(db, results)

    with db.connect() as c:
        stats["has_iap"] = c.execute("SELECT COUNT(*) FROM apps WHERE has_iap=1").fetchone()[0]
        stats["no_iap"] = c.execute(
            "SELECT COUNT(*) FROM apps WHERE has_iap=0 AND iap_checked=1").fetchone()[0]
        stats["checked"] = c.execute("SELECT COUNT(*) FROM apps WHERE iap_checked=1").fetchone()[0]
    log.info("iap: %s", stats)
    return stats


def _flush(db: Database, results: list[tuple[str, bool | None]]) -> None:
    with db.connect() as c:
        for app_id, has in results:
            if has is None:
                continue  # leave unchecked for retry
            c.execute("UPDATE apps SET has_iap=?, iap_checked=1 WHERE app_id=?",
                      (1 if has else 0, app_id))
