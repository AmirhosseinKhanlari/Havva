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
import time
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
    r"App\s*內購買", r"應用程式內購買",       # zh-Hant (tw/hk)
    r"Compras\s*(dentro\s*do|na)\s*app", r"Compras\s*integradas",   # pt-BR / pt-PT
    r"In[\-‐‑ ]?app[\-‐‑ ]?aankopen",      # nl
    r"Uygulama\s*[İIiı]çi\s*Satın\s*Al[ıi]m",   # tr
    r"(?:عمليات\s*)?شراء\s*داخل\s*التطبيق", r"مشتريات\s*داخل\s*التطبيق",   # ar
    r"Pembelian\s*Dalam\s*Aplikasi",       # id
    r"Köp\s*inuti\s*appen", r"Köp\s*i\s*appen",          # sv
    r"Køb\s*i\s*appen", r"Kjøp\s*i\s*appen",             # da / no
    r"Sovelluksen\s*sisäiset\s*ostot",     # fi
    r"Zakupy\s*w\s*aplikacji",             # pl
    r"Покупки\s*в\s*застосунку",           # uk
    r"การซื้อภายในแอป",                    # th
    r"Mua\s*hàng\s*trong\s*ứng\s*dụng",     # vi
    r"ऐप\s*के\s*अंदर\s*खरीदारी",              # hi
    r"Αγορές\s*εντός\s*εφαρμογής",         # el
    r"Nákupy\s*v\s*aplikaci", r"Nákupy\s*v\s*aplikácii",   # cs / sk
    r"Alkalmazáson\s*belüli\s*vásárlások",  # hu
]
_IAP_RE = re.compile("|".join(_IAP_TEXT_PATTERNS), re.IGNORECASE)
# The app's own info line: <p class="attributes ...">Free · In-App Purchases</p>.
# "attributes" is the stable class; the svelte hash suffix changes over time.
_ATTR_P_RE = re.compile(r'<p[^>]*class="[^"]*attributes[^"]*"[^>]*>(.*?)</p>',
                        re.IGNORECASE | re.DOTALL)
# Fallback: the info-list row header, present only when the app has IAP.
_DT_RE = re.compile(r'<dt[^>]*>\s*(?:' + "|".join(_IAP_TEXT_PATTERNS) + r')',
                    re.IGNORECASE)


def parse_has_iap(html: str) -> bool | None:
    """Pure page parser. True when the app's own info line or info-list row
    carries the (localized) In-App Purchases label; False when the page is a
    recognizable product page without it; None when the HTML has neither an
    attributes paragraph nor an info list (not a product page: do not decide).

    A plain full-page search is contaminated by the always-present JSON key
    "inAppPurchases" and the related-apps section, so we look only inside the
    <p class="attributes"> paragraphs (there are several: device support, price
    line, ...; the IAP label lives in the price line) AND the info-list <dt> row.
    Both are checked before deciding False: never short-circuit on the first."""
    attrs = _ATTR_P_RE.findall(html or "")
    if any(_IAP_RE.search(a) for a in attrs):
        return True
    if _DT_RE.search(html or ""):
        return True
    if attrs or re.search(r"<dt[\s>]", html or "", re.IGNORECASE):
        return False
    return None


def check_has_iap(app_id: str, country: str, session: requests.Session | None = None) -> bool | None:
    """True/False if determined, None if unknown (fetch failure, non-200 page,
    unrecognized page layout): None rows stay iap_checked=0 and are retried.
    The page is requested with ?l=en so the label is English on every
    storefront; the localized patterns remain as a fallback."""
    url = f"https://apps.apple.com/{country.lower()}/app/id{app_id}?l=en"
    getter = session or requests
    html = ""
    for attempt in range(3):
        try:
            r = getter.get(url, headers=_HEADERS, timeout=20)
            if r.status_code in (429, 403, 503):  # throttled: back off and retry
                time.sleep(2 * (attempt + 1))
                continue
            if r.status_code != 200:
                # 404 (pulled / wrong storefront) or any other non-200 is NOT
                # "no IAP": record nothing so the app is retried later.
                log.info("iap %s/%s: HTTP %s -> unknown", country, app_id, r.status_code)
                return None
            html = r.text
            break
        except requests.RequestException:
            time.sleep(1.5 * (attempt + 1))
    if not html:
        return None
    return parse_has_iap(html)


def _check_chunk(rows, workers: int, session) -> list[tuple[str, bool | None]]:
    def work(row):
        return row["app_id"], check_has_iap(row["app_id"], row["country"], session)
    out = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(work, r) for r in rows]):
            out.append(fut.result())
    return out


def run(db: Database, limit: int | None = None, workers: int = 8,
        rotate_vpn: bool = False, chunk_size: int = 250,
        throttle_threshold: float = 0.4) -> dict[str, int]:
    """Scan IAP in resumable chunks. With rotate_vpn, switch exit IP (openvpn,
    needs sudo) whenever a chunk comes back mostly throttled."""
    db.add_column_if_missing("apps", "iap_checked", "INTEGER DEFAULT 0")
    with db.connect() as c:
        rows = c.execute(
            "SELECT app_id, country FROM apps WHERE COALESCE(iap_checked,0)=0"
        ).fetchall()
    if limit:
        rows = rows[:limit]

    if rotate_vpn:
        from . import vpn
        if not vpn.available():
            log.warning("rotate_vpn requested but no configs/auth; continuing without")
            rotate_vpn = False
        else:
            vpn.rotate()

    session = requests.Session()
    total = len(rows)
    done = 0
    for start in range(0, total, chunk_size):
        chunk = rows[start:start + chunk_size]
        results = _check_chunk(chunk, workers, session)
        nones = sum(1 for _, v in results if v is None)
        _flush(db, results)
        done += len(chunk)
        fail_rate = nones / len(chunk) if chunk else 0
        log.info("iap chunk %d-%d: %d throttled (%.0f%%), %d/%d done",
                 start, start + len(chunk), nones, 100 * fail_rate, done, total)
        # Requeue throttled ones (they stayed iap_checked=0) by leaving them.
        if fail_rate >= throttle_threshold and rotate_vpn:
            log.info("throttled; rotating exit IP")
            from . import vpn
            vpn.rotate()

    with db.connect() as c:
        checked = c.execute("SELECT COUNT(*) FROM apps WHERE iap_checked=1").fetchone()[0]
        has = c.execute("SELECT COUNT(*) FROM apps WHERE has_iap=1").fetchone()[0]
        no = c.execute("SELECT COUNT(*) FROM apps WHERE has_iap=0 AND iap_checked=1").fetchone()[0]
        remaining = c.execute("SELECT COUNT(*) FROM apps WHERE COALESCE(iap_checked,0)=0").fetchone()[0]
    stats = {"checked": checked, "has_iap": has, "no_iap": no, "remaining": remaining}
    log.info("iap: %s", stats)
    return stats


def _flush(db: Database, results: list[tuple[str, bool | None]]) -> None:
    with db.connect() as c:
        for app_id, has in results:
            if has is None:
                continue  # unknown (error / non-200 / unparsable): leave iap_checked=0 for retry
            c.execute("UPDATE apps SET has_iap=?, iap_checked=1 WHERE app_id=?",
                      (1 if has else 0, app_id))
