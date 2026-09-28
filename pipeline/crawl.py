"""Stage A: crawl (fresh, AppFigures ranks + iTunes metadata enrichment).

Approach carried over as an idea from paper 1: hit the public AppFigures ranks
snapshot endpoint per category per storefront for the top-free list, then enrich
each app with the iTunes lookup API to capture the full metadata (the spec's
"hold every possible metadata" requirement). The raw iTunes JSON is stored
verbatim in `apps.raw_json` so nothing is lost.
"""

from __future__ import annotations

import json
import os
import time

import requests

from .config import CONFIG, CRAWL_COUNT_PER_CATEGORY, STOREFRONTS
from .db import Database
from .util import get_logger

log = get_logger("crawl", CONFIG.paths.log_dir)

# Full App Store category set (paper-1 parity). Crawling every category gives the
# category stratification the design calls for; pinning-heavy verticals (Finance,
# Social, Health, Lifestyle/dating, Business) are all present.
CATEGORIES: dict[str, str] = {
    "6000": "Business", "6001": "Weather", "6002": "Utilities", "6003": "Travel",
    "6004": "Sports", "6005": "Social Networking", "6006": "Reference",
    "6007": "Productivity", "6008": "Photo & Video", "6009": "News",
    "6010": "Navigation", "6011": "Music", "6012": "Lifestyle",
    "6013": "Health & Fitness", "6014": "Games", "6015": "Finance",
    "6016": "Entertainment", "6017": "Education", "6018": "Books",
    "6020": "Medical", "6021": "Magazines & Newspapers", "6023": "Food & Drink",
}

APPFIGURES_URL = "https://appfigures.com/_u/api/ranks/snapshots"
ITUNES_LOOKUP = "https://itunes.apple.com/lookup"
# Legacy but still-live public chart feed: per-genre, per-country, no auth.
ITUNES_RSS = "https://itunes.apple.com/{country}/rss/topfreeapplications/limit={limit}/genre={genre}/json"
ITUNES_RSS_MAX = 200  # RSS feeds cap here (AppFigures allows more)

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://appfigures.com/top-apps/ios-app-store/united-states",
}

_AF_FIELDS = ("results,id,entries,name,developer,developer_id,price,currency,"
              "storefront,vendor_identifier,category,subtype,timestamp,total_count")


def _appfigures_cookie() -> str:
    """AppFigures' internal API is session-gated; a logged-in cookie unlocks it."""
    return os.environ.get("APPFIGURES_COOKIE", "")


def fetch_category_appfigures(category_id: str, country: str, count: int) -> list[dict]:
    """Return ranked free apps via the AppFigures internal ranks API.

    Needs a logged-in session cookie (APPFIGURES_COOKIE) or it returns 403.
    """
    params = {"category": category_id, "country": country.upper(), "count": count,
              "start": 0, "fields": _AF_FIELDS}
    headers = dict(HEADERS)
    cookie = _appfigures_cookie()
    if cookie:
        headers["Cookie"] = cookie
    try:
        r = requests.get(APPFIGURES_URL, params=params, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError) as e:
        log.warning("appfigures %s/%s failed: %s", category_id, country, e)
        return []

    apps: list[dict] = []
    rank = 0
    for group in data.get("results", []):
        for entry in group.get("entries", []):
            price_info = entry.get("price") or {}
            price_val = price_info.get("price", "0.00") if isinstance(price_info, dict) else "0.00"
            try:
                if float(price_val) != 0:
                    continue  # free apps only
            except (TypeError, ValueError):
                pass
            rank += 1
            apps.append({
                "app_id": str(entry.get("id")),
                "bundle_id": entry.get("vendor_identifier"),
                "name": entry.get("name"),
                "seller_name": entry.get("developer"),
                "developer_id": str(entry.get("developer_id") or ""),
                "rank": rank,
                "rank_category": f"{category_id}:{CATEGORIES.get(category_id, category_id)}",
            })
    return apps


def fetch_category_itunes_rss(category_id: str, country: str, count: int) -> list[dict]:
    """Public fallback: legacy iTunes RSS top-free feed (per-genre, no auth).

    RSS gives no bundle id; the iTunes lookup enrichment fills it in later.
    """
    limit = min(count, ITUNES_RSS_MAX)
    url = ITUNES_RSS.format(country=country.lower(), limit=limit, genre=category_id)
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        entries = r.json().get("feed", {}).get("entry", [])
    except (requests.RequestException, ValueError, KeyError) as e:
        log.warning("itunes rss %s/%s failed: %s", category_id, country, e)
        return []
    if isinstance(entries, dict):  # single-entry feeds come back as an object
        entries = [entries]

    apps: list[dict] = []
    for rank, entry in enumerate(entries, 1):
        try:
            app_id = entry["id"]["attributes"]["im:id"]
        except (KeyError, TypeError):
            continue
        apps.append({
            "app_id": str(app_id),
            "bundle_id": entry.get("id", {}).get("attributes", {}).get("im:bundleId"),
            "name": entry.get("im:name", {}).get("label"),
            "seller_name": entry.get("im:artist", {}).get("label"),
            "developer_id": "",
            "rank": rank,
            "rank_category": f"{category_id}:{CATEGORIES.get(category_id, category_id)}",
        })
    return apps


def fetch_category(category_id: str, country: str, count: int, source: str) -> list[dict]:
    """Dispatch to the chosen source. 'auto' uses AppFigures if a cookie is set,
    otherwise the public iTunes RSS feed."""
    if source == "auto":
        source = "appfigures" if _appfigures_cookie() else "itunes"
    if source == "appfigures":
        apps = fetch_category_appfigures(category_id, country, count)
        if apps:
            return apps
        log.info("appfigures empty, falling back to itunes rss for %s/%s", category_id, country)
        return fetch_category_itunes_rss(category_id, country, count)
    return fetch_category_itunes_rss(category_id, country, count)


def itunes_lookup(track_ids: list[str], country: str) -> dict[str, dict]:
    """Batch-lookup full metadata. iTunes allows many ids per call; use 180."""
    out: dict[str, dict] = {}
    for i in range(0, len(track_ids), 180):
        chunk = [t for t in track_ids[i:i + 180] if t]
        if not chunk:
            continue
        try:
            r = requests.get(ITUNES_LOOKUP,
                             params={"id": ",".join(chunk), "country": country.lower()},
                             timeout=30)
            r.raise_for_status()
            for res in r.json().get("results", []):
                if res.get("wrapperType") == "software" or "trackId" in res:
                    out[str(res.get("trackId"))] = res
        except (requests.RequestException, ValueError) as e:
            log.warning("itunes lookup chunk failed (%s): %s", country, e)
        time.sleep(0.3)
    return out


def _normalize(af: dict, itunes: dict | None) -> dict:
    """Merge AppFigures rank data with the full iTunes metadata into app columns."""
    fields = {
        "bundle_id": af.get("bundle_id"),
        "name": af.get("name"),
        "seller_name": af.get("seller_name"),
        "developer_id": af.get("developer_id"),
        "rank": af.get("rank"),
        "rank_category": af.get("rank_category"),
        "crawl_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source_endpoint": "appfigures+itunes",
    }
    if itunes:
        fields.update({
            "bundle_id": itunes.get("bundleId") or fields["bundle_id"],
            "name": itunes.get("trackName") or fields["name"],
            "seller_name": itunes.get("sellerName") or fields["seller_name"],
            "developer_id": str(itunes.get("artistId") or fields["developer_id"] or ""),
            "primary_category": itunes.get("primaryGenreName"),
            "all_categories": itunes.get("genres") or [],
            "content_rating": itunes.get("contentAdvisoryRating") or itunes.get("trackContentRating"),
            "current_version": itunes.get("version"),
            "release_date": itunes.get("releaseDate"),
            "current_version_release_date": itunes.get("currentVersionReleaseDate"),
            "minimum_os": itunes.get("minimumOsVersion"),
            "supported_devices": itunes.get("supportedDevices") or [],
            "languages": itunes.get("languageCodesISO2A") or [],
            "price": itunes.get("price"),
            "currency": itunes.get("currency"),
            "formatted_price": itunes.get("formattedPrice"),
            "avg_rating": itunes.get("averageUserRating"),
            "rating_count": itunes.get("userRatingCount"),
            "description": itunes.get("description"),
            "release_notes": itunes.get("releaseNotes"),
            "screenshot_urls": itunes.get("screenshotUrls") or [],
            "artwork_url": itunes.get("artworkUrl512") or itunes.get("artworkUrl100"),
            "seller_url": itunes.get("sellerUrl"),
            "marketing_url": itunes.get("trackViewUrl"),
            "file_size_bytes": _to_int(itunes.get("fileSizeBytes")),
            "raw_json": json.dumps(itunes, ensure_ascii=False),
        })
    return {k: v for k, v in fields.items() if v is not None}


def _to_int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def crawl(db: Database, countries: list[str] | None = None,
          categories: dict[str, str] | None = None,
          count: int | None = None, enrich: bool = True, source: str = "auto") -> int:
    """Crawl all categories x storefronts, enrich, upsert. Returns app count."""
    countries = countries or STOREFRONTS
    categories = categories or CATEGORIES
    count = count or CRAWL_COUNT_PER_CATEGORY

    total = 0
    for country in countries:
        for cat_id, cat_name in categories.items():
            entries = fetch_category(cat_id, country, count, source)
            log.info("%s / %s (%s): %d free apps", country, cat_name, cat_id, len(entries))
            if not entries:
                continue
            itunes = itunes_lookup([e["app_id"] for e in entries], country) if enrich else {}
            for e in entries:
                meta = _normalize(e, itunes.get(e["app_id"]))
                db.upsert_app(e["app_id"], country, **meta)
                total += 1
            time.sleep(0.5)  # be polite
    log.info("crawl done: %d app rows upserted", total)
    return total
