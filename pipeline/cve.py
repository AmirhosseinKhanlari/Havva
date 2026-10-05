"""Dependency CVE lookup for fingerprinted iOS SDKs (MASTG-TEST-0273/0275).

We extract each embedded framework's version and check it against known
vulnerabilities. Two sources, because no single free DB covers iOS well:

  * OSV.dev  — has SwiftPM packages keyed by their GitHub repo
               (`pkg:swift/github.com/<org>/<repo>@<version>`). CocoaPods is NOT
               in OSV, so this only helps SwiftPM-distributed SDKs.
  * curated  — a small built-in advisory list for classic CocoaPods SDK CVEs
               that OSV lacks (e.g. old AFNetworking TLS-validation bugs).

Results are cached on disk by purl so an at-scale run hits the network once per
(name, version). Network failures degrade gracefully to "unknown / cached".
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .config import CONFIG
from .util import get_logger

log = get_logger("cve", CONFIG.paths.log_dir)


def _osv_enabled() -> bool:
    """OSV network lookups are on by default; set CVE_LOOKUP=0 to stay offline
    (curated advisories still run). Tests disable it to avoid network."""
    return os.environ.get("CVE_LOOKUP", "1").lower() not in ("0", "false", "no")

# SDK / framework name (lowercased substring) -> GitHub "org/repo" for OSV swift.
_SDK_REPOS = {
    "alamofire": "Alamofire/Alamofire",
    "afnetworking": "AFNetworking/AFNetworking",
    "kingfisher": "onevcat/Kingfisher",
    "sdwebimage": "SDWebImage/SDWebImage",
    "rxswift": "ReactiveX/RxSwift",
    "snapkit": "SnapKit/SnapKit",
    "lottie": "airbnb/lottie-ios",
    "realm": "realm/realm-swift",
    "stripe": "stripe/stripe-ios",
    "sentry": "getsentry/sentry-cocoa",
    "firebase": "firebase/firebase-ios-sdk",
    "googlesignin": "google/GoogleSignIn-iOS",
    "appauth": "openid/AppAuth-iOS",
    "grpc": "grpc/grpc-swift",
    "trustkit": "datatheorem/TrustKit",
    "swiftyjson": "SwiftyJSON/SwiftyJSON",
    "starscream": "daltoniam/Starscream",
    "gtmsessionfetcher": "google/gtm-session-fetcher",
    "nanopb": "nanopb/nanopb",
    "openssl": "openssl/openssl",
}

# Curated advisories for SDKs OSV doesn't cover (mainly CocoaPods). Each entry:
# name -> [{id, summary, severity, fixed}]  — affected when version < `fixed`.
_CURATED = {
    "afnetworking": [
        {"id": "CVE-2015-1840", "severity": "high", "fixed": "2.5.2",
         "summary": "SSL certificate domain validation disabled by default "
                    "(AFSecurityPolicy), enabling MITM."},
        {"id": "CVE-2014-0000-afn", "severity": "high", "fixed": "2.5.3",
         "summary": "SSL validation still bypassable via crafted cert chain; "
                    "fixed in 2.5.3."},
    ],
    "gtmsessionfetcher": [
        {"id": "CVE-2018-16559", "severity": "medium", "fixed": "1.1.15",
         "summary": "Improper certificate validation in older GTMSessionFetcher."},
    ],
}


def _cache_path() -> Path:
    return CONFIG.paths.work_dir / "cve_cache.json"


def _load_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text())
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        _cache_path().parent.mkdir(parents=True, exist_ok=True)
        _cache_path().write_text(json.dumps(cache))
    except OSError:
        pass


def _vtuple(v: str) -> tuple:
    """Loose numeric version tuple for comparison ('5.6.4' -> (5,6,4))."""
    parts = []
    for seg in str(v).replace("-", ".").split("."):
        num = "".join(ch for ch in seg if ch.isdigit())
        parts.append(int(num) if num else 0)
    return tuple(parts) or (0,)


def _repo_for(name: str) -> str | None:
    low = name.lower().replace(".framework", "").replace(" ", "")
    for key, repo in _SDK_REPOS.items():
        if key in low:
            return repo
    return None


def _curated_for(name: str, version: str) -> list[dict]:
    low = name.lower().replace(".framework", "").replace(" ", "")
    out = []
    for key, advs in _CURATED.items():
        if key not in low:
            continue
        for a in advs:
            if not version or _vtuple(version) < _vtuple(a["fixed"]):
                out.append({"id": a["id"], "severity": a["severity"],
                            "summary": a["summary"], "fixed": a["fixed"],
                            "source": "curated"})
    return out


def _osv_swift(repo: str, version: str, cache: dict) -> list[dict]:
    purl = f"pkg:swift/github.com/{repo}@{version}"
    if purl in cache:
        return cache[purl]
    vulns: list[dict] = []
    try:
        import requests
        r = requests.post("https://api.osv.dev/v1/query", timeout=12,
                          json={"package": {"purl": f"pkg:swift/github.com/{repo}"},
                                "version": version})
        if r.ok:
            for v in r.json().get("vulns", []):
                sev = "medium"
                for s in v.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        sev = "high"
                fixed = ""
                for aff in v.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if ev.get("fixed"):
                                fixed = ev["fixed"]
                vulns.append({"id": v.get("id", "?"), "severity": sev,
                              "summary": (v.get("summary") or v.get("details") or "")[:200],
                              "fixed": fixed, "source": "osv"})
        cache[purl] = vulns
    except Exception as e:  # noqa: BLE001 — network/JSON; degrade gracefully
        log.info("osv query failed for %s: %s", purl, e)
    return vulns


def build_sbom(app_meta: dict, deps: list[dict]) -> dict:
    """CycloneDX 1.5 SBOM for one app (MASTG-TECH-0132). `app_meta` carries
    app_id/name/version; `deps` is the enriched dependency list."""
    import datetime
    components, vulns = [], []
    for d in deps:
        name, ver = d.get("name", ""), d.get("version", "")
        purl = f"pkg:swift/{_repo_for(name)}@{ver}" if _repo_for(name) else f"pkg:generic/{name}@{ver}"
        ref = f"{name}@{ver}"
        components.append({"type": "library", "name": name, "version": ver,
                           "purl": purl, "bom-ref": ref})
        for c in d.get("cves", []):
            vulns.append({"id": c.get("id", ""), "bom-ref": ref,
                          "ratings": [{"severity": c.get("severity", "unknown")}],
                          "description": c.get("summary", ""),
                          "affects": [{"ref": ref}]})
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "component": {"type": "application",
                          "name": app_meta.get("name") or app_meta.get("app_id", "app"),
                          "version": str(app_meta.get("version", "")),
                          "bom-ref": app_meta.get("app_id", "app")},
        },
        "components": components,
    }
    if vulns:
        sbom["vulnerabilities"] = vulns
    return sbom


def prevalence(db) -> dict:
    """Corpus-wide dependency-vulnerability stats for the paper: how many
    analyzed apps ship >=1 known-vulnerable dependency, and the most common."""
    import json as _json
    from collections import Counter
    total = with_deps = vuln_apps = 0
    vuln_lib = Counter()
    cve_count = Counter()
    with db.connect() as c:
        rows = c.execute("SELECT dependencies FROM analysis WHERE dependencies IS NOT NULL").fetchall()
    for r in rows:
        total += 1
        try:
            deps = _json.loads(r["dependencies"]) or []
        except (ValueError, TypeError):
            continue
        if deps:
            with_deps += 1
        app_vuln = False
        for d in deps:
            if d.get("cves"):
                app_vuln = True
                vuln_lib[d.get("name", "?")] += 1
                for cv in d["cves"]:
                    cve_count[cv.get("id", "?")] += 1
        if app_vuln:
            vuln_apps += 1
    return {
        "apps_analyzed": total, "apps_with_deps": with_deps,
        "apps_with_vuln_dep": vuln_apps,
        "pct_vulnerable": round(100 * vuln_apps / total, 1) if total else 0.0,
        "top_vulnerable_libs": vuln_lib.most_common(15),
        "top_cves": cve_count.most_common(15),
    }


def enrich(deps: list[dict]) -> list[dict]:
    """Given [{name, version}], return the same list with a `cves` key added to
    each (a list of {id, severity, summary, fixed, source})."""
    cache = _load_cache()
    out = []
    for d in deps:
        name = d.get("name", "")
        ver = d.get("version") or ""
        cves: list[dict] = []
        repo = _repo_for(name)
        if repo and ver and _osv_enabled():
            cves += _osv_swift(repo, ver, cache)
        cves += _curated_for(name, ver)
        # de-dup by id
        seen, uniq = set(), []
        for c in cves:
            if c["id"] in seen:
                continue
            seen.add(c["id"])
            uniq.append(c)
        out.append({**d, "cves": uniq})
    _save_cache(cache)
    n = sum(len(x["cves"]) for x in out)
    if n:
        log.info("dependency CVE check: %d advisorie(s) across %d dependency(ies)",
                 n, sum(1 for x in out if x["cves"]))
    return out
