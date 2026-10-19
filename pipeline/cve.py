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

# EXACT framework name (lowercased, ".framework" stripped) -> GitHub "org/repo"
# for the OSV swift ecosystem. Exact keys only: substring mapping sent
# AlamofireImage to Alamofire/Alamofire and gRPC-C++ to grpc-swift, so the
# version was checked against the wrong package's advisories.
_SDK_REPOS = {
    "alamofire": "Alamofire/Alamofire",
    "alamofireimage": "Alamofire/AlamofireImage",
    "alamofirenetworkactivityindicator": "Alamofire/AlamofireNetworkActivityIndicator",
    "afnetworking": "AFNetworking/AFNetworking",
    "kingfisher": "onevcat/Kingfisher",
    "sdwebimage": "SDWebImage/SDWebImage",
    "sdwebimageswiftui": "SDWebImage/SDWebImageSwiftUI",
    "sdwebimagewebpcoder": "SDWebImage/SDWebImageWebPCoder",
    "sdwebimagesvgcoder": "SDWebImage/SDWebImageSVGCoder",
    "rxswift": "ReactiveX/RxSwift",
    "rxcocoa": "ReactiveX/RxSwift",
    "rxrelay": "ReactiveX/RxSwift",
    "snapkit": "SnapKit/SnapKit",
    "lottie": "airbnb/lottie-ios",
    "realm": "realm/realm-swift",
    "realmswift": "realm/realm-swift",
    "stripe": "stripe/stripe-ios",
    "stripecore": "stripe/stripe-ios",
    "stripepayments": "stripe/stripe-ios",
    "stripepaymentsheet": "stripe/stripe-ios",
    "stripepaymentsui": "stripe/stripe-ios",
    "stripeuicore": "stripe/stripe-ios",
    "stripeapplepay": "stripe/stripe-ios",
    "sentry": "getsentry/sentry-cocoa",
    "sentryswiftui": "getsentry/sentry-cocoa",
    "firebasecore": "firebase/firebase-ios-sdk",
    "firebaseauth": "firebase/firebase-ios-sdk",
    "firebasemessaging": "firebase/firebase-ios-sdk",
    "firebasefirestore": "firebase/firebase-ios-sdk",
    "firebasedatabase": "firebase/firebase-ios-sdk",
    "firebasestorage": "firebase/firebase-ios-sdk",
    "firebasecrashlytics": "firebase/firebase-ios-sdk",
    "firebaseremoteconfig": "firebase/firebase-ios-sdk",
    "firebaseinstallations": "firebase/firebase-ios-sdk",
    "firebaseperformance": "firebase/firebase-ios-sdk",
    "firebasefunctions": "firebase/firebase-ios-sdk",
    "firebaseappcheck": "firebase/firebase-ios-sdk",
    "firebasesessions": "firebase/firebase-ios-sdk",
    "firebasecoreinternal": "firebase/firebase-ios-sdk",
    "googlesignin": "google/GoogleSignIn-iOS",
    "appauth": "openid/AppAuth-iOS",
    "grpc": "grpc/grpc-swift",
    "grpc-swift": "grpc/grpc-swift",
    "grpc-c++": "grpc/grpc",
    "grpc-core": "grpc/grpc",
    "grpcpp": "grpc/grpc",
    "trustkit": "datatheorem/TrustKit",
    "swiftyjson": "SwiftyJSON/SwiftyJSON",
    "starscream": "daltoniam/Starscream",
    "gtmsessionfetcher": "google/gtm-session-fetcher",
    "nanopb": "nanopb/nanopb",
    "openssl": "openssl/openssl",
}

# Curated advisories for SDKs OSV doesn't cover (mainly CocoaPods). Each entry:
# EXACT name -> [{id, summary, severity, fixed}]  — affected when version < `fixed`.
# Applied only when the framework version is KNOWN (an unknown version is
# reported as such, never assumed vulnerable).
_CURATED = {
    "afnetworking": [
        # TODO(verify): CVE-2015-1840 is the id used by the earlier analyzer for
        # the AFNetworking 2.5.x "domain validation disabled by default"
        # AFSecurityPolicy bug. Manually verify it against the AFNetworking
        # advisory before publishing results: CVE-2015-3996 (AFNetworking before
        # 2.5.3, SSL validation bypass) may be the intended one, and other ids
        # in that range (CVE-2015-1840 is a Rails XSS id in NVD) may have been
        # mis-copied.
        {"id": "CVE-2015-1840", "severity": "high", "fixed": "2.5.2",
         "summary": "SSL certificate domain validation disabled by default "
                    "(AFSecurityPolicy), enabling MITM."},
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


def _norm_name(name: str) -> str:
    return (name or "").lower().replace(".framework", "").replace(".xcframework", "").replace(" ", "")


def _repo_for(name: str) -> str | None:
    """Exact-name mapping only (never by substring)."""
    return _SDK_REPOS.get(_norm_name(name))


def _curated_for(name: str, version: str) -> list[dict]:
    """Curated advisories for an exactly-named SDK at a KNOWN version. With no
    version there is no basis for "affected": return nothing (the dependency is
    reported as "version unknown" by enrich())."""
    if not version:
        return []
    out = []
    for a in _CURATED.get(_norm_name(name), []):
        if _vtuple(version) < _vtuple(a["fixed"]):
            out.append({"id": a["id"], "severity": a["severity"],
                        "summary": a["summary"], "fixed": a["fixed"],
                        "source": "curated"})
    return out


# ---- CVSS ---------------------------------------------------------------

_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup (one decimal, away from zero, float-safe)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (i // 10000 + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score from a CVSS v3.0/3.1 vector string, or None if unparsable."""
    try:
        parts = dict(p.split(":", 1) for p in str(vector).strip().split("/") if ":" in p)
        scope_changed = parts["S"] == "C"
        c, i, a = (_CVSS3_CIA[parts[k]] for k in ("C", "I", "A"))
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_CVSS3_PR_C if scope_changed else _CVSS3_PR_U)[parts["PR"]]
        expl = 8.22 * _CVSS3_AV[parts["AV"]] * _CVSS3_AC[parts["AC"]] * pr * _CVSS3_UI[parts["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, ValueError, AttributeError):
        return None


def severity_from_score(score: float | None) -> str:
    """CVSS qualitative rating: >=9 critical, >=7 high, >=4 medium, else low."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def osv_severity(v: dict) -> str:
    """Severity of one OSV vuln record from its CVSS score (v3 vector computed
    locally, numeric scores taken as-is), falling back to the database's own
    qualitative rating; "unknown" when neither is available. Never "any v3 =
    high"."""
    best: float | None = None
    for s in v.get("severity") or []:
        raw = str(s.get("score", ""))
        score = None
        if raw.upper().startswith("CVSS:3"):
            score = cvss3_base_score(raw)
        else:
            try:
                score = float(raw)
            except ValueError:
                score = None
        if score is not None and (best is None or score > best):
            best = score
    if best is not None:
        return severity_from_score(best)
    qual = str((v.get("database_specific") or {}).get("severity", "")).lower()
    return {"critical": "critical", "high": "high", "moderate": "medium",
            "medium": "medium", "low": "low"}.get(qual, "unknown")


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
        if not r.ok:
            # Non-2xx (throttled, outage): do NOT cache an empty answer as "no CVEs".
            log.info("osv query for %s: HTTP %s (not cached)", purl, r.status_code)
            return vulns
        for v in r.json().get("vulns", []):
            fixed = ""
            for aff in v.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if ev.get("fixed"):
                            fixed = ev["fixed"]
            vulns.append({"id": v.get("id", "?"), "severity": osv_severity(v),
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
    each (a list of {id, severity, summary, fixed, source}) and a `cve_status`:
    "version unknown" (no version: nothing was checked, nothing is assumed),
    "unmapped" (no OSV repo / curated entry for this name), or "checked"."""
    cache = _load_cache()
    out = []
    for d in deps:
        name = d.get("name", "")
        ver = d.get("version") or ""
        cves: list[dict] = []
        repo = _repo_for(name)
        if not ver:
            status = "version unknown"
        elif repo is None and _norm_name(name) not in _CURATED:
            status = "unmapped"
        else:
            status = "checked"
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
        out.append({**d, "cves": uniq, "cve_status": status})
    _save_cache(cache)
    n = sum(len(x["cves"]) for x in out)
    if n:
        log.info("dependency CVE check: %d advisorie(s) across %d dependency(ies)",
                 n, sum(1 for x in out if x["cves"]))
    return out
