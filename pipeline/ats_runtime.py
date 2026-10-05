"""ATS declared-vs-needed gap (MASTG-TECH-0149).

Uses `nscurl --ats-diagnostics` to ask, per endpoint, "does this server pass
Apple's DEFAULT App Transport Security?" (TLS 1.2+, forward secrecy, strong
ciphers). Cross-referenced with what the app DECLARES in its Info.plist ATS
config, this reveals *unnecessary weakening*: apps that disable ATS globally or
add per-domain exceptions for endpoints that already meet default ATS. That is
the transport-layer analogue of the client-integrity adopt-vs-enforce gap.

Per-domain results are cached on disk (one nscurl run per domain across the
whole corpus). Set ATS_LOOKUP=0 to stay offline.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .config import CONFIG
from .util import get_logger, run_cmd

log = get_logger("ats", CONFIG.paths.log_dir)

_APPLE = ("apple.com", "icloud.com", "mzstatic.com", "itunes.apple.com",
          "cdn-apple.com", "apple-cloudkit.com")


def _enabled() -> bool:
    return os.environ.get("ATS_LOOKUP", "1").lower() not in ("0", "false", "no")


def _cache() -> Path:
    return CONFIG.paths.work_dir / "ats_cache.json"


def _load() -> dict:
    try:
        return json.loads(_cache().read_text())
    except (OSError, ValueError):
        return {}


def _save(c: dict) -> None:
    try:
        _cache().parent.mkdir(parents=True, exist_ok=True)
        _cache().write_text(json.dumps(c))
    except OSError:
        pass


def _nscurl_default(domain: str) -> "bool | None":
    """Pure nscurl check (no cache): True if the domain passes Apple's default
    ATS, False if not, None if it could not run (unreachable / no nscurl)."""
    p = run_cmd(["nscurl", "--ats-diagnostics", f"https://{domain}"], timeout=30)
    out = p.stdout + p.stderr
    m = re.search(r"Default ATS Secure Connection.*?Result\s*:\s*(PASS|FAIL)", out, re.S)
    if m:
        return m.group(1) == "PASS"
    return None  # unreachable / timed out / no output


def assess(ats_cfg: dict, domains: list[str], exception_details: list[dict],
           arbitrary_loads: bool, max_domains: int = 6) -> dict:
    """Run the gap analysis for one app. Returns per-domain results + the list of
    unnecessary weakenings + a summary. nscurl checks run in parallel."""
    if not _enabled():
        return {"checked": False, "reason": "ATS_LOOKUP disabled"}
    cache = _load()
    exc_doms = [d["domain"] for d in (exception_details or [])]
    # Prioritise domains the app explicitly weakened, then a sample of others.
    ordered = exc_doms + [d for d in domains if d not in exc_doms]
    ordered = [d for d in ordered if not any(d == a or d.endswith("." + a) for a in _APPLE)]
    ordered = ordered[:max_domains]

    # Resolve uncached domains concurrently (each nscurl run is independent).
    uncached = [d for d in ordered if d not in cache]
    if uncached:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(5, len(uncached))) as ex:
            for dom, ok in zip(uncached, ex.map(_nscurl_default, uncached)):
                cache[dom] = ok
        _save(cache)

    checked, unnecessary = [], []
    for dom in ordered:
        ok = cache.get(dom)
        checked.append({"domain": dom, "default_ats_pass": ok})
        if ok is True:
            if dom in exc_doms:
                unnecessary.append({"domain": dom, "kind": "exception",
                                    "detail": "per-domain ATS exception, but endpoint already passes default ATS"})
            elif arbitrary_loads:
                unnecessary.append({"domain": dom, "kind": "global",
                                    "detail": "NSAllowsArbitraryLoads set, but endpoint already passes default ATS"})
    _save(cache)
    tested = [c for c in checked if c["default_ats_pass"] is not None]
    passing = [c for c in tested if c["default_ats_pass"]]
    return {
        "checked": True,
        "domains": checked,
        "unnecessary_weakenings": unnecessary,
        "n_tested": len(tested),
        "n_pass_default": len(passing),
        "n_unnecessary": len(unnecessary),
        # Verdict for the app.
        "verdict": ("unnecessary_weakening" if unnecessary
                    else "justified" if (arbitrary_loads or exc_doms) and tested
                    else "clean" if tested else "inconclusive"),
    }


_IPLIT = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _hosts_from_urls(urls: list[str], exc_doms: list[str]) -> list[str]:
    """Real, reachable hostnames from the app's URLs (not the noisy domain-regex
    list, which catches SF Symbol names like '0.circle'). Plus declared ATS
    exception domains. Drops localhost / IP literals / placeholders."""
    from urllib.parse import urlparse
    hosts: list[str] = []

    def _ok(h: str) -> bool:
        if not h or "." not in h or "%" in h or " " in h:
            return False
        if h in ("localhost", "0.0.0.0") or h.startswith("127.") or _IPLIT.match(h):
            return False
        if h.split(".")[0] in ("ip",):     # 'ip:port' placeholders
            return False
        if not h.split(".")[-1].isalpha():  # TLD must be alphabetic
            return False
        return True

    for u in urls or []:
        try:
            h = (urlparse(u).hostname or "").lower()
        except ValueError:
            continue
        if _ok(h):
            hosts.append(h)
    for d in exc_doms or []:
        if _ok(d.lower()):
            hosts.append(d.lower())
    seen, out = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def assess_and_store(db, app_id: str) -> dict:
    """Load the app's stored analysis, run the gap check over the hostnames of
    its real URLs (+ declared ATS exception domains), store the result in the
    analysis.ats_gap column, and return it."""
    an = db.get_analysis(app_id)
    if not an:
        raise RuntimeError("app not analyzed yet (run deep analysis first)")
    ats = json.loads(an["ats"]) if an["ats"] else {}
    secrets = json.loads(an["secrets"]) if an["secrets"] else {}
    exc = [d["domain"] for d in (ats.get("exception_details") or [])]
    hosts = _hosts_from_urls(secrets.get("urls") or [], exc)
    res = assess(ats, hosts, ats.get("exception_details") or [],
                 bool(ats.get("allows_arbitrary_loads")))
    db.set_analysis_field(app_id, "ats_gap", json.dumps(res))
    return res
