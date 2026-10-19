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


def _tls_below_12(v) -> bool:
    """True for NSExceptionMinimumTLSVersion values below TLS 1.2 (TLSv1.0/1.1)."""
    m = re.search(r"(\d+)\.(\d+)", str(v or ""))
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2))) < (1, 2)


def exception_effect(det: dict | None, arbitrary_loads: bool) -> str | None:
    """What a per-domain NSExceptionDomains entry actually does.
      weakening     - it allows insecure HTTP, lowers the TLS floor below 1.2, or
                      disables forward secrecy (relative to default ATS).
      strengthening - no weakening key, under NSAllowsArbitraryLoads=YES: a scoped
                      entry re-enables default ATS for that host (the exception
                      overrides the global opt-out), i.e. it is a hardening.
      neutral       - no weakening key and ATS is on globally (e.g. only
                      NSIncludesSubdomains / NSRequiresCertificateTransparency).
    None when the domain has no exception entry."""
    if det is None:
        return None
    weak = (bool(det.get("insecure_http")) or _tls_below_12(det.get("min_tls"))
            or det.get("forward_secrecy") is False)
    if weak:
        return "weakening"
    return "strengthening" if arbitrary_loads else "neutral"


def assess(ats_cfg: dict, domains: list[str], exception_details: list[dict],
           arbitrary_loads: bool, max_domains: int = 6) -> dict:
    """Run the gap analysis for one app. Returns per-domain results + the list of
    unnecessary weakenings + a summary. nscurl checks run in parallel.

    Probe results are tri-state: True (passes default ATS), False (fails), None
    (unreachable / nscurl missing). None is never cached, never counted as
    tested, and never used to call a weakening "justified"."""
    if not _enabled():
        return {"checked": False, "reason": "ATS_LOOKUP disabled"}
    cache = _load()
    exc_map = {d["domain"]: d for d in (exception_details or []) if d.get("domain")}
    exc_doms = list(exc_map)
    # Prioritise domains the app explicitly weakened, then a sample of others.
    ordered = exc_doms + [d for d in domains if d not in exc_doms]
    ordered = [d for d in ordered if not any(d == a or d.endswith("." + a) for a in _APPLE)]
    ordered = ordered[:max_domains]

    # Resolve domains without a cached True/False concurrently (each nscurl run
    # is independent). A stale None in an old cache file is re-probed, not trusted.
    results: dict[str, bool | None] = {d: cache[d] for d in ordered
                                       if isinstance(cache.get(d), bool)}
    uncached = [d for d in ordered if d not in results]
    if uncached:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(5, len(uncached))) as ex:
            for dom, ok in zip(uncached, ex.map(_nscurl_default, uncached)):
                results[dom] = ok
                if ok is not None:
                    cache[dom] = ok
                else:
                    cache.pop(dom, None)
        _save(cache)

    checked, unnecessary, strengthening = [], [], []
    for dom in ordered:
        ok = results.get(dom)
        effect = exception_effect(exc_map.get(dom), arbitrary_loads)
        entry = {"domain": dom, "default_ats_pass": ok, "exception_effect": effect}
        checked.append(entry)
        if effect == "strengthening":
            strengthening.append(dom)
        if ok is not True:
            continue   # unreachable (None) or genuinely failing: nothing is unnecessary
        if effect == "weakening":
            unnecessary.append({"domain": dom, "kind": "exception",
                                "detail": "per-domain ATS exception weakens ATS, but endpoint already passes default ATS"})
        elif effect is None and arbitrary_loads:
            unnecessary.append({"domain": dom, "kind": "global",
                                "detail": "NSAllowsArbitraryLoads set, but endpoint already passes default ATS"})
    tested = [c for c in checked if c["default_ats_pass"] is not None]
    passing = [c for c in tested if c["default_ats_pass"]]
    weakens = arbitrary_loads or any(c["exception_effect"] == "weakening" for c in checked)
    if unnecessary:
        verdict = "unnecessary_weakening"
    elif not tested:
        verdict = "untested"          # only unreachable hosts: no claim either way
    elif weakens:
        verdict = "justified"         # weakened, and every reachable host needs it
    else:
        verdict = "clean"
    return {
        "checked": True,
        "domains": checked,
        "unnecessary_weakenings": unnecessary,
        "strengthening_exceptions": strengthening,
        "n_tested": len(tested),
        "n_unreachable": len(checked) - len(tested),
        "n_pass_default": len(passing),
        "n_unnecessary": len(unnecessary),
        # Verdict for the app.
        "verdict": verdict,
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
