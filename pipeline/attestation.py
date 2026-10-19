"""Stage H: App Attest enforcement measurement (graded probe battery).

Weak server-side enforcement is a *backend behavior*, so it can only be measured
by testing the backend's response, never from the binary. For each App-Attest app
with a test account, we reach a gated action logged in (pinning bypassed so we can
see the traffic) and run a battery of probes, each defeating attestation a
different way, then grade how the backend reacts:

  baseline   : attestation intact          -> must serve gated data (else INCONCLUSIVE)
  omit       : no assertion sent           -> served? => NOT_REQUIRED
  tamper     : garbage assertion           -> served? => SIGNATURE_NOT_VERIFIED
  noreg      : key never registered        -> served? => NOT_REGISTERED_OK
  downgrade  : App Attest reported unsupported -> served? => DOWNGRADEABLE

Plus a coverage map from the baseline flows: which gated endpoints actually carry
an assertion (partial coverage is the most common real bug).

Validity rules (see docs/audit-2026-10-18.md, Tier 1 #1-2):
  * The oracle is derived from the BASELINE: only endpoints that carried an
    assertion and returned data are "gated". Unrelated 2xx traffic never counts.
  * Each probe's traffic is captured in a session cleared AFTER the intact login
    phase, with the hook armed persistently and the app re-exercised without
    relaunch, so the intact phase cannot leak into the probe's evidence.
  * A probe only yields a verdict if it armed, its hook fired, and the probe-phase
    request's assertion state matches what the probe expects (a cached assertion
    or session token from the intact phase proves nothing). Otherwise it is None
    (inconclusive) and can never be read as enforcement.
Remaining caveats: the backend may remember a key registered by an earlier run on
the same account (affects `noreg`); replay is not automated here.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import capture, device, instrument
from .config import CONFIG
from .db import Database
from .models import BackendBehavior, BypassStage, EnforcementVerdict, Stage, WorkState
from .util import get_logger, run_cmd

log = get_logger("attestation", CONFIG.paths.log_dir)

SCRIPTS = CONFIG.paths.root / "scripts"

# (probe name, frida script or None for the intact baseline)
# Core battery (default): baseline + the four probes that map to F1, F3, F4.
# `noreg` and `downgrade` are kept in PROBES_FULL (opt-in): noreg behaves like
# omit, downgrade tests the app's fallback rather than the server.
PROBES: list[tuple[str, Path | None]] = [
    ("baseline", None),
    ("omit", SCRIPTS / "attest_omit.js"),        # F1: assertion not required
    ("tamper", SCRIPTS / "attest_tamper.js"),    # F1: signature not verified (structure intact)
    ("bind", SCRIPTS / "attest_bind.js"),        # F3: clientDataHash not bound to the request
    ("replay", SCRIPTS / "attest_replay.js"),    # F4: counter / challenge not enforced
]
PROBES_FULL: list[tuple[str, Path | None]] = PROBES + [
    ("noreg", SCRIPTS / "attest_noreg.js"),      # weak: key registration fails -> behaves like omit
    ("downgrade", SCRIPTS / "attest_downgrade.js"),  # app's unsupported-device fallback
]

# Request headers that plausibly carry an attestation assertion/token.
# Attestation-specific wording, matched in request HEADERS and BODY (NOT a generic
# x-.*token, which matches auth/session/CSRF tokens). See attest_detect for rationale.
_ASSERT_HEADER_RE = re.compile(
    r"attest|(?<!client)(?<!client[-_])assert|integrity|device[-_]?check|app[-_]?check|approov|"
    r"client[-_]?data[-_]?hash",
    re.IGNORECASE)   # OAuth client_assertion / clientAssertion / client-assertion-type are not attestation

# Content fingerprints, independent of header names. An App Attest assertion is
# the CBOR map {signature, authenticatorData}; canonical key order puts the
# 9-byte key first, so the blob always starts a2 69 'signature'. An attestation
# object starts a3 63 'fmt' 6f 'apple-appattest'. Both are sent base64 (or
# base64url, or hex) and keep these prefixes verbatim.
ASSERTION_B64_PREFIX = "omlzaWduYXR1cm"   # first 14 chars are invariant (11 bytes do not align to 3)
ATTESTATION_B64_PREFIX = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0"
_FINGERPRINTS = (
    ("cbor-assertion", ASSERTION_B64_PREFIX),
    ("cbor-assertion", ASSERTION_B64_PREFIX.replace("+", "-").replace("/", "_")),
    ("cbor-assertion", "a2697369676e6174757265"),
    ("cbor-attestation", ATTESTATION_B64_PREFIX),
    ("cbor-attestation", ATTESTATION_B64_PREFIX.replace("+", "-").replace("/", "_")),
    ("cbor-attestation", "a363666d746f6170706c652d617070617474657374"),
)
_MIN_TOKEN_LEN = 16   # an attestation-named header whose value is shorter than this is empty/omitted


def assertion_fingerprint(text: str) -> str | None:
    """'cbor-assertion' / 'cbor-attestation' if `text` contains the encoded
    prefix of an App Attest assertion / attestation object, else None."""
    if not text:
        return None
    for kind, pfx in _FINGERPRINTS:
        if pfx in text:
            return kind
    low = text.lower()
    for kind, pfx in _FINGERPRINTS[2:3] + _FINGERPRINTS[5:6]:
        if pfx in low:
            return kind
    return None


def assertion_evidence(f) -> list[str]:
    """Where a request carries attestation evidence: header names (matched by
    content fingerprint, by attestation wording in the name with a non-empty
    value, or by wording in the value) and/or 'body'. Fingerprint hits add a
    'cbor-assertion' / 'cbor-attestation' token.

    Judged on VALUES: a header such as `X-Assertion:` with an empty value is an
    OMITTED assertion, not a carried one (the omit probe depends on this)."""
    hits: list[str] = []
    hdrs = f.request_headers or {}
    items = hdrs.items() if isinstance(hdrs, dict) else [(h, "") for h in hdrs]
    for name, val in items:
        name = str(name or "")
        val = val if isinstance(val, str) else str(val or "")
        fp = assertion_fingerprint(val[:8000])
        if fp:
            hits.append(name)
            hits.append(fp)
            continue
        if len(val.strip()) < _MIN_TOKEN_LEN:
            continue
        if _ASSERT_HEADER_RE.search(name) or _ASSERT_HEADER_RE.search(val[:512]):
            hits.append(name)
    body = f.request_body or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if body:
        fp = assertion_fingerprint(body[:65536])
        if fp:
            hits.append("body")
            hits.append(fp)
        elif _ASSERT_HEADER_RE.search(body[:4000]):
            hits.append("body")
    return hits


def _req_carries_assertion(f) -> bool:
    """True if the request carries attestation evidence (see assertion_evidence)."""
    return bool(assertion_evidence(f))


def _endpoint_key(f) -> str:
    """host + path (no query) identifies a gated endpoint across runs."""
    path = (f.url or "").split("?")[0]
    path = path.split("//", 1)[-1]
    path = path[len(f.host):] if f.host and path.startswith(f.host) else path
    return f"{f.host}{path}"


def _is_data_2xx(f) -> bool:
    return (200 <= f.status < 300 and bool(f.host) and not capture.is_excluded(f.host)
            and len(f.response_body or "") > 64)


def _gated_endpoints(flows: list) -> set[str]:
    """Baseline-derived oracle: the endpoints that BOTH carried an assertion AND
    returned real data. Only these are tested by the probes; serving unrelated
    config/analytics/CDN responses must never count as gated data."""
    return {_endpoint_key(f) for f in flows if _is_data_2xx(f) and _req_carries_assertion(f)}


# What a probe-phase request to a gated endpoint should look like for its reply
# to be evidence. tamper: a (garbage) assertion must be present; omit/noreg/
# downgrade: no assertion. A mismatch means the app reused a cached assertion or
# session token from the intact phase, which proves nothing about enforcement.
_PROBE_EXPECTS_ASSERTION = {"tamper": True, "omit": False, "noreg": False, "downgrade": False,
                            "replay": True, "bind": True}


def _json_keys(body: str) -> set[str] | None:
    try:
        v = json.loads(body)
    except (ValueError, TypeError):
        return None
    return set(v.keys()) if isinstance(v, dict) else set()


def _response_similar(base, probe) -> bool:
    """Did the probe-phase response look like the baseline response for the
    same endpoint? Same status class, comparable size and, for JSON objects, a
    mostly overlapping key set. A server that detects the tamper and serves a
    limited / error payload (Apple's recommended soft enforcement) fails this."""
    if (base.status // 100) != (probe.status // 100):
        return False
    bl, pl = len(base.response_body or ""), len(probe.response_body or "")
    if bl and pl and not (0.5 <= pl / bl <= 2.0):
        return False
    bk, pk = _json_keys(base.response_body or ""), _json_keys(probe.response_body or "")
    if bk is None and pk is None:
        return True
    if bk is None or pk is None:
        return False
    if not bk and not pk:
        return True
    inter, union = len(bk & pk), len(bk | pk)
    return union == 0 or inter / union >= 0.6


def _probe_outcome(name: str, gated: set[str], probe_flows: list,
                   armed: bool, hit: bool, baseline_flows: list | None = None
                   ) -> tuple[bool | str | None, str]:
    """Result for one probe:
      True       gated data served in full under the probe (weakness)
      "degraded" served, but a different / limited response than the baseline
                 for that endpoint (detected and degraded: soft enforcement)
      False      refused (enforced for this probe)
      None       inconclusive
    Returns (outcome, reason)."""
    if not gated:
        return None, "no attested gated endpoint in baseline"
    if not armed:
        return None, "probe script did not arm"
    if not hit:
        return None, "probe hook never fired (assertion cached / path not exercised)"
    expects = _PROBE_EXPECTS_ASSERTION.get(name, False)
    base_by_key: dict[str, object] = {}
    for f in baseline_flows or []:
        k = _endpoint_key(f)
        if k in gated and _is_data_2xx(f) and k not in base_by_key:
            base_by_key[k] = f
    requested = served = full = False
    for f in probe_flows:
        k = _endpoint_key(f)
        if k not in gated:
            continue
        if _req_carries_assertion(f) != expects:
            continue  # cached/legit assertion state: not evidence either way
        requested = True
        if _is_data_2xx(f):
            served = True
            base = base_by_key.get(k)
            if base is None or _response_similar(base, f):
                full = True
    if not requested:
        return None, "gated endpoint not re-exercised under the probe"
    if served and not full:
        return "degraded", "served a different / limited response under probe (soft enforcement)"
    return served, ("served in full under probe" if served else "refused under probe")


def _coverage_class(flows: list) -> str:
    """How the app covers its data endpoints with assertions:
      per_request  every 2xx data endpoint carries an assertion
      per_session  the unattested data endpoints all come AFTER the first
                   attested one and carry a session credential (Authorization /
                   Cookie): attest-at-login, then a bound session. Normal design.
      partial      unattested data endpoints that are not explained by a session
      none         no attested endpoint at all"""
    data = [f for f in flows if _is_data_2xx(f)]
    attested = [f for f in data if _req_carries_assertion(f)]
    plain = [f for f in data if not _req_carries_assertion(f)]
    if not attested:
        return "none"
    if not plain:
        return "per_request"
    starts = [f.started for f in attested if getattr(f, "started", "")]
    first = min(starts) if starts else None

    def _has_credential(f) -> bool:
        keys = {str(k).lower() for k in (f.request_headers or {}).keys()}
        return bool(keys & {"authorization", "cookie"})
    if first is not None and all(getattr(f, "started", "") and f.started >= first and _has_credential(f)
                                 for f in plain):
        return "per_session"
    return "partial"


def load_accounts() -> dict[str, dict[str, str]]:
    path = CONFIG.paths.results_dir / "accounts.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def creds_for(accounts: dict, app_id: str, bundle_id: str = "") -> dict | None:
    """Pick credentials for an app: a specific app_id or bundle_id entry wins,
    else the wildcard default ('*' or 'default') applies to every app."""
    return (accounts.get(app_id) or accounts.get(bundle_id or "")
            or accounts.get("*") or accounts.get("default"))


def _creds_for(row, accounts: dict) -> dict[str, str] | None:
    return creds_for(accounts, row["app_id"], row["bundle_id"] or "")


def _served_gated_data(flows: list) -> bool:
    """A 2xx response from a non-excluded host with a non-trivial body = gated
    data was served."""
    for f in flows:
        if 200 <= f.status < 300 and f.host and not capture.is_excluded(f.host):
            if len(f.response_body or "") > 64:
                return True
    return False


def _coverage(flows: list) -> tuple[int, int]:
    """(gated_endpoints, of_which_carry_an_assertion). Coverage ratio = 2nd/1st."""
    gated = attested = 0
    seen: set[str] = set()
    for f in flows:
        if not (200 <= f.status < 300 and f.host and not capture.is_excluded(f.host)):
            continue
        if len(f.response_body or "") <= 64:
            continue
        key = f.host + (f.url.split("?")[0][-40:])
        if key in seen:
            continue
        seen.add(key)
        gated += 1
        if _req_carries_assertion(f):
            attested += 1
    return gated, attested


_ARMED_RE = re.compile(r"ATTESTPROBE ARMED (\w+)")
_HIT_RE = re.compile(r"ATTESTPROBE HIT (\w+)")


def _materialize_script(script: Path, gated: set[str] | None) -> Path:
    """Scripts may carry a `__GATED__` placeholder (the bind probe needs the
    baseline's gated endpoint keys). Substitute it into a work copy; scripts
    without the placeholder are used as-is."""
    try:
        text = script.read_text()
    except OSError:
        return script
    if "__GATED__" not in text:
        return script
    out = CONFIG.paths.work_dir / f"probe_{script.stem}.js"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text.replace("__GATED__", json.dumps(sorted(gated or []))))
    return out


def _arm_probe(script: Path, settle: float = 6.0, gated: set[str] | None = None):
    """Attach frida to the running gadget and load `script` PERSISTENTLY (no -q,
    which would detach and unload the hooks). Returns (proc, lines) where `lines`
    is a live list of the script's console output; `_disarm` stops it."""
    import subprocess
    import threading
    import time as _t
    lines: list[str] = []
    script = _materialize_script(script, gated)
    try:
        proc = subprocess.Popen(["frida", "-U", "-n", "Gadget", "-l", str(script)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except FileNotFoundError:
        log.error("frida CLI not found; cannot arm probe %s", script.name)
        return None, lines

    def _pump():
        try:
            for ln in proc.stdout:  # type: ignore[union-attr]
                lines.append(ln.rstrip("\n"))
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=_pump, daemon=True).start()
    deadline = _t.time() + settle
    while _t.time() < deadline and not any(_ARMED_RE.search(x) for x in lines):
        if proc.poll() is not None:
            break
        _t.sleep(0.3)
    return proc, lines


def _disarm(proc) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _export_flows(app_id: str, tag: str) -> list:
    har = CONFIG.paths.results_dir / f"{app_id}_attest_{tag}.har"
    try:
        har.unlink()  # never let a failed export reuse a previous run's file
    except FileNotFoundError:
        pass
    capture.export_har(har)
    if not har.exists():
        return []
    return capture.har_to_flows(capture.load_har(har), CONFIG.test_device.client_ip)


def _run_probe(app_id: str, bundle_id: str, decrypted: str, creds: dict,
               script: Path | None, gated: set[str] | None = None) -> dict:
    """One probe run. Returns {flows, armed, hit, launched, error, login_status,
    crashed, crash_reason, syslog}.

    baseline (script=None): intact login drive under AttestObserver; flows =
    whole session; syslog = the observer trail (which calls happened, when).
    probe: intact login drive (reach the logged-in state), then the session is
    CLEARED, the probe is armed persistently, and the already-running app is
    re-exercised WITHOUT relaunch (so the Frida attach survives). flows = probe
    phase only, so the intact phase can never masquerade as 'served under probe'.
    """
    out = {"flows": [], "armed": False, "hit": False, "launched": False, "error": "",
           "login_status": "none", "crashed": False, "crash_reason": "", "syslog": ""}
    # Gadget + SSL Kill Switch + AttestObserver + SideloadFix: the proxy must
    # see a pinned app's gated endpoints or every probe is inconclusive.
    ok, signed, err = instrument.build(app_id, decrypted, "attest_probe")
    if not ok:
        out["error"] = f"build failed: {err}"
        log.warning("%s attest build failed: %s", app_id, err)
        return out
    installed, ierr = device.install_ipa(signed)
    if not installed:
        out["error"] = f"install failed: {ierr}"
        log.warning("%s attest install failed: %s", app_id, ierr)
        return out

    capture.check_connection()
    capture.clear_session()
    device.flush_crash_reports()
    driver = device.AppiumDriver(credentials=creds)
    box: dict = {}

    def _drive():
        box["dr"] = driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=True)
    out["syslog"] = device.capture_syslog(during=_drive, grep="OBSERVER") or ""
    dr = box.get("dr")
    out["launched"] = bool(dr and dr.launched)
    out["login_status"] = getattr(dr, "login_status", "none") if dr else "none"
    out["crashed"] = bool(dr and (getattr(dr, "died", False) or dr.crashed))
    if out["crashed"]:
        from . import escalate
        out["crash_reason"] = escalate.crash_reason(getattr(dr, "crash_report", "") or "")
    tag = script.stem if script else "baseline"

    if script is None:
        out["flows"] = _export_flows(app_id, tag)
        device.uninstall(bundle_id)
        return out

    if not out["launched"] or not script.exists():
        out["error"] = "app did not launch" if not out["launched"] else "probe script missing"
        device.uninstall(bundle_id)
        return out

    # Probe phase: fresh session, persistent hook, no relaunch.
    capture.clear_session()
    proc, lines = _arm_probe(script, gated=gated)
    out["armed"] = any(_ARMED_RE.search(x) for x in lines)
    drive_attached = getattr(driver, "drive_attached", None)
    if out["armed"] and drive_attached is not None:
        try:
            drive_attached(bundle_id, CONFIG.runtime.monitor_seconds)
        except Exception as e:  # noqa: BLE001
            out["error"] = f"attached drive failed: {e}"
    elif out["armed"]:
        out["error"] = "driver lacks drive_attached (would relaunch and drop the hook)"
    else:
        out["error"] = "probe did not arm: " + " | ".join(lines[-3:])
    _disarm(proc)
    out["hit"] = any(_HIT_RE.search(x) for x in lines)
    out["flows"] = _export_flows(app_id, tag)
    device.uninstall(bundle_id)
    return out


# ---- baseline classification (tiers) -------------------------------------------
# The re-signed client carries a foreign relying-party hash, so a server that
# implements Apple's verification refuses it at ENROLLMENT. The baseline run is
# therefore the strongest probe and sorts servers into tiers before any script
# is armed:
#   T0  enrollment refused, nothing gated served        REFUSED_AT_ENROLLMENT
#   T1  enrolled; probes all refused                     ENFORCED / PARTIAL_COVERAGE
#   T1s enrolled; probes degraded                        SOFT_DEGRADED
#   T2  enrolled; a probe served in full                 the weakness verdicts
#   T3  assertions produced, never sent with a request   ASSERTION_UNUSED
_UNRELATED_REFUSAL_RE = re.compile(r"version|upgrade|update required|rate ?limit|too many|maintenance",
                                   re.IGNORECASE)
_ATTEST_REFUSAL_RE = re.compile(r"attest|integrity|device ?check|signature|provenance|tamper", re.IGNORECASE)
_LOGIN_OK = ("success", "not_needed")


def _enrollment_uploads(flows: list) -> list:
    """Requests that carry an attestation OBJECT (enrollment), any status."""
    return [f for f in flows if f.host and not capture.is_excluded(f.host)
            and "cbor-attestation" in assertion_evidence(f)]


def classify_baseline(flows: list, syslog_text: str, login_status: str,
                      crashed: bool = False, crash_reason: str = "") -> dict:
    """Decide what the baseline run showed BEFORE probing. Returns
    {proceed, verdict, tier, reason, evidence}. `proceed` is True only when
    attested gated endpoints exist (the probe battery has an oracle)."""
    from . import attest_detect
    trail = attest_detect.parse_trail(syslog_text or "")
    calls = trail.appattest_calls
    gated = _gated_endpoints(flows)
    uploads = _enrollment_uploads(flows)
    login_ok = login_status in _LOGIN_OK
    ev = {"login_status": login_status, "observer_loaded": trail.loaded,
          "appattest_calls": calls, "enrollment_uploads": [
              {"host": f.host, "status": f.status, "body": (f.response_body or "")[:160]}
              for f in uploads[:4]],
          "gated_endpoints": sorted(gated)[:8]}

    def res(proceed, verdict, tier, reason):
        return {"proceed": proceed, "verdict": verdict, "tier": tier, "reason": reason, "evidence": ev}

    if gated:
        return res(True, None, "", f"{len(gated)} attested gated endpoint(s)")
    if crashed:
        from . import escalate
        intent = escalate.crash_intent(crash_reason)
        why = "app crashed / exited during the baseline"
        if intent == "entitlement":
            why += " (stripped entitlement: re-run with the entitlement shim)"
        elif intent == "tamper":
            why += " (tamper-worded crash: client-side integrity check, not server enforcement)"
        return res(False, EnforcementVerdict.INCONCLUSIVE, "", why + (f": {crash_reason[:120]}" if crash_reason else ""))
    if uploads and all(not (200 <= f.status < 300) for f in uploads):
        bodies = " ".join((f.response_body or "")[:400] for f in uploads)
        if _UNRELATED_REFUSAL_RE.search(bodies) and not _ATTEST_REFUSAL_RE.search(bodies):
            return res(False, EnforcementVerdict.INCONCLUSIVE, "",
                       "enrollment upload refused for an unrelated reason (version / rate limit)")
        if login_ok or _ATTEST_REFUSAL_RE.search(bodies):
            return res(False, EnforcementVerdict.REFUSED_AT_ENROLLMENT, "T0",
                       "the re-signed client's attestation was refused at enrollment and no gated data was served")
        return res(False, EnforcementVerdict.INCONCLUSIVE, "",
                   f"enrollment upload refused but login did not complete ({login_status})")
    if login_status not in _LOGIN_OK and login_status != "none":
        return res(False, EnforcementVerdict.INCONCLUSIVE, "", f"login {login_status}: gated screens not reached")
    if any(("generateAssertion" in c) or ("attestKey" in c) for c in calls):
        if login_ok:
            return res(False, EnforcementVerdict.ASSERTION_UNUSED, "T3",
                       "assertions were produced but no data request carried one (content, wording or timing)")
        return res(False, EnforcementVerdict.INCONCLUSIVE, "",
                   "assertions produced, no attested request seen, and no login was driven")
    if trail.loaded and not calls and login_ok:
        return res(False, EnforcementVerdict.NOT_USED, "not_used",
                   "App Attest never called during a logged-in drive")
    if not trail.loaded:
        return res(False, EnforcementVerdict.INCONCLUSIVE, "",
                   "no attested gated endpoint observed (observer trail missing: dylib not loaded or syslog unavailable)")
    return res(False, EnforcementVerdict.INCONCLUSIVE, "", "no attested gated endpoint observed")


_TIER_OF = {
    EnforcementVerdict.REFUSED_AT_ENROLLMENT: "T0",
    EnforcementVerdict.ENFORCED: "T1",
    EnforcementVerdict.PARTIAL_COVERAGE: "T1",
    EnforcementVerdict.SOFT_DEGRADED: "T1s",
    EnforcementVerdict.ASSERTION_UNUSED: "T3",
    EnforcementVerdict.NOT_USED: "not_used",
    EnforcementVerdict.INCONCLUSIVE: "",
}


def tier_of(verdict: EnforcementVerdict) -> str:
    """T0 / T1 / T1s / T2 / T3 / not_used / '' (inconclusive). Every weakness
    verdict (served in full under a probe) is T2."""
    return _TIER_OF.get(verdict, "T2")


_WEAKNESS_ORDER = (
    ("tamper", EnforcementVerdict.SIGNATURE_NOT_VERIFIED),
    ("omit", EnforcementVerdict.NOT_REQUIRED),
    ("bind", EnforcementVerdict.UNBOUND_REQUEST),
    ("replay", EnforcementVerdict.REPLAYABLE),
    ("noreg", EnforcementVerdict.NOT_REGISTERED_OK),
    ("downgrade", EnforcementVerdict.DOWNGRADEABLE),
)


def _grade(served: dict, coverage: tuple[int, int],
           coverage_class: str = "partial") -> EnforcementVerdict:
    """Grade from probe results (True = served in full / weak, "degraded" =
    served a limited response, False = refused, None = inconclusive). ENFORCED
    requires the two strongest probes (tamper, omit) to be DEFINITE refusals;
    inconclusive probes never count as evidence of enforcement. A degraded
    response is soft enforcement (detected, not blocked), its own rung."""
    if not served.get("baseline"):
        return EnforcementVerdict.INCONCLUSIVE
    for name, verdict in _WEAKNESS_ORDER:     # strongest weakness first
        if served.get(name) is True:
            return verdict
    if any(v is True for k, v in served.items() if k != "baseline"):
        return EnforcementVerdict.WEAK_OTHER
    if any(v == "degraded" for k, v in served.items() if k != "baseline"):
        return EnforcementVerdict.SOFT_DEGRADED
    if served.get("tamper") is not False or served.get("omit") is not False:
        return EnforcementVerdict.INCONCLUSIVE  # could not establish a definite refusal
    # All definite tamper probes refused. Coverage: unattested data endpoints
    # explained by an attested session are fine; unexplained ones are partial.
    gated, attested = coverage
    if coverage_class == "partial" and gated > 0 and 0 < attested < gated:
        return EnforcementVerdict.PARTIAL_COVERAGE
    return EnforcementVerdict.ENFORCED


def _to_behavior(v: EnforcementVerdict) -> BackendBehavior:
    if v in (EnforcementVerdict.ENFORCED, EnforcementVerdict.REFUSED_AT_ENROLLMENT):
        return BackendBehavior.FAIL_CLOSED
    if v is EnforcementVerdict.SOFT_DEGRADED:
        return BackendBehavior.SOFT_DEGRADED
    if v in (EnforcementVerdict.INCONCLUSIVE, EnforcementVerdict.ASSERTION_UNUSED,
             EnforcementVerdict.NOT_USED):
        return BackendBehavior.INCONCLUSIVE   # no gated oracle: nothing to call open or closed
    return BackendBehavior.FAIL_OPEN  # any weakness = effectively fails open


def process_app(db: Database, row, accounts: dict, full: bool = False) -> EnforcementVerdict:
    app_id, bundle_id = row["app_id"], row["bundle_id"]
    creds = _creds_for(row, accounts)
    with db.connect() as c:
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    decrypted = ac["ipa_path"] if ac else ""

    if not creds or not decrypted:
        _save(db, app_id, EnforcementVerdict.INCONCLUSIVE, {}, (0, 0),
              WorkState.UNTESTED, "no account or ipa")
        return EnforcementVerdict.INCONCLUSIVE

    served: dict = {}
    reasons: dict = {}
    # Baseline first: it defines the oracle (the attested gated endpoints) and,
    # on its own, sorts T0 / T3 / not-used servers out before any probe.
    base = _run_probe(app_id, bundle_id, decrypted, creds, None)
    bl = classify_baseline(base["flows"], base["syslog"], base["login_status"],
                           base["crashed"], base["crash_reason"])
    if bl["verdict"] is EnforcementVerdict.REFUSED_AT_ENROLLMENT:
        # A refusal must repeat before it counts: rule out a one-off server hiccup.
        log.info("%s baseline: enrollment refused; re-running the baseline once to confirm", app_id)
        base2 = _run_probe(app_id, bundle_id, decrypted, creds, None)
        bl2 = classify_baseline(base2["flows"], base2["syslog"], base2["login_status"],
                                base2["crashed"], base2["crash_reason"])
        if bl2["verdict"] is not EnforcementVerdict.REFUSED_AT_ENROLLMENT:
            bl = bl2 if bl2["proceed"] else {**bl2, "verdict": EnforcementVerdict.INCONCLUSIVE, "tier": "",
                                              "reason": "enrollment refusal did not repeat: " + bl2["reason"]}
            base = base2
    reasons["baseline"] = bl["reason"]
    reasons["baseline_evidence"] = bl["evidence"]
    gated = set(bl["evidence"].get("gated_endpoints", [])) if bl["proceed"] else set()
    gated = _gated_endpoints(base["flows"]) if bl["proceed"] else gated
    served["baseline"] = bool(gated)

    if not bl["proceed"]:
        verdict = bl["verdict"]
        tier = bl["tier"] or tier_of(verdict)
        reasons["tier"] = tier
        state = (WorkState.POSITIVE if verdict in (EnforcementVerdict.REFUSED_AT_ENROLLMENT,
                                                   EnforcementVerdict.ASSERTION_UNUSED)
                 else WorkState.DONE_NEGATIVE if verdict is EnforcementVerdict.NOT_USED
                 else WorkState.UNTESTED)
        _save(db, app_id, verdict, served, (0, 0), state, "" if tier else bl["reason"], reasons)
        log.info("%s attestation -> %s [%s] (%s)", app_id, verdict.value, tier or "inconclusive", bl["reason"])
        return verdict

    for name, script in (PROBES_FULL if full else PROBES):
        if script is None:
            continue
        res = _run_probe(app_id, bundle_id, decrypted, creds, script, gated)
        outcome, why = _probe_outcome(name, gated, res["flows"], res["armed"], res["hit"],
                                      baseline_flows=base["flows"])
        if outcome is None and res["armed"] and not res["error"]:
            # Hook never fired or endpoint not re-exercised: one retry.
            res = _run_probe(app_id, bundle_id, decrypted, creds, script, gated)
            outcome, why = _probe_outcome(name, gated, res["flows"], res["armed"], res["hit"],
                                          baseline_flows=base["flows"])
            why += " (after retry)"
        served[name] = outcome
        reasons[name] = why if not res["error"] else f"{why}; {res['error']}"
        log.info("%s probe %s -> %s (%s)", app_id, name, outcome, reasons[name])

    coverage = _coverage(base["flows"])
    cov_class = _coverage_class(base["flows"])
    reasons["coverage"] = cov_class
    verdict = _grade(served, coverage, cov_class)
    reasons["tier"] = tier_of(verdict)
    state = WorkState.POSITIVE if verdict is not EnforcementVerdict.INCONCLUSIVE else WorkState.UNTESTED
    _save(db, app_id, verdict, served, coverage, state, "", reasons)
    log.info("%s attestation -> %s [%s]  (served=%s coverage=%s)", app_id, verdict.value,
             reasons["tier"] or "inconclusive", served, coverage)
    return verdict


def _save(db: Database, app_id: str, verdict: EnforcementVerdict, served: dict,
          coverage: tuple[int, int], state: WorkState, error: str = "",
          reasons: dict | None = None) -> None:
    db.add_column_if_missing("attestation", "verdict", "TEXT")
    db.add_column_if_missing("attestation", "probe_results", "TEXT")
    db.add_column_if_missing("attestation", "coverage_gated", "INTEGER DEFAULT 0")
    db.add_column_if_missing("attestation", "coverage_attested", "INTEGER DEFAULT 0")
    behavior = _to_behavior(verdict)
    neutralized = any(v is True for k, v in served.items() if k != "baseline")
    db.save_attestation(app_id, tested=(verdict is not EnforcementVerdict.INCONCLUSIVE),
                        neutralized=neutralized, behavior=behavior, state=state, error=error)
    reasons = dict(reasons or {})
    payload = {"served": served, "reasons": reasons, "tier": reasons.pop("tier", tier_of(verdict)),
               "baseline_evidence": reasons.pop("baseline_evidence", {})}
    with db.connect() as c:
        c.execute("UPDATE attestation SET verdict=?, probe_results=?, coverage_gated=?, "
                  "coverage_attested=? WHERE app_id=?",
                  (verdict.value, json.dumps(payload), coverage[0], coverage[1], app_id))


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    if CONFIG.missing_for_dynamic():
        log.error("cannot run attestation; missing: %s", "; ".join(CONFIG.missing_for_dynamic()))
        return {}
    accounts = load_accounts()
    if not accounts:
        log.warning("no results/accounts.json; attestation needs per-app test accounts")
    rows = db.apps_needing(Stage.ATTESTATION_DONE)
    if limit:
        rows = rows[:limit]
    tally: dict[str, int] = {}
    for row in rows:
        try:
            v = process_app(db, row, accounts)
            if v is not EnforcementVerdict.INCONCLUSIVE:
                db.set_stage(row["app_id"], Stage.ATTESTATION_DONE)
            tally[v.value] = tally.get(v.value, 0) + 1
        except Exception as e:
            log.exception("attestation %s failed: %s", row["app_id"], e)
    log.info("attestation tally: %s", tally)
    return tally
