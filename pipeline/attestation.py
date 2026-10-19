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
PROBES: list[tuple[str, Path | None]] = [
    ("baseline", None),
    ("omit", SCRIPTS / "attest_omit.js"),
    ("tamper", SCRIPTS / "attest_tamper.js"),
    ("noreg", SCRIPTS / "attest_noreg.js"),
    ("downgrade", SCRIPTS / "attest_downgrade.js"),
]

# Request headers that plausibly carry an attestation assertion/token.
# Attestation-specific wording, matched in request HEADERS and BODY (NOT a generic
# x-.*token, which matches auth/session/CSRF tokens). See attest_detect for rationale.
_ASSERT_HEADER_RE = re.compile(
    r"attest|(?<!client_)assert|integrity|device[-_]?check|app[-_]?check|approov|"
    r"client[-_]?data[-_]?hash",
    re.IGNORECASE)


def _req_carries_assertion(f) -> bool:
    """True if the request headers (names OR values) or body carry attestation
    wording. `request_headers` is a dict of lowercased names -> values."""
    hdrs = f.request_headers or {}
    items = hdrs.items() if isinstance(hdrs, dict) else [(h, "") for h in hdrs]
    for name, val in items:
        if _ASSERT_HEADER_RE.search(str(name)) or _ASSERT_HEADER_RE.search(str(val)[:512]):
            return True
    body = f.request_body or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return bool(body and _ASSERT_HEADER_RE.search(body[:4000]))


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
_PROBE_EXPECTS_ASSERTION = {"tamper": True, "omit": False, "noreg": False, "downgrade": False}


def _probe_outcome(name: str, gated: set[str], probe_flows: list,
                   armed: bool, hit: bool) -> tuple[bool | None, str]:
    """Tri-state result for one probe: True = gated data served under the probe
    (weakness), False = refused (enforced for this probe), None = inconclusive.
    Returns (outcome, reason)."""
    if not gated:
        return None, "no attested gated endpoint in baseline"
    if not armed:
        return None, "probe script did not arm"
    if not hit:
        return None, "probe hook never fired (assertion cached / path not exercised)"
    expects = _PROBE_EXPECTS_ASSERTION.get(name, False)
    requested = served = False
    for f in probe_flows:
        if _endpoint_key(f) not in gated:
            continue
        if _req_carries_assertion(f) != expects:
            continue  # cached/legit assertion state: not evidence either way
        requested = True
        if _is_data_2xx(f):
            served = True
    if not requested:
        return None, "gated endpoint not re-exercised under the probe"
    return served, ("served under probe" if served else "refused under probe")


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


def _arm_probe(script: Path, settle: float = 6.0):
    """Attach frida to the running gadget and load `script` PERSISTENTLY (no -q,
    which would detach and unload the hooks). Returns (proc, lines) where `lines`
    is a live list of the script's console output; `_disarm` stops it."""
    import subprocess
    import threading
    import time as _t
    lines: list[str] = []
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
    """One probe run. Returns {flows, armed, hit, launched, error}.

    baseline (script=None): intact login drive; flows = whole session.
    probe: intact login drive (reach the logged-in state), then the session is
    CLEARED, the probe is armed persistently, and the already-running app is
    re-exercised WITHOUT relaunch (so the Frida attach survives). flows = probe
    phase only, so the intact phase can never masquerade as 'served under probe'.
    """
    out = {"flows": [], "armed": False, "hit": False, "launched": False, "error": ""}
    ok, signed, err = instrument.build(app_id, decrypted, BypassStage.FRIDA.value)
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
    driver = device.AppiumDriver(credentials=creds)
    dr = driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=True)
    out["launched"] = bool(dr.launched)
    tag = script.stem if script else "baseline"

    if script is None:
        out["flows"] = _export_flows(app_id, tag)
        device.uninstall(bundle_id)
        return out

    if not dr.launched or not script.exists():
        out["error"] = "app did not launch" if not dr.launched else "probe script missing"
        device.uninstall(bundle_id)
        return out

    # Probe phase: fresh session, persistent hook, no relaunch.
    capture.clear_session()
    proc, lines = _arm_probe(script)
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


def _grade(served: dict[str, bool | None], coverage: tuple[int, int]) -> EnforcementVerdict:
    """Grade from tri-state probe results (True=served/weak, False=refused,
    None=inconclusive). A verdict of ENFORCED requires the two strongest probes
    (tamper, omit) to be DEFINITE refusals; inconclusive probes never count as
    evidence of enforcement."""
    if not served.get("baseline"):
        return EnforcementVerdict.INCONCLUSIVE
    # Strongest evidence first: a garbage assertion accepted = no verification.
    if served.get("tamper") is True:
        return EnforcementVerdict.SIGNATURE_NOT_VERIFIED
    if served.get("omit") is True:
        return EnforcementVerdict.NOT_REQUIRED
    if served.get("noreg") is True:
        return EnforcementVerdict.NOT_REGISTERED_OK
    if served.get("downgrade") is True:
        return EnforcementVerdict.DOWNGRADEABLE
    if any(v is True for k, v in served.items() if k != "baseline"):
        return EnforcementVerdict.WEAK_OTHER
    if served.get("tamper") is not False or served.get("omit") is not False:
        return EnforcementVerdict.INCONCLUSIVE  # could not establish a definite refusal
    # All definite tamper probes refused. Check coverage: are all gated endpoints attested?
    gated, attested = coverage
    if gated > 0 and 0 < attested < gated:
        return EnforcementVerdict.PARTIAL_COVERAGE
    return EnforcementVerdict.ENFORCED


def _to_behavior(v: EnforcementVerdict) -> BackendBehavior:
    if v is EnforcementVerdict.ENFORCED:
        return BackendBehavior.FAIL_CLOSED
    if v is EnforcementVerdict.INCONCLUSIVE:
        return BackendBehavior.INCONCLUSIVE
    return BackendBehavior.FAIL_OPEN  # any weakness = effectively fails open


def process_app(db: Database, row, accounts: dict) -> EnforcementVerdict:
    app_id, bundle_id = row["app_id"], row["bundle_id"]
    creds = _creds_for(row, accounts)
    with db.connect() as c:
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    decrypted = ac["ipa_path"] if ac else ""

    if not creds or not decrypted:
        _save(db, app_id, EnforcementVerdict.INCONCLUSIVE, {}, (0, 0),
              WorkState.UNTESTED, "no account or ipa")
        return EnforcementVerdict.INCONCLUSIVE

    served: dict[str, bool | None] = {}
    reasons: dict[str, str] = {}
    # Baseline first: it defines the oracle (the attested gated endpoints).
    base = _run_probe(app_id, bundle_id, decrypted, creds, None)
    gated = _gated_endpoints(base["flows"])
    served["baseline"] = bool(gated)
    reasons["baseline"] = (f"{len(gated)} attested gated endpoint(s)" if gated else
                           (base["error"] or "no attested 2xx endpoint observed"))
    if not gated:
        _save(db, app_id, EnforcementVerdict.INCONCLUSIVE, served, (0, 0),
              WorkState.UNTESTED, "gated data not reached", reasons)
        return EnforcementVerdict.INCONCLUSIVE

    for name, script in PROBES:
        if script is None:
            continue
        res = _run_probe(app_id, bundle_id, decrypted, creds, script, gated)
        outcome, why = _probe_outcome(name, gated, res["flows"], res["armed"], res["hit"])
        served[name] = outcome
        reasons[name] = why if not res["error"] else f"{why}; {res['error']}"
        log.info("%s probe %s -> %s (%s)", app_id, name, outcome, reasons[name])

    coverage = _coverage(base["flows"])
    verdict = _grade(served, coverage)
    state = WorkState.POSITIVE if verdict is not EnforcementVerdict.INCONCLUSIVE else WorkState.UNTESTED
    _save(db, app_id, verdict, served, coverage, state, "", reasons)
    log.info("%s attestation -> %s  (served=%s coverage=%s)", app_id, verdict.value,
             served, coverage)
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
    payload = {"served": served, "reasons": reasons or {}}
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
