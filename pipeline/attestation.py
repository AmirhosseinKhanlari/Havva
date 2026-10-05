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

On-device caveats (validate when running): the probe Frida script must load
before the gated action fires; the backend may remember a key registered by an
earlier run on the same account (affects `noreg`); replay is not automated here.
These are noted, not hidden.
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
    r"attest|assert|integrity|device[-_]?check|app[-_]?check|approov|client[-_]?data[-_]?hash",
    re.IGNORECASE)


def _req_carries_assertion(f) -> bool:
    """True if the request headers or body carry attestation wording."""
    if any(_ASSERT_HEADER_RE.search(h) for h in (f.request_headers or [])):
        return True
    body = f.request_body or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return bool(body and _ASSERT_HEADER_RE.search(body[:4000]))


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


def _run_probe(app_id: str, bundle_id: str, decrypted: str, creds: dict,
               script: Path | None) -> list:
    """One logged-in run under the Frida-gadget config, optionally loading a probe
    script, then capture. Returns flows."""
    ok, signed, err = instrument.build(app_id, decrypted, BypassStage.FRIDA.value)
    if not ok:
        log.warning("%s attest build failed: %s", app_id, err)
        return []
    installed, ierr = device.install_ipa(signed)
    if not installed:
        log.warning("%s attest install failed: %s", app_id, ierr)
        return []

    capture.check_connection()
    capture.clear_session()

    driver = device.AppiumDriver(credentials=creds)
    dr = driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=True)
    if script and script.exists() and dr.launched:
        # Load the probe into the running gadget, then re-exercise so the gated
        # request fires with the probe active.
        run_cmd(["frida", "-U", "-n", "Gadget", "-l", str(script), "-q"], timeout=30)
        driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=False)

    tag = script.stem if script else "baseline"
    har = CONFIG.paths.results_dir / f"{app_id}_attest_{tag}.har"
    capture.export_har(har)
    flows = capture.har_to_flows(capture.load_har(har), CONFIG.test_device.client_ip)
    device.uninstall(bundle_id)
    return flows


def _grade(served: dict[str, bool], coverage: tuple[int, int]) -> EnforcementVerdict:
    if not served.get("baseline"):
        return EnforcementVerdict.INCONCLUSIVE
    # Strongest evidence first: a garbage assertion accepted = no verification.
    if served.get("tamper"):
        return EnforcementVerdict.SIGNATURE_NOT_VERIFIED
    if served.get("omit"):
        return EnforcementVerdict.NOT_REQUIRED
    if served.get("noreg"):
        return EnforcementVerdict.NOT_REGISTERED_OK
    if served.get("downgrade"):
        return EnforcementVerdict.DOWNGRADEABLE
    if any(v for k, v in served.items() if k != "baseline"):
        return EnforcementVerdict.WEAK_OTHER
    # All tamper probes refused. Check coverage: are all gated endpoints attested?
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

    served: dict[str, bool] = {}
    baseline_flows: list = []
    for name, script in PROBES:
        flows = _run_probe(app_id, bundle_id, decrypted, creds, script)
        served[name] = _served_gated_data(flows)
        if name == "baseline":
            baseline_flows = flows
            if not served["baseline"]:
                _save(db, app_id, EnforcementVerdict.INCONCLUSIVE, served, (0, 0),
                      WorkState.UNTESTED, "gated data not reached")
                return EnforcementVerdict.INCONCLUSIVE

    coverage = _coverage(baseline_flows)
    verdict = _grade(served, coverage)
    _save(db, app_id, verdict, served, coverage, WorkState.POSITIVE)
    log.info("%s attestation -> %s  (served=%s coverage=%s)", app_id, verdict.value,
             served, coverage)
    return verdict


def _save(db: Database, app_id: str, verdict: EnforcementVerdict, served: dict,
          coverage: tuple[int, int], state: WorkState, error: str = "") -> None:
    db.add_column_if_missing("attestation", "verdict", "TEXT")
    db.add_column_if_missing("attestation", "probe_results", "TEXT")
    db.add_column_if_missing("attestation", "coverage_gated", "INTEGER DEFAULT 0")
    db.add_column_if_missing("attestation", "coverage_attested", "INTEGER DEFAULT 0")
    behavior = _to_behavior(verdict)
    db.save_attestation(app_id, tested=(verdict is not EnforcementVerdict.INCONCLUSIVE),
                        neutralized=bool(served), behavior=behavior, state=state, error=error)
    with db.connect() as c:
        c.execute("UPDATE attestation SET verdict=?, probe_results=?, coverage_gated=?, "
                  "coverage_attested=? WHERE app_id=?",
                  (verdict.value, json.dumps(served), coverage[0], coverage[1], app_id))


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
