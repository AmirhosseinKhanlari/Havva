"""Stage H: attestation-enforcement differential test (the headline).

For apps that use App Attest / DeviceCheck, we test whether the backend actually
enforces it. On a real logged-in session with pinning bypassed so we can see the
traffic:

  baseline  : attestation intact, reach the gated action -> confirm gated data flows
  neutralized: attestation hooked off (scripts/attest_neutralize.js), same action

If gated data still flows with attestation neutralized -> FAIL_OPEN (adopted but
not enforced, theater). If the backend now refuses -> FAIL_CLOSED (real defense).
Enforcement is a backend property, so this is valid on the non-JB device.

Runs only on the authenticated sample: apps with a test account in the accounts
store (results/accounts.json: {app_id or bundle_id: {username, password}}).
"""

from __future__ import annotations

import json
from pathlib import Path

from . import capture, device, instrument
from .config import CONFIG
from .db import Database
from .models import BackendBehavior, BypassStage, Stage, WorkState
from .util import get_logger, run_cmd

log = get_logger("attestation", CONFIG.paths.log_dir)

ATTEST_SCRIPT = CONFIG.paths.root / "scripts" / "attest_neutralize.js"


def load_accounts() -> dict[str, dict[str, str]]:
    path = CONFIG.paths.results_dir / "accounts.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def _creds_for(row, accounts: dict) -> dict[str, str] | None:
    return accounts.get(row["app_id"]) or accounts.get(row["bundle_id"] or "")


def _backend_served_data(flows: list) -> bool:
    """Heuristic: a successful (2xx) response from a non-excluded host with a
    non-trivial body = gated data was served."""
    for f in flows:
        if 200 <= f.status < 300 and f.host and not capture.is_excluded(f.host):
            if len(f.response_body or "") > 64:
                return True
    return False


def _run_once(app_id: str, bundle_id: str, decrypted: str, creds: dict,
              neutralize: bool) -> list:
    """One logged-in run with pinning bypassed; optionally neutralize attestation.
    Returns captured flows."""
    # Use the Frida-gadget config so we can both bypass pinning and load the
    # neutralization script over USB.
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
    # Launch + login first.
    dr = driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=True)

    if neutralize and dr.launched:
        # Load the neutralization script into the running gadget, then re-exercise.
        run_cmd(["frida", "-U", "-n", "Gadget", "-l", str(ATTEST_SCRIPT),
                 "--runtime=v8", "-q"], timeout=30)
        driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=False)

    har_path = CONFIG.paths.results_dir / f"{app_id}_attest_{'neu' if neutralize else 'base'}.har"
    capture.export_har(har_path)
    flows = capture.har_to_flows(capture.load_har(har_path), CONFIG.test_device.client_ip)
    device.uninstall(bundle_id)
    return flows


def process_app(db: Database, row, accounts: dict) -> BackendBehavior:
    app_id = row["app_id"]
    bundle_id = row["bundle_id"]
    creds = _creds_for(row, accounts)
    with db.connect() as c:
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    decrypted = ac["ipa_path"] if ac else ""

    if not creds or not decrypted:
        db.save_attestation(app_id, tested=False, neutralized=False,
                            behavior=BackendBehavior.INCONCLUSIVE,
                            state=WorkState.UNTESTED, error="no account or ipa")
        return BackendBehavior.INCONCLUSIVE

    base_flows = _run_once(app_id, bundle_id, decrypted, creds, neutralize=False)
    if not _backend_served_data(base_flows):
        # Never reached the gated data even with attestation intact: cannot judge.
        db.save_attestation(app_id, tested=True, neutralized=False,
                            behavior=BackendBehavior.INCONCLUSIVE,
                            state=WorkState.UNTESTED, error="gated data not reached")
        return BackendBehavior.INCONCLUSIVE

    neu_flows = _run_once(app_id, bundle_id, decrypted, creds, neutralize=True)
    served = _backend_served_data(neu_flows)
    behavior = BackendBehavior.FAIL_OPEN if served else BackendBehavior.FAIL_CLOSED
    db.save_attestation(app_id, tested=True, neutralized=True, behavior=behavior,
                        state=WorkState.POSITIVE)
    log.info("%s attestation -> %s", app_id, behavior.value)
    return behavior


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    missing = CONFIG.missing_for_dynamic()
    if missing:
        log.error("cannot run attestation stage; missing: %s", "; ".join(missing))
        return {}
    accounts = load_accounts()
    if not accounts:
        log.warning("no accounts.json; attestation test needs per-app test accounts")
    rows = db.apps_needing(Stage.ATTESTATION_DONE)
    if limit:
        rows = rows[:limit]
    tally: dict[str, int] = {}
    for row in rows:
        try:
            b = process_app(db, row, accounts)
            if b in (BackendBehavior.FAIL_OPEN, BackendBehavior.FAIL_CLOSED):
                db.set_stage(row["app_id"], Stage.ATTESTATION_DONE)
            tally[b.value] = tally.get(b.value, 0) + 1
        except Exception as e:
            log.exception("attestation %s failed: %s", row["app_id"], e)
    log.info("attestation tally: %s", tally)
    return tally
