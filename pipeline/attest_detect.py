"""Dynamic App Attest usage detection.

Confirms whether an app actually *invokes* App Attest at runtime (the strongest
usage signal, stronger than a static symbol), and identifies the endpoint that
carries the attestation object. Produces a confidence level combining static and
dynamic signals:

  entitlement present            -> CAPABLE          (weak)
  symbols/framework linked       -> LIKELY           (medium)
  runtime API call observed      -> CONFIRMED_ACTIVE (high)
  observed + endpoint located    -> CONFIRMED_LOCATED (highest)

Read-only probe (scripts/attest_observe.js logs, changes nothing). Runs under the
Frida-gadget config. Negative results are coverage-bounded (not observing a call
does not prove non-use), so we never downgrade a static signal on a miss.
"""

from __future__ import annotations

import json
import re

from . import capture, device, instrument
from .config import CONFIG
from .db import Database
from .models import AttestConfidence, BypassStage, Stage
from .util import get_logger, run_cmd

log = get_logger("attest_detect", CONFIG.paths.log_dir)

OBSERVE_SCRIPT = CONFIG.paths.root / "scripts" / "attest_observe.js"
_ASSERT_HEADER_RE = re.compile(r"assert|attest|integrity|device-?check|app-?check|x-.*token",
                               re.IGNORECASE)
_CALL_RE = re.compile(r"ATTEST_OBSERVE CALL (\S+) (\S+)")


def classify_confidence(entitlement: bool, symbols: bool,
                        methods_seen: list[str], endpoint_found: bool) -> AttestConfidence:
    """Pure confidence ladder. A dynamic observation never lowers a static signal;
    it only raises confidence."""
    if methods_seen and endpoint_found:
        return AttestConfidence.CONFIRMED_LOCATED
    if methods_seen:
        return AttestConfidence.CONFIRMED_ACTIVE
    if symbols:
        return AttestConfidence.LIKELY
    if entitlement:
        return AttestConfidence.CAPABLE
    return AttestConfidence.NONE


def _methods_from_output(frida_output: str) -> list[str]:
    return sorted({f"{c} {s}" for c, s in _CALL_RE.findall(frida_output or "")})


def _endpoint_found(flows: list) -> str:
    """Return the first non-excluded host whose request carries an assertion-like
    header (the attested endpoint), else empty."""
    for f in flows:
        if f.host and not capture.is_excluded(f.host):
            if any(_ASSERT_HEADER_RE.search(h) for h in f.request_headers):
                return f.host
    return ""


def observe(app_id: str, bundle_id: str, decrypted: str,
            creds: dict | None) -> tuple[list[str], str]:
    """Run the app with the observe probe; return (methods_seen, attested_endpoint)."""
    ok, signed, err = instrument.build(app_id, decrypted, BypassStage.FRIDA.value)
    if not ok:
        log.warning("%s observe build failed: %s", app_id, err)
        return [], ""
    installed, ierr = device.install_ipa(signed)
    if not installed:
        log.warning("%s observe install failed: %s", app_id, ierr)
        return [], ""

    capture.check_connection()
    capture.clear_session()

    driver = device.AppiumDriver(credentials=creds or {})
    driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=bool(creds))
    # Load the observe script into the running gadget and capture its stdout.
    proc = run_cmd(["frida", "-U", "-n", "Gadget", "-l", str(OBSERVE_SCRIPT), "-q"], timeout=40)
    # Exercise again so attestation-bearing requests fire while hooked.
    driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=False)

    har = CONFIG.paths.results_dir / f"{app_id}_attest_observe.har"
    capture.export_har(har)
    flows = capture.har_to_flows(capture.load_har(har), CONFIG.test_device.client_ip)
    device.uninstall(bundle_id)

    methods = _methods_from_output(proc.stdout + "\n" + proc.stderr)
    endpoint = _endpoint_found(flows)
    return methods, endpoint


def process_app(db: Database, row, accounts: dict) -> AttestConfidence:
    app_id, bundle_id = row["app_id"], row["bundle_id"]
    with db.connect() as c:
        st = c.execute("SELECT appattest_flag, matched_patterns FROM static_profile "
                       "WHERE app_id=?", (app_id,)).fetchone()
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    symbols = bool(st and st["appattest_flag"])
    entitlement = False
    if st and st["matched_patterns"]:
        try:
            entitlement = "appattest" in json.loads(st["matched_patterns"])
        except (ValueError, TypeError):
            entitlement = False
    decrypted = ac["ipa_path"] if ac else ""

    methods, endpoint = ([], "")
    if decrypted:
        methods, endpoint = observe(app_id, bundle_id, decrypted,
                                    accounts.get(app_id) or accounts.get(bundle_id or ""))

    conf = classify_confidence(entitlement, symbols, methods, bool(endpoint))
    _save(db, app_id, conf, methods, endpoint)
    log.info("%s attest usage -> %s (methods=%s endpoint=%s)", app_id, conf.value,
             methods, endpoint or "-")
    return conf


def _save(db: Database, app_id: str, conf: AttestConfidence,
          methods: list[str], endpoint: str) -> None:
    db.add_column_if_missing("static_profile", "attest_confidence", "TEXT")
    db.add_column_if_missing("static_profile", "attest_methods_seen", "TEXT")
    db.add_column_if_missing("static_profile", "attested_endpoint", "TEXT")
    with db.connect() as c:
        c.execute("UPDATE static_profile SET attest_confidence=?, attest_methods_seen=?, "
                  "attested_endpoint=? WHERE app_id=?",
                  (conf.value, json.dumps(methods), endpoint, app_id))


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    if CONFIG.missing_for_dynamic():
        log.error("cannot run attest-detect; missing: %s",
                  "; ".join(CONFIG.missing_for_dynamic()))
        return {}
    from .attestation import load_accounts
    accounts = load_accounts()
    # Candidates: apps with any static attestation signal (confirm + locate them).
    with db.connect() as c:
        rows = c.execute("SELECT a.* FROM apps a JOIN static_profile s ON s.app_id=a.app_id "
                         "WHERE s.appattest_flag=1").fetchall()
    if limit:
        rows = rows[:limit]
    tally: dict[str, int] = {}
    for row in rows:
        try:
            conf = process_app(db, row, accounts)
            tally[conf.value] = tally.get(conf.value, 0) + 1
        except Exception as e:
            log.exception("attest-detect %s failed: %s", row["app_id"], e)
    log.info("attest-detect tally: %s", tally)
    return tally
