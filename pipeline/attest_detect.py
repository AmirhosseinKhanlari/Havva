"""Dynamic App Attest usage detection via library injection (no jailbreak, no Frida).

Injects AttestObserver.dylib (ObjC swizzling) into the re-signed app; the dylib
logs a staged marker trail (OBSERVER_LOADED -> CLASS_PRESENT/ABSENT ->
HOOK_VERIFIED -> CALL) to the device syslog, which we read over USB with
idevicesyslog. The trail distinguishes tooling failure from a real negative.

Confidence ladder (static + dynamic; dynamic never downgrades a static signal):
  entitlement -> CAPABLE ; symbols -> LIKELY ; runtime CALL -> CONFIRMED_ACTIVE ;
  CALL + attested endpoint located -> CONFIRMED_LOCATED.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import capture, device, instrument
from .config import CONFIG
from .db import Database
from .models import AttestConfidence, Stage
from .util import get_logger

log = get_logger("attest_detect", CONFIG.paths.log_dir)

_ASSERT_HEADER_RE = re.compile(r"assert|attest|integrity|device-?check|app-?check|x-.*token",
                               re.IGNORECASE)
_CALL_RE = re.compile(r"CALL (\S+) (\S+)")
_VERIFIED_RE = re.compile(r"HOOK_VERIFIED (\S+)")
_FAILED_RE = re.compile(r"HOOK_FAILED (\S+)")


@dataclass
class Trail:
    """Parsed AttestObserver marker trail from the device syslog."""
    loaded: bool = False
    class_present: bool = False
    class_absent: bool = False
    verified: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    @property
    def tooling_ok(self) -> bool:
        # The detector worked if it loaded and either armed a hook or proved the
        # class is absent (a real, confident negative).
        return self.loaded and (bool(self.verified) or self.class_absent)


def parse_trail(syslog_text: str) -> Trail:
    t = Trail()
    txt = syslog_text or ""
    t.loaded = "OBSERVER_LOADED" in txt
    t.class_present = "CLASS_PRESENT" in txt
    t.class_absent = "CLASS_ABSENT" in txt
    t.verified = sorted(set(_VERIFIED_RE.findall(txt)))
    t.failed = sorted(set(_FAILED_RE.findall(txt)))
    t.calls = sorted({f"{c} {s}" for c, s in _CALL_RE.findall(txt)})
    return t


def classify_confidence(entitlement: bool, symbols: bool,
                        methods_seen: list[str], endpoint_found: bool) -> AttestConfidence:
    """Pure confidence ladder. A dynamic observation only raises confidence."""
    if methods_seen and endpoint_found:
        return AttestConfidence.CONFIRMED_LOCATED
    if methods_seen:
        return AttestConfidence.CONFIRMED_ACTIVE
    if symbols:
        return AttestConfidence.LIKELY
    if entitlement:
        return AttestConfidence.CAPABLE
    return AttestConfidence.NONE


def _endpoint_found(flows: list) -> str:
    for f in flows:
        if f.host and not capture.is_excluded(f.host):
            if any(_ASSERT_HEADER_RE.search(h) for h in f.request_headers):
                return f.host
    return ""


def observe(app_id: str, bundle_id: str, decrypted: str,
            creds: dict | None) -> tuple[Trail, str]:
    """Inject the observer, run the app while streaming syslog, parse the trail."""
    ok, signed, err = instrument.build(app_id, decrypted, "attest_observe")
    if not ok:
        log.warning("%s observe build failed: %s", app_id, err)
        return Trail(), ""
    installed, ierr = device.install_ipa(signed)
    if not installed:
        log.warning("%s observe install failed: %s", app_id, ierr)
        return Trail(), ""

    capture.check_connection()
    capture.clear_session()

    driver = device.AppiumDriver(credentials=creds or {})

    def during():
        driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=bool(creds))

    syslog = device.capture_syslog(during=during, grep="OBSERVER")

    har = CONFIG.paths.results_dir / f"{app_id}_attest_observe.har"
    capture.export_har(har)
    flows = capture.har_to_flows(capture.load_har(har), CONFIG.test_device.client_ip)
    device.uninstall(bundle_id)

    return parse_trail(syslog), _endpoint_found(flows)


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

    trail, endpoint = (Trail(), "")
    if decrypted:
        trail, endpoint = observe(app_id, bundle_id, decrypted,
                                  accounts.get(app_id) or accounts.get(bundle_id or ""))

    conf = classify_confidence(entitlement, symbols, trail.calls, bool(endpoint))
    _save(db, app_id, conf, trail, endpoint)
    status = "ok" if trail.tooling_ok else "TOOLING-UNCONFIRMED"
    log.info("%s attest usage -> %s [%s] calls=%s endpoint=%s",
             app_id, conf.value, status, trail.calls, endpoint or "-")
    return conf


def _save(db: Database, app_id: str, conf: AttestConfidence, trail: Trail, endpoint: str) -> None:
    for col in ("attest_confidence TEXT", "attest_methods_seen TEXT",
                "attested_endpoint TEXT", "attest_tooling_ok INTEGER DEFAULT 0",
                "attest_trail TEXT"):
        name, decl = col.split(" ", 1)
        db.add_column_if_missing("static_profile", name, decl)
    trail_json = json.dumps({"loaded": trail.loaded, "class_present": trail.class_present,
                             "class_absent": trail.class_absent, "verified": trail.verified,
                             "failed": trail.failed, "calls": trail.calls})
    with db.connect() as c:
        c.execute("UPDATE static_profile SET attest_confidence=?, attest_methods_seen=?, "
                  "attested_endpoint=?, attest_tooling_ok=?, attest_trail=? WHERE app_id=?",
                  (conf.value, json.dumps(trail.calls), endpoint,
                   int(trail.tooling_ok), trail_json, app_id))


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    if CONFIG.missing_for_dynamic():
        log.error("cannot run attest-detect; missing: %s",
                  "; ".join(CONFIG.missing_for_dynamic()))
        return {}
    from .attestation import load_accounts
    accounts = load_accounts()
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
