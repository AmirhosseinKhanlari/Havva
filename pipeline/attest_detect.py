"""Dynamic App Attest usage detection via library injection (no jailbreak, no Frida).

Injects AttestObserver.dylib (ObjC swizzling) into the re-signed app; the dylib
logs a staged marker trail (OBSERVER_LOADED -> CLASS_PRESENT/ABSENT ->
HOOK_VERIFIED -> CALL) to the device syslog, which we read over USB with
idevicesyslog. The trail distinguishes tooling failure from a real negative.

Confidence ladder (static + dynamic; dynamic never downgrades a static signal):
  entitlement -> CAPABLE ; symbols -> LIKELY ; runtime CALL -> CONFIRMED_ACTIVE ;
  CALL + attested endpoint located -> CONFIRMED_LOCATED.

The ladder is an APP ATTEST ladder: only DCAppAttestService calls feed it.
DeviceCheck (DCDevice generateToken) is observed by the same dylib but is a
different mechanism; it is persisted separately inside the trail JSON
(`devicecheck_status`) and never produces an App Attest CONFIRMED_* verdict.

CAPABLE is reachable once static_classify reports the entitlement separately
from the API symbols (`matched_patterns["appattest_entitlement"]` /
`["appattest_symbols"]`): an app provisioned for App Attest whose binary carries
no DCAppAttestService symbol lands there. With the legacy single "appattest" key
the entitlement is recovered from the entry that names the entitlement itself.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import capture, device, instrument
from .config import CONFIG
from .db import Database
from .models import AttestConfidence, Stage
from .util import get_logger

log = get_logger("attest_detect", CONFIG.paths.log_dir)

# Attestation-specific wording, matched in request HEADER NAMES, HEADER VALUES
# and the BODY. Deliberately NOT a generic `x-.*token` (that matches auth/session/
# CSRF tokens). Catches X-Attestation/X-App-Attest/attestationObject (attest),
# X-Assertion/assertion (assert), X-Firebase-AppCheck/appCheckToken (app-check),
# X-Integrity-Token (integrity), DeviceCheck, clientDataHash, Approov.
#
# `assert` is guarded by negative lookbehinds so the OAuth 2 JWT client
# authentication fields (`client_assertion`, `client_assertion_type`,
# `client-assertion-type:jwt-bearer`, `clientAssertion`) do not count as an
# attestation signal: they are a plain OAuth credential, present in countless
# token-endpoint bodies, and were the main source of false "attested endpoint"
# hits.
_ASSERT_HEADER_RE = re.compile(
    r"attest|(?<!client)(?<!client[-_])assert|integrity|device[-_]?check|app[-_]?check"
    r"|approov|client[-_]?data[-_]?hash",
    re.IGNORECASE)

# Entitlement key as static_classify records it inside matched_patterns entries.
_ENT_APPATTEST = "com.apple.developer.devicecheck.appattest-environment"


def _flow_attest_hits(f) -> list[str]:
    """Where an attestation signal matched on a flow: header name(s) and/or
    'body', plus a 'cbor-assertion' / 'cbor-attestation' token when the CONTENT
    fingerprint matched (independent of what the header is called). Shared
    with the enforcement stage (attestation.assertion_evidence) so both stages
    agree on what an attested request is."""
    from .attestation import assertion_evidence
    headers = f.request_headers
    if headers and not isinstance(headers, dict):   # defensive: list of "name: value"
        f.request_headers = {h.split(":", 1)[0].strip().lower(): (h.split(":", 1)[1] if ":" in h else "")
                             for h in headers}
    return assertion_evidence(f)


# ---- hook <-> request timing correlation --------------------------------------
# The observer logs every App Attest call with the syslog timestamp; the HAR
# carries each request's startedDateTime. A data request that leaves within a
# few seconds AFTER generateAssertion / attestKey is the one carrying the
# result, whatever the header is called. Second-granularity on the syslog side,
# so the window is generous and the hit is labelled 'timing' (corroborating).
_SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)")
_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
                                       "Sep", "Oct", "Nov", "Dec"), 1)}
_TIMING_WINDOW = 5.0


def _call_times(syslog_text: str, year: int | None = None) -> list[datetime]:
    """Local naive timestamps of the App Attest / DeviceCheck CALL lines."""
    out: list[datetime] = []
    year = year or datetime.now().year
    for line in (syslog_text or "").splitlines():
        if "CALL DCAppAttestService" not in line and "CALL DCDevice" not in line:
            continue
        if "isSupported" in line:
            continue
        m = _SYSLOG_TS_RE.match(line)
        if not m:
            continue
        try:
            out.append(datetime(year, _MONTHS[m.group(1)], int(m.group(2)),
                                int(m.group(3)), int(m.group(4)), int(m.group(5))))
        except (KeyError, ValueError):
            continue
    return out


def _flow_time(f) -> datetime | None:
    s = getattr(f, "started", "") or ""
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def _timing_hits(flows: list, calls: list[datetime], window: float = _TIMING_WINDOW) -> dict[int, float]:
    """{flow index: seconds after the nearest preceding call} for non-excluded
    requests that start within `window` seconds after a hook firing."""
    hits: dict[int, float] = {}
    if not calls:
        return hits
    for i, f in enumerate(flows):
        if not f.host or capture.is_excluded(f.host):
            continue
        t = _flow_time(f)
        if t is None:
            continue
        best = None
        for c in calls:
            d = (t - c).total_seconds()
            if -1.0 <= d <= window and (best is None or d < best):
                best = d
        if best is not None:
            hits[i] = max(best, 0.0)
    return hits


_CALL_RE = re.compile(r"CALL (\S+) (\S+)")
_SUPPORTED_RE = re.compile(r"CALL DCAppAttestService isSupported=(\d)")
_VERIFIED_RE = re.compile(r"HOOK_VERIFIED (\S+)")
_FAILED_RE = re.compile(r"HOOK_FAILED (\S+)")
_PRESENT_RE = re.compile(r"CLASS_PRESENT (\S+)")

_AA_CLASS = "DCAppAttestService"
_DC_CLASS = "DCDevice"
_AA_SELECTOR_HINTS = ("attestKey", "generateAssertion", "generateKeyWith")
_DC_SELECTOR_HINTS = ("generateToken",)


@dataclass
class Trail:
    """Parsed AttestObserver marker trail from the device syslog."""
    loaded: bool = False
    class_present: bool = False
    class_absent: bool = False
    present: list[str] = field(default_factory=list)   # classes reported CLASS_PRESENT
    verified: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)     # "Class selector" (App Attest AND DeviceCheck)
    launches: int = 0            # how many times the observer loaded (new PID = relaunch)
    supported: bool | None = None  # what isSupported returned (None = never queried)
    crash_report: str = ""       # crash report matching the app, if any
    launch_failed: bool = False  # device.launch() returned no pid (denied/failed; NOT a crash)

    @property
    def hooks_armed(self) -> bool:
        # The detector itself worked: it loaded and either armed a hook or proved
        # the class is absent.
        return self.loaded and (bool(self.verified) or self.class_absent)

    @property
    def tooling_ok(self) -> bool:
        """Is the verdict reliable? True only when the hooks were armed AND the
        result is not explained by the app never running to the point where
        attestation would have happened:
          - launch failed/denied   -> nothing was observed, negative is void
          - crashed with no CALL   -> "present but not called" is unreliable
            (the app may attest later than it died, or refuses to run re-signed)
        A CALL observed before a crash is still a reliable positive."""
        if not self.hooks_armed or self.launch_failed:
            return False
        if self.crashed and not self.calls:
            return False
        return True

    @property
    def crashed(self) -> bool:
        # Authoritative signal: a crash report for this app was captured during the
        # run (device crash reports are flushed before launch, so it's this run's).
        # NOTE: launch count is NOT used -- in manual mode the human may relaunch.
        return bool(self.crash_report)

    @property
    def appattest_calls(self) -> list[str]:
        return [c for c in self.calls if _AA_CLASS in c]

    @property
    def devicecheck_calls(self) -> list[str]:
        return [c for c in self.calls if _DC_CLASS in c]


def parse_trail(syslog_text: str) -> Trail:
    t = Trail()
    txt = syslog_text or ""
    t.loaded = "OBSERVER_LOADED" in txt
    t.launches = txt.count("OBSERVER_LOADED")
    t.class_present = "CLASS_PRESENT" in txt
    t.class_absent = "CLASS_ABSENT" in txt
    t.present = sorted(set(_PRESENT_RE.findall(txt)))
    t.verified = sorted(set(_VERIFIED_RE.findall(txt)))
    t.failed = sorted(set(_FAILED_RE.findall(txt)))
    # isSupported is a capability query every SDK makes at init: logged for
    # the downgrade analysis, never counted as USAGE.
    t.calls = sorted({f"{c} {s}" for c, s in _CALL_RE.findall(txt)
                      if not s.startswith("isSupported")})
    sup = _SUPPORTED_RE.findall(txt)
    if sup:
        t.supported = sup[-1] == "1"
    return t


def appattest_status(trail: Trail) -> dict:
    """App Attest (DCAppAttestService) observation, independent of DeviceCheck."""
    calls = trail.appattest_calls
    present = bool(calls) or _AA_CLASS in trail.present or any(
        h in v for v in trail.verified for h in _AA_SELECTOR_HINTS)
    return {"present": present, "called": bool(calls), "calls": calls}


def devicecheck_status(trail: Trail) -> dict:
    """DeviceCheck (DCDevice generateToken) observation. Kept OUT of the App
    Attest confidence ladder; persisted inside the trail JSON so no schema
    change is needed."""
    calls = trail.devicecheck_calls
    present = bool(calls) or _DC_CLASS in trail.present or any(
        h in v for v in trail.verified for h in _DC_SELECTOR_HINTS)
    return {"present": present, "called": bool(calls), "calls": calls}


def classify_confidence(entitlement: bool, symbols: bool,
                        methods_seen: list[str], endpoint_found: bool) -> AttestConfidence:
    """Pure App Attest confidence ladder. A dynamic observation only raises
    confidence. `methods_seen` must contain App Attest calls ONLY (the caller
    filters out DCDevice/DeviceCheck calls; see `process_app`)."""
    if methods_seen and endpoint_found:
        return AttestConfidence.CONFIRMED_LOCATED
    if methods_seen:
        return AttestConfidence.CONFIRMED_ACTIVE
    if symbols:
        return AttestConfidence.LIKELY
    if entitlement:
        return AttestConfidence.CAPABLE
    return AttestConfidence.NONE


def static_signals(appattest_flag, matched_patterns) -> tuple[bool, bool]:
    """(entitlement, symbols) from a static_profile row.

    New static_classify rows carry separate `appattest_entitlement` and
    `appattest_symbols` keys in matched_patterns; those are authoritative and
    make CAPABLE (entitlement, no symbols) reachable. Older rows only have the
    combined `appattest` key (symbol hits plus an `<entitlement>=<env>` entry):
    there the entitlement is recovered from that entry and `symbols` falls back
    to `appattest_flag`."""
    mp: dict = {}
    if matched_patterns:
        try:
            parsed = json.loads(matched_patterns) if isinstance(matched_patterns, str) \
                else matched_patterns
            if isinstance(parsed, dict):
                mp = parsed
        except (ValueError, TypeError):
            mp = {}
    if "appattest_entitlement" in mp or "appattest_symbols" in mp:
        entitlement = bool(mp.get("appattest_entitlement"))
        symbols = bool(mp.get("appattest_symbols"))
        return entitlement, symbols
    legacy = mp.get("appattest") or []
    if not isinstance(legacy, (list, tuple)):
        legacy = [legacy]
    entitlement = any(isinstance(x, str) and x.startswith(_ENT_APPATTEST) for x in legacy)
    if legacy:
        # Legacy list = API-symbol hits + (optionally) the entitlement entry, so any
        # non-entitlement entry is a symbol hit.
        symbols = any(isinstance(x, str) and not x.startswith(_ENT_APPATTEST) for x in legacy)
    else:
        symbols = bool(appattest_flag)
    return entitlement, symbols


def _endpoint_found(flows: list, syslog_text: str = "") -> str:
    """Host of the first request that carries attestation evidence (content
    fingerprint, wording, or a request that left right after a hook fired)."""
    for f in flows:
        if f.host and not capture.is_excluded(f.host) and _flow_attest_hits(f):
            return f.host
    timing = _timing_hits(flows, _call_times(syslog_text)) if syslog_text else {}
    for i in sorted(timing):
        f = flows[i]
        if 200 <= f.status < 300 and getattr(f, "method", "").upper() in ("POST", "PUT", "PATCH"):
            return f.host
    return ""


def _attest_requests(flows: list, syslog_text: str = "") -> list[dict]:
    """Every captured request that carries an attestation-looking signal (header,
    body, content fingerprint, or hook timing), for the UI table. `signal` names
    where it matched."""
    out: list[dict] = []
    timing = _timing_hits(flows, _call_times(syslog_text)) if syslog_text else {}
    for i, f in enumerate(flows):
        if not f.host or capture.is_excluded(f.host):
            continue
        hits = _flow_attest_hits(f)
        if i in timing:
            hits = hits + [f"timing(+{timing[i]:.0f}s)"]
        if not hits:
            continue
        out.append({
            "host": f.host,
            "method": getattr(f, "method", "") or "",
            "url": (f.url or "")[:200],
            "status": f.status,
            "signal": ", ".join(sorted(set(hits))[:5]),
        })
        if len(out) >= 50:
            break
    return out


def observe(app_id: str, bundle_id: str, decrypted: str,
            creds: dict | None, manual: bool = False,
            manual_seconds: int = 300, log_cb=None, stop_check=None,
            entshim: bool = False) -> tuple[Trail, str, list]:
    """Inject the observer, run the app while streaming syslog, parse the trail.

    manual=True: launch the app and capture the observer trail for `manual_seconds`
    while the human drives the UI by hand (no Appium), and leave the app INSTALLED
    afterwards so interaction can continue. manual=False: Appium-driven, then
    uninstall (the automated window-gated path).

    entshim=True also injects the EntitlementShim dylib (swallows re-sign
    entitlement-loss crashes so they aren't mis-read as tamper detection)."""
    def _stopped() -> bool:
        return bool(stop_check and stop_check())

    if _stopped():
        return Trail(), "", []
    ok, signed, err = instrument.build(app_id, decrypted, "attest_observe", entshim=entshim)
    if not ok:
        log.warning("%s observe build failed: %s", app_id, err)
        return Trail(), "", []
    if _stopped():
        return Trail(), "", []
    installed, ierr = device.install_ipa(signed)
    if not installed:
        log.warning("%s observe install failed: %s", app_id, ierr)
        return Trail(), "", []
    if _stopped():
        device.uninstall(bundle_id)
        return Trail(), "", []

    capture.check_connection()
    capture.clear_session()
    device.flush_crash_reports()  # so a crash during this run is attributable, not stale

    box: dict = {}  # holds the non-manual driver's DriveResult
    crashed_box = {"v": False}
    launch_failed = False
    if manual:
        pid = device.launch(bundle_id)  # open it; the human drives from here
        if pid is None:
            # The launch was denied or failed before the process existed (e.g.
            # SpringBoard refused, devicectl/pmd3 error). That is NOT a crash and
            # NOT anti-tamper: nothing ran, so nothing can be concluded.
            launch_failed = True
            log.warning("%s attest observe: launch failed/denied (not a crash)", app_id)
            if log_cb:
                log_cb("launch failed/denied (not a crash): the app process was never "
                       "started, so 'not called' cannot be concluded. You may still open "
                       "it by hand; the observer trail is captured either way.\n")
        _start = time.time()

        def _tick():
            # Detect a crash/anti-tamper exit AS SOON AS the process is gone, after a
            # short grace to let it launch. Logs it live and stops the capture.
            if crashed_box["v"]:
                return True
            if launch_failed:
                # No pid was ever started by us; "process gone" would just restate
                # the failed launch, not an exit. Keep capturing for the human.
                return False
            if time.time() - _start < 6:
                return False
            if device.is_app_running(bundle_id) is False:
                crashed_box["v"] = True
                if log_cb:
                    log_cb("process exited (crash, anti-tamper exit, or closed manually) "
                           "-> process gone. Stopping capture.\n")
                return True
            return False

        syslog = device.capture_syslog(seconds=manual_seconds, during=None,
                                       grep="AttestObserver", on_line=log_cb,
                                       stop_check=stop_check, tick=_tick)
    else:
        driver = device.AppiumDriver(credentials=creds or {})
        secs = CONFIG.runtime.monitor_seconds
        if creds:
            secs = max(secs, 60)  # logging in + reaching gated screens needs time

        def during():
            box["dr"] = driver.drive(bundle_id, secs, login=bool(creds),
                                     stop_check=stop_check)

        # Pass log_cb so the observer markers (HOOK/CALL) stream to the job console
        # live in UI-automation mode too, not just manual mode.
        syslog = device.capture_syslog(during=during, grep="AttestObserver",
                                       on_line=log_cb, stop_check=stop_check)

    har = CONFIG.paths.results_dir / f"{app_id}_attest_observe.har"
    capture.export_har(har)
    flows = capture.har_to_flows(capture.load_har(har), CONFIG.test_device.client_ip)

    trail = parse_trail(syslog)
    trail.launch_failed = launch_failed and not trail.loaded
    report = device.fetch_crash_report(bundle_id)  # crash report captured this run
    # Also honor the driver's own crash signal (Appium "Cannot launch application"
    # => app crashed on launch), in case the report file is slow/missing.
    dr = box.get("dr")
    if not report and dr is not None and getattr(dr, "crashed", False):
        report = dr.crash_report or "app failed to launch under WDA (crash on launch)"
    # Liveness: the observer loaded but the app's process is gone and nothing fired
    # => it terminated during the session. Catches graceful anti-tamper exits that
    # leave no crash report. (Manual: could also be the user closing the app.)
    if not report and manual and trail.loaded and not trail.calls:
        if crashed_box["v"] or device.is_app_running(bundle_id) is False:
            report = ("process exited during the session (crash, anti-tamper exit, or "
                      "closed manually; no crash report)")
    if not trail.launch_failed:
        trail.crash_report = report
    if not manual:
        device.uninstall(bundle_id)  # manual mode keeps the app installed

    return trail, _endpoint_found(flows, syslog), _attest_requests(flows, syslog)


def process_app(db: Database, row, accounts: dict, manual: bool = False,
                manual_seconds: int = 300, log_cb=None, stop_check=None,
                login: bool = False, entshim: bool = False) -> AttestConfidence:
    app_id, bundle_id = row["app_id"], row["bundle_id"]
    with db.connect() as c:
        st = c.execute("SELECT appattest_flag, matched_patterns FROM static_profile "
                       "WHERE app_id=?", (app_id,)).fetchone()
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    entitlement, symbols = static_signals(st["appattest_flag"] if st else False,
                                         st["matched_patterns"] if st else None)
    decrypted = ac["ipa_path"] if ac else ""

    from .attestation import creds_for
    # UI login is used only when explicitly enabled (and never needed for manual mode,
    # where the human drives). Without it, observe just launches + watches.
    creds = creds_for(accounts, app_id, bundle_id or "") if (login and not manual) else None
    trail, endpoint, requests = (Trail(), "", [])
    if decrypted:
        trail, endpoint, requests = observe(app_id, bundle_id, decrypted, creds,
                                            manual=manual, manual_seconds=manual_seconds, log_cb=log_cb,
                                            stop_check=stop_check, entshim=entshim)

    # App Attest ladder is fed by DCAppAttestService calls ONLY. DeviceCheck is a
    # separate mechanism and is reported/persisted on its own (devicecheck_status).
    aa_calls = trail.appattest_calls
    dc = devicecheck_status(trail)
    conf = classify_confidence(entitlement, symbols, aa_calls, bool(endpoint))
    _save(db, app_id, conf, trail, endpoint, requests)
    status = "ok" if trail.tooling_ok else "TOOLING-UNCONFIRMED"
    if trail.launch_failed:
        log.info("%s attest: launch failed/denied (not a crash); negative is unreliable", app_id)
    elif trail.crashed:
        log.info("%s attest: app process exited during the run (crash / anti-tamper exit%s)",
                 app_id, "" if not manual else " / closed manually")
    log.info("%s attest usage -> %s [%s] aa_calls=%s devicecheck=%s endpoint=%s "
             "crashed=%s launch_failed=%s",
             app_id, conf.value, status, aa_calls, dc["calls"], endpoint or "-",
             trail.crashed, trail.launch_failed)

    if log_cb:
        aa = appattest_status(trail)

        def _sel(calls):
            return ", ".join(sorted({c.split(" ", 1)[1] for c in calls if " " in c}))

        def _line(name, calls, present):
            if calls:
                return f"{name}: actively called ({_sel(calls)})"
            if present:
                if not trail.tooling_ok:
                    return f"{name}: present, not observed calling (UNRELIABLE negative)"
                return f"{name}: present, not observed calling"
            return f"{name}: not detected"

        log_cb("=== usage detection verdict ===\n")
        if trail.launch_failed:
            log_cb("App launch failed/denied (not a crash, not anti-tamper): the process "
                   "never ran, so any 'not called' result here is unreliable.\n")
        elif trail.crashed:
            if manual:
                log_cb("process exited (crash, anti-tamper exit, or closed manually) during "
                       "the session. Attestation 'not called' is unreliable here.\n")
            else:
                log_cb("App CRASHED / exited (crash report captured) -> possible anti-tamper / "
                       "integrity enforcement (it refuses to run re-signed). "
                       "Attestation 'not called' is unreliable here.\n")
        log_cb(_line("App Attest", aa["calls"], aa["present"]) + "\n")
        log_cb(_line("DeviceCheck", dc["calls"], dc["present"]) + "\n")
        log_cb(f"Attested endpoint (network): {endpoint or 'none found'}\n")
        log_cb(f"Overall App Attest confidence: {conf.value} | "
               f"detector reliable: {trail.tooling_ok}\n")
    return conf


def _save(db: Database, app_id: str, conf: AttestConfidence, trail: Trail, endpoint: str,
          requests: list | None = None) -> None:
    for col in ("attest_confidence TEXT", "attest_methods_seen TEXT",
                "attested_endpoint TEXT", "attest_tooling_ok INTEGER DEFAULT 0",
                "attest_trail TEXT", "attest_requests TEXT"):
        name, decl = col.split(" ", 1)
        db.add_column_if_missing("static_profile", name, decl)
    # `calls` keeps every observed call (the UI's hooked-calls table needs both
    # APIs); `devicecheck` carries the DeviceCheck verdict separately so it is
    # never folded into the App Attest confidence (no schema change needed).
    trail_json = json.dumps({"loaded": trail.loaded, "class_present": trail.class_present,
                             "class_absent": trail.class_absent, "present": trail.present,
                             "verified": trail.verified,
                             "failed": trail.failed, "calls": trail.calls,
                             "launches": trail.launches, "crashed": trail.crashed,
                             "supported": trail.supported,
                             "launch_failed": trail.launch_failed,
                             "hooks_armed": trail.hooks_armed,
                             "reliable": trail.tooling_ok,
                             "appattest": appattest_status(trail),
                             "devicecheck": devicecheck_status(trail)})
    with db.connect() as c:
        c.execute("UPDATE static_profile SET attest_confidence=?, attest_methods_seen=?, "
                  "attested_endpoint=?, attest_tooling_ok=?, attest_trail=?, attest_requests=? "
                  "WHERE app_id=?",
                  (conf.value, json.dumps(trail.appattest_calls), endpoint,
                   int(trail.tooling_ok), trail_json, json.dumps(requests or []), app_id))


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
