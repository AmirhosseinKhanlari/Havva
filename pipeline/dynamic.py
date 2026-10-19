"""Stages E/F/G orchestration: run the bypass ladder and decide the outcome.

Per pinned app:
  1. Stage 0 (own CA, no bypass): if the app's traffic is already visible, it
     does not pin -> NOT_PINNED, done.
  2. Otherwise walk the escalation ladder (dylib -> control-informed tail),
     capturing the host set each config reveals.
  3. Feed Stage-0 and per-config host sets to the oracle for the final label and
     bypass cost.

Every config run is: build (instrument) -> install -> drive (device) -> capture.
Resumable via the outcome work queue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import capture, device, escalate, instrument
from .config import CONFIG
from .db import Database
from .models import BypassStage, CrashClass, Outcome, Stage, WorkState
from .oracle import OracleInput, decide
from .util import get_logger

log = get_logger("dynamic", CONFIG.paths.log_dir)


@dataclass
class ConfigRun:
    config: str
    ran: bool
    crashed: bool
    crash_class: CrashClass
    hosts: set[str]
    reached_network: bool
    login_status: str
    crash_report: str = ""
    # From the native Proxyman session (ConnectionTraces): host -> outcome
    # (decrypted / pinned / unresolved / connect_failed / unknown). Reveals
    # hosts the app reached whose pinning our MITM could not break.
    conn_outcomes: dict = None
    run_log: str = ""        # captured pipeline log lines for just this run
    flows: list = None       # captured Flow objects (for IAP-bypass analysis)


@dataclass
class LaunchProbe:
    label: str
    built: bool
    installed: bool
    launched: bool
    alive: bool          # still running after the window
    crashed: bool
    error: str = ""

    @property
    def survived(self) -> bool:
        return self.launched and self.alive and not self.crashed


def _launch_probe(app_id: str, bundle_id: str, decrypted_ipa: str, label: str,
                  specs, sign_env, secs: int, entshim: bool = False) -> LaunchProbe:
    """Build + install + launch, wait `secs`, check liveness, uninstall. No
    Proxyman capture -- this only asks 'did the app stay running?'."""
    import time
    rs = CONFIG.signing.resolve(sign_env)
    prefer = "devicectl" if rs.get_task_allow else "pmd3"
    log.info("[%s] building (%s signing) ...", label, rs.env)
    ok, signed, err = instrument.build(app_id, decrypted_ipa, label, specs=specs,
                                       sign_env=sign_env, entshim=entshim)
    if not ok:
        log.warning("  build failed: %s", err)
        return LaunchProbe(label, False, False, False, False, False, err)
    inst, ierr = device.install_ipa(signed)
    if not inst:
        log.warning("  install failed: %s", ierr)
        return LaunchProbe(label, True, False, False, False, False, ierr)
    log.info("  installed; launching + waiting %ss ...", secs)
    # Consume any report left on the device (e.g. the control run's) so this
    # probe's fetch only sees a crash that happened AFTER this launch.
    device.flush_crash_reports()
    pid = device.launch(bundle_id, prefer=prefer)
    launched = pid is not None
    time.sleep(secs)
    # is_app_running is tri-state (None = unknown). Only a definite False means
    # the app exited; an unknown must not become a false "detected".
    running = device.is_app_running(bundle_id) if launched else False
    if launched and running is None:
        log.warning("  liveness unknown (device query failed); not treating as exited")
    alive = bool(launched) and running is not False
    crashed = bool(device.fetch_crash_report(bundle_id))
    log.info("  launched=%s alive=%s crashed=%s", launched, alive, crashed)
    device.terminate(pid, bundle_id)
    device.uninstall(bundle_id)
    return LaunchProbe(label, True, inst, launched, alive, crashed, "")


def inspect_storage(db: Database, row, sign_env: str | None = None,
                    monitor_seconds=None, entshim=False) -> dict:
    """Dynamic insecure-data-storage check. Runs the app, pulls its data
    container via house_arrest/AFC, and scans the unencrypted stores
    (NSUserDefaults / SQLite / Core Data / Realm / Cookies / keyboard cache)
    for secrets and sensitive values. Full-container access needs dev signing
    (get-task-allow); ad-hoc can usually only vend Documents."""
    import shutil
    import time
    from . import storage_scan

    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")
    secs = int(monitor_seconds) if monitor_seconds else 6

    rs = CONFIG.signing.resolve(sign_env)
    prefer = "devicectl" if rs.get_task_allow else "pmd3"
    if not rs.get_task_allow:
        log.warning("[storage] dist signing: house_arrest may vend Documents only; "
                    "use dev signing for full-container access")

    log.info("[storage] building (%s signing) + installing", rs.env)
    specs = instrument.custom_specs(["sideloadfix"], aliased=False)
    ok, signed, err = instrument.build(app_id, decrypted, "storage", specs=specs,
                                       sign_env=sign_env, entshim=entshim)
    if not ok:
        raise RuntimeError(f"build failed: {err}")
    installed, ierr = device.install_ipa(signed)
    if not installed:
        raise RuntimeError(f"install failed: {ierr}")

    log.info("[storage] launching + exercising for %ss (so it writes to disk)", secs)
    pid = device.launch(bundle_id, prefer=prefer)
    time.sleep(secs)

    dest = CONFIG.paths.work_dir / f"container_{app_id}"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    pulled_any = False
    for sub in ("Library", "Documents", "tmp"):
        if device.pull_container(bundle_id, sub, dest):
            pulled_any = True
            log.info("[storage] pulled %s", sub)

    device.terminate(pid, bundle_id)
    device.uninstall(bundle_id)

    if not pulled_any:
        db.save_storage_probe(app_id, "inconclusive",
                              "Could not pull the app container (need dev signing / app not launchable).",
                              [], {})
        log.warning("[storage] nothing pulled -> inconclusive")
        return {"verdict": "inconclusive", "note": "container not accessible",
                "findings": [], "stores": {}}

    findings, stores = storage_scan.scan_container(dest)
    verdict, note = storage_scan.verdict_of(findings)
    shutil.rmtree(dest, ignore_errors=True)
    db.save_storage_probe(app_id, verdict, note, findings, stores)
    log.info("[storage] verdict=%s: %d finding(s) across %d store(s)",
             verdict, len(findings), len(stores))
    return {"verdict": verdict, "note": note, "findings": findings, "stores": stores}


def detect_iap_bypass(db: Database, row, driver: device.UIDriver,
                      sign_env: str | None = None, monitor_seconds=None,
                      swap_certs=False, entshim=False, stop_check=None) -> dict:
    """In-app-purchase / subscription bypass detection (paper 1's phase_2). Runs
    the app with pinning bypassed (so IAP traffic is visible), captures the
    decrypted flows, and asks the Llama API whether any IAP field is
    client-tamperable. Stores + returns the verdict."""
    from . import iap_bypass
    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")

    log.info("[iap] launching with pinning bypass to capture IAP traffic")
    specs = instrument.custom_specs(["ssks", "sideloadfix"], aliased=True)
    run = run_config(app_id, bundle_id, decrypted, "iap", driver, specs=specs,
                     sign_env=sign_env, monitor_seconds=monitor_seconds, swap_certs=swap_certs,
                     entshim=entshim, stop_check=stop_check)
    flows = run.flows or []
    iap = iap_bypass.iap_flows(flows)
    log.info("[iap] %d captured flow(s), %d IAP-related", len(flows), len(iap))
    app_name = (row["name"] if "name" in row.keys() else None) or bundle_id

    res = iap_bypass.analyze_with_llama(app_name, iap)
    verdict = "bypassable" if res.get("tamperable") else (
        "inconclusive" if (res.get("error") or not iap) else "not_bypassable")
    db.save_iap_bypass(app_id, verdict, res, len(iap))
    log.info("[iap] verdict=%s (%s)", verdict, res.get("method") or res.get("error") or "")
    return {"verdict": verdict, **res, "n_iap_flows": len(iap)}


def detect_sideload(db: Database, row, sign_env: str | None = None,
                    monitor_seconds=None, entshim=False) -> dict:
    """Sideload / anti-resign detection via a differential launch:
      control : plain re-sign, NOTHING injected.
      fix     : SideloadFix injected.
    If the control can't stay running but the SideloadFix build can, the app
    detects sideloading (and SideloadFix defeats it)."""
    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")
    secs = int(monitor_seconds) if monitor_seconds else 5

    log.info("[sideload] control run: plain re-sign, no SideloadFix")
    control = _launch_probe(app_id, bundle_id, decrypted, "sideload:control", [], sign_env, secs,
                            entshim=entshim)
    log.info("[sideload] fix run: SideloadFix injected")
    slf_specs = instrument.custom_specs(["sideloadfix"], aliased=False)
    fixed = _launch_probe(app_id, bundle_id, decrypted, "sideload:sideloadfix", slf_specs, sign_env, secs,
                          entshim=entshim)

    c, f = control.survived, fixed.survived
    if not control.built or not fixed.built:
        verdict, note = "inconclusive", "Build failed; could not complete the probe."
    elif c and f:
        verdict, note = "no_detection", "Runs even with a plain re-sign — no sideload / anti-resign check."
    elif (not c) and f:
        verdict, note = "detected", "A plain re-sign is blocked but SideloadFix makes it run — the app detects sideloading."
    elif (not c) and (not f):
        verdict, note = "inconclusive", "Neither build stayed running — broken re-sign or anti-tamper SideloadFix can't defeat."
    else:
        verdict, note = "inconclusive", "Ran without SideloadFix but not with it — anomalous; re-run."

    db.save_sideload_probe(app_id, verdict, note, c, f, control.crashed, fixed.crashed)
    log.info("[sideload] verdict=%s (%s)", verdict, note)
    return {"verdict": verdict, "note": note, "control": control, "fixed": fixed}


def _resolve_bundle_id(db: Database, app_id: str, decrypted_ipa: str,
                       current: str | None) -> str:
    """The corpus DB sometimes has no bundle id. Recover it from the decrypted
    IPA's Info.plist and backfill, so we never try to launch a null bundle id."""
    if current:
        return current
    bid = instrument.bundle_id_from_ipa(decrypted_ipa)
    if bid:
        db.set_bundle_id(app_id, bid)
        log.info("recovered bundle id for %s from IPA: %s", app_id, bid)
    else:
        log.error("no bundle id for %s and could not read it from the IPA", app_id)
    return bid


import io as _io
import logging as _logging

_RUN_LOG_LOGGERS = ("dynamic", "instrument", "device", "capture")


class _CaptureRunLog:
    """Buffer log records from the pipeline loggers for the duration of one run,
    so each dynamic run can show its own log in the UI."""
    def __enter__(self):
        self.buf = _io.StringIO()
        self.handler = _logging.StreamHandler(self.buf)
        self.handler.setFormatter(_logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
        self.loggers = [_logging.getLogger(n) for n in _RUN_LOG_LOGGERS]
        for lg in self.loggers:
            lg.addHandler(self.handler)
        return self

    def __exit__(self, *exc):
        for lg in self.loggers:
            lg.removeHandler(self.handler)
        self.handler.flush()

    def text(self) -> str:
        return self.buf.getvalue()


def run_config(app_id: str, bundle_id: str, decrypted_ipa: str, config: str,
               driver: device.UIDriver, specs=None, sign_env=None,
               monitor_seconds=None, swap_certs=False, login=False,
               entshim=False, stop_check=None) -> ConfigRun:
    """Build + install + drive + capture one config, recording this run's own
    log lines onto the returned ConfigRun. `stop_check` (callable -> bool) is
    polled by the driver so a cancelled job stops driving the device."""
    cap = _CaptureRunLog()
    with cap:
        run = _run_config_impl(app_id, bundle_id, decrypted_ipa, config, driver,
                               specs=specs, sign_env=sign_env,
                               monitor_seconds=monitor_seconds, swap_certs=swap_certs,
                               login=login, entshim=entshim, stop_check=stop_check)
    run.run_log = cap.text()
    return run


def _run_config_impl(app_id: str, bundle_id: str, decrypted_ipa: str, config: str,
                     driver: device.UIDriver, specs=None, sign_env=None,
                     monitor_seconds=None, swap_certs=False, login=False,
                     entshim=False, stop_check=None) -> ConfigRun:
    """Build + install + drive + capture one config. If `specs` is given, inject
    exactly those dylibs (a custom selection). `sign_env` ("dev"/"dist") picks
    the cert+profile and the matching launch path. `monitor_seconds` overrides
    the capture window."""
    rs = CONFIG.signing.resolve(sign_env)
    prefer = "devicectl" if rs.get_task_allow else "pmd3"
    secs = int(monitor_seconds) if monitor_seconds else CONFIG.runtime.monitor_seconds
    log.info("[%s] building instrumented IPA (%s signing%s)", config, rs.env,
             ", cert-swap" if swap_certs else "")
    ok, signed, err = instrument.build(app_id, decrypted_ipa, config, specs=specs,
                                       sign_env=sign_env, swap_certs=swap_certs,
                                       entshim=entshim)
    if not ok:
        log.warning("%s build %s failed: %s", app_id, config, err)
        return ConfigRun(config, False, False, CrashClass.NONE, set(), False, "none")

    log.info("installing on device ...")
    installed, ierr = device.install_ipa(signed)
    if not installed:
        log.warning("%s install %s failed: %s", app_id, config, ierr)
        return ConfigRun(config, False, False, CrashClass.UNKNOWN, set(), False, "none")
    log.info("  installed")

    capture.check_connection()
    capture.clear_session()
    device.flush_crash_reports()  # so a stale crash from an earlier run isn't mis-read

    creds = None
    if login:
        from . import attestation
        creds = attestation.creds_for(attestation.load_accounts(), app_id, bundle_id)
        if creds:
            driver.credentials = creds   # AppiumDriver logs in with these
        else:
            log.info("UI login requested but no accounts.json entry for %s / %s",
                     app_id, bundle_id)
    log.info("launching + driving app for %ss (capturing traffic%s) ...", secs,
             ", UI login" if creds else "")
    dr = driver.drive(bundle_id, secs, login=bool(creds), prefer=prefer,
                      stop_check=stop_check)

    safe = config.replace(":", "_")
    har_path = CONFIG.paths.results_dir / f"{app_id}_{safe}.har"
    sess_path = CONFIG.paths.results_dir / f"{app_id}_{safe}.proxymansession"
    # Remove the previous run's exports FIRST: a failed export must never
    # silently reuse last run's HAR/session as this run's evidence.
    for stale in (har_path, sess_path, *sess_path.parent.glob(sess_path.name + "*")):
        try:
            if stale.is_file():
                stale.unlink()
        except OSError:
            pass
    if not capture.export_har(har_path):
        log.warning("  HAR export failed (no file); treating as no decrypted traffic")
    har = capture.load_har(har_path)
    flows = capture.har_to_flows(har, CONFIG.test_device.client_ip)
    hosts = capture.app_hosts(flows)
    reached = capture.reached_any_network(flows)   # non-excluded hosts only

    # Native session: per-host TLS outcome, including undecrypted tunnels.
    conn_outcomes: dict = {}
    if capture.export_session(sess_path):
        conn_outcomes = capture.session_host_outcomes(sess_path)
        pinned_now = [h for h, o in conn_outcomes.items() if o == "pinned"]
        if pinned_now:
            log.info("  %d host(s) with TLS-flavoured upstream failures (possible pinning; "
                     "upstream leg only, confirm manually): %s",
                     len(pinned_now), ", ".join(sorted(pinned_now)[:6]))

    # Two crash signals, trusted differently:
    #   died         : the LIVE liveness watch saw the process exit during the
    #                  window. Trustworthy; never suppressed by traffic (an app
    #                  can talk first and then kill itself on a tamper check).
    #   report_crash : a crash report was fetched. Only means launch-failure /
    #                  tamper if the app did NOT run; after a launched run that
    #                  produced traffic it is teardown/stale noise.
    died = bool(getattr(dr, "died", False))
    report_crash = bool(dr.crash_report) and not died
    effective_crashed = died or (report_crash and not (dr.launched and reached))
    if effective_crashed:
        log.info("  app crashed/exited (%s; possible tamper detection)",
                 "liveness: process exited during the window" if died
                 else "crash report, no traffic before it")
    elif hosts:
        log.info("  captured %d app host(s): %s", len(hosts), ", ".join(sorted(hosts)[:6]))
    elif reached:
        log.info("  reached network but no plaintext hosts (still pinned?)")
    else:
        log.info("  no traffic captured")
    if report_crash and not effective_crashed:
        log.info("  (ignored a crash report: app launched and produced traffic)")

    crash_class = escalate.classify_crash(dr.crash_report, dr.launched, reached)
    device.uninstall(bundle_id)
    log.info("  uninstalled")

    # Clear after export too (not just before the drive): leaves Proxyman empty
    # so decrypted traffic doesn't linger and can't bleed into the next run.
    capture.clear_session()

    return ConfigRun(config, ran=dr.launched and not effective_crashed, crashed=effective_crashed,
                     crash_class=crash_class, hosts=hosts, reached_network=reached,
                     login_status=dr.login_status, crash_report=dr.crash_report,
                     conn_outcomes=conn_outcomes, flows=flows)


# Catalog ids that actually defeat pinning / hooks. Injecting only helper dylibs
# (sideloadfix, entshim, attest) is NOT a bypass, so traffic seen with only those
# loaded means the host was never pinned.
BYPASS_DYLIB_IDS = frozenset({"ssks", "frida", "evasion"})
_LABEL_RE = re.compile(r"^[A-Za-z0-9_:.,-]+$")


def validate_dylib_ids(dylib_ids: list[str]) -> list[str]:
    """Reject anything that is not a known catalog id. The ids end up in the
    run label, which names a work directory that gets rmtree'd, so an
    unvalidated id is a path-traversal primitive."""
    known = {it["id"] for it in instrument.dylib_catalog()}
    out: list[str] = []
    for x in dylib_ids:
        if not isinstance(x, str) or x not in known:
            raise ValueError(f"unknown dylib id: {x}")
        out.append(x)
    return out


def _check_label(label: str) -> str:
    if not label or not _LABEL_RE.match(label):
        raise ValueError(f"invalid run label: {label!r}")
    return label


def custom_outcome(run: ConfigRun, dylib_ids: list[str]) -> tuple[Outcome, BypassStage, bool, WorkState]:
    """Pure: outcome/stage/pinned/state for a custom run. Only a selection that
    includes a real bypass dylib may be graded BYPASSED; traffic seen with only
    helper dylibs loaded means NOT_PINNED."""
    has_bypass = any(x in BYPASS_DYLIB_IDS for x in dylib_ids)
    if run.hosts:
        if has_bypass:
            return Outcome.BYPASSED, BypassStage.DYLIB, True, WorkState.POSITIVE
        return Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE
    stage = BypassStage.DYLIB if has_bypass else BypassStage.NONE
    if run.crashed:
        return Outcome.TAMPER_DETECTED, stage, False, WorkState.UNTESTED
    if run.reached_network:
        return Outcome.PINNED_UNBYPASSED, stage, has_bypass, WorkState.UNTESTED
    return Outcome.INCONCLUSIVE, stage, False, WorkState.UNTESTED


def run_custom(db: Database, row, driver: device.UIDriver,
               dylib_ids: list[str], aliased: bool = True,
               sign_env: str | None = None, monitor_seconds=None,
               swap_certs=False, stop_check=None) -> ConfigRun:
    """Run ONE dynamic pass injecting the user-selected dylibs, record it, and
    save an outcome. Returns the ConfigRun. Raises ValueError on an unknown
    dylib id (before anything touches the disk)."""
    dylib_ids = validate_dylib_ids(list(dylib_ids))
    label = _check_label("custom:" + ",".join(dylib_ids))
    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")
    db.clear_dynamic_runs(app_id)
    specs = instrument.custom_specs(dylib_ids, aliased=aliased)
    run = run_config(app_id, bundle_id, decrypted, label, driver, specs=specs,
                     sign_env=sign_env, monitor_seconds=monitor_seconds,
                     swap_certs=swap_certs, stop_check=stop_check)
    db.add_dynamic_run(app_id, label, "ran" if run.ran else "fail",
                       run.crash_class, len(run.hosts), run.login_status, log=run.run_log)
    outcome, stage, pinned, state = custom_outcome(run, dylib_ids)
    db.save_outcome(app_id, outcome, stage, pinned, state)
    return run


def detect_pinning(db: Database, row, driver: device.UIDriver,
                   aliased: bool = True, sign_env: str | None = None,
                   monitor_seconds=None, swap_certs=False, login=False,
                   entshim=False, stop_check=None) -> dict:
    """Differential per-endpoint SSL-pinning detection via Proxyman.

    Two MITM runs, both proxying `*`:
      clean  : SideloadFix only (no cert-pinning bypass). Only endpoints that
               already trust our CA decrypt -> hosts_clean.
      bypass : SSL Kill Switch 2 + SideloadFix. Pinning is defeated, so pinned
               endpoints now decrypt too -> hosts_bypass.

    A host visible ONLY once the bypass is in place was refusing Proxyman's CA
    on its own -> it enforces pinning. PINNED = hosts_bypass - hosts_clean
    (Apple/CDN already dropped by CONFIG.runtime.excluded_hosts). This is more
    robust than toggling SSL-proxying on/off, because the HAR export only holds
    decrypted transactions -- a non-decrypted tunnel isn't in it at all, so an
    MITM-off run yields no baseline to diff against.

    Returns {pinned, not_pinned, reliable, clean_reached, bypass_reached}.
    """
    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")

    db.clear_dynamic_runs(app_id)
    db.clear_pinning_probe(app_id)

    # Run 1: clean baseline -- what decrypts with no pinning help at all.
    log.info("[pinning] clean run (no bypass): endpoints that decrypt on their own")
    clean_specs = instrument.custom_specs(["sideloadfix"], aliased=aliased)
    clean = run_config(app_id, bundle_id, decrypted, "pinning:clean", driver,
                       specs=clean_specs, sign_env=sign_env, monitor_seconds=monitor_seconds,
                       login=login, entshim=entshim, stop_check=stop_check)
    db.add_dynamic_run(app_id, "pinning:clean", "ran" if clean.ran else "fail",
                       clean.crash_class, len(clean.hosts), clean.login_status, log=clean.run_log)

    # If the baseline build crashed / exited on launch, the app refuses to run
    # re-signed (anti-tamper / integrity enforcement). The bypass build is the same
    # re-sign plus SSKS, so it would die identically -- skip it, and report tamper
    # detection (a real finding), not "inconclusive".
    if clean.crashed:
        log.warning("[pinning] baseline crashed/exited on launch (anti-tamper); "
                    "skipping the bypass run")
        db.save_outcome(app_id, Outcome.TAMPER_DETECTED, BypassStage.NONE, False,
                        WorkState.DONE_NEGATIVE)
        return {"pinned": [], "hard_pinned": [], "not_pinned": [], "unresolved": [],
                "reliable": False, "crashed": True,
                "clean_reached": clean.reached_network, "bypass_reached": False}

    # Run 2: bypass -- SSL Kill Switch, so pinned endpoints decrypt too.
    log.info("[pinning] bypass run (SSL Kill Switch): all endpoints incl. pinned")
    bypass_specs = instrument.custom_specs(["ssks", "sideloadfix"], aliased=aliased)
    byp = run_config(app_id, bundle_id, decrypted, "pinning:bypass", driver,
                     specs=bypass_specs, sign_env=sign_env, monitor_seconds=monitor_seconds,
                     swap_certs=swap_certs, login=login, entshim=entshim, stop_check=stop_check)
    db.add_dynamic_run(app_id, "pinning:bypass", "ran" if byp.ran else "fail",
                       byp.crash_class, len(byp.hosts), byp.login_status, log=byp.run_log)

    # The clean build ran but the SSKS build died: the app noticed the hook
    # (anti-hook / integrity check), not "no pinning". Without a bypass run
    # there is no differential, so do NOT fall through to NOT_PINNED/BYPASSED.
    if byp.crashed:
        log.warning("[pinning] bypass run crashed/exited (possible anti-hook detection); "
                    "no differential available")
        db.save_outcome(app_id, Outcome.INCONCLUSIVE, BypassStage.DYLIB, False,
                        WorkState.UNTESTED)
        return {"pinned": [], "hard_pinned": [], "not_pinned": [], "unresolved": [],
                "reliable": False, "crashed": False, "crashed_bypass": True,
                "clean_reached": clean.reached_network, "bypass_reached": byp.reached_network}

    # A clean run that crashed gives no baseline -> the open/bypassable split
    # would be all false positives. Only trust that split if it launched.
    reliable = clean.ran and not clean.crashed
    byp_conn = byp.conn_outcomes or {}
    decrypted = byp.hosts | clean.hosts

    # Tier 3: hosts the app reached whose TLS aborted against our cert even with
    # SSL Kill Switch loaded -> pinning our MITM could not break. Direct signal
    # from the bypass run's connection traces, so it stands on its own.
    hard_pinned = sorted(h for h, o in byp_conn.items()
                         if o == "pinned" and h not in decrypted)
    # Endpoints that never resolved (dead / sinkholed) -- reported, not pinned.
    unresolved = sorted(h for h, o in byp_conn.items()
                        if o == "unresolved" and h not in decrypted
                        and h not in hard_pinned)

    # Tier 1/2: among endpoints we DID decrypt, which needed the bypass?
    bypassable = sorted(byp.hosts - clean.hosts)          # decrypt only w/ SSKS
    both = sorted(byp.hosts & clean.hosts)                # decrypt either way
    clean_only = sorted(clean.hosts - byp.hosts)          # decrypt w/o bypass

    diff_verdict = "pinned" if reliable else "uncertain"
    for h in bypassable:
        db.add_pinning_probe(app_id, h, diff_verdict, seen_bypass=True, seen_clean=False)
    for h in both:
        db.add_pinning_probe(app_id, h, "not_pinned", seen_bypass=True, seen_clean=True)
    for h in clean_only:
        db.add_pinning_probe(app_id, h, "not_pinned", seen_bypass=False, seen_clean=True)
    for h in hard_pinned:
        db.add_pinning_probe(app_id, h, "pinned_hard", seen_bypass=False, seen_clean=False)
    for h in unresolved:
        db.add_pinning_probe(app_id, h, "unresolved", seen_bypass=False, seen_clean=False)

    if not reliable:
        log.warning("[pinning] clean run did not launch cleanly (crash=%s); "
                    "open/bypassable split is UNCERTAIN", clean.crashed)
    log.info("[pinning] %d bypassable-pinned, %d hard-pinned, %d open, %d unresolved",
             len(bypassable), len(hard_pinned), len(both), len(unresolved))
    if bypassable:
        log.info("[pinning] bypassable: %s", ", ".join(bypassable))
    if hard_pinned:
        log.info("[pinning] HARD-PINNED (bypass failed): %s", ", ".join(hard_pinned))

    # Reflect the probe in the app's outcome.
    if hard_pinned:
        db.save_outcome(app_id, Outcome.PINNED_UNBYPASSED, BypassStage.NONE, True, WorkState.DONE_NEGATIVE)
    elif reliable and bypassable:
        db.save_outcome(app_id, Outcome.BYPASSED, BypassStage.DYLIB, True, WorkState.POSITIVE)
    elif reliable and decrypted:
        db.save_outcome(app_id, Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE)
    else:
        db.save_outcome(app_id, Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED)

    return {"pinned": bypassable, "hard_pinned": hard_pinned, "not_pinned": both,
            "unresolved": unresolved, "reliable": reliable, "crashed": False,
            "crashed_bypass": False,
            "clean_reached": clean.reached_network, "bypass_reached": byp.reached_network}


def ladder_tail_inputs(runs: list) -> tuple[bool, bool, bool]:
    """Pure: (all_crashed, any_ran, reached) for the oracle, computed over the
    BYPASS rungs only. The stage0 baseline and the control re-sign are not
    bypass attempts, so a clean stage0 must not mask 'every bypass rung
    crashed' (which is the TAMPER_DETECTED signal)."""
    bypass_runs = [r for r in runs if r.config not in ("stage0", "control")]
    all_crashed = bool(bypass_runs) and all(r.crashed for r in bypass_runs)
    any_ran = any(r.ran for r in bypass_runs)
    reached = any(r.reached_network for r in runs)
    return all_crashed, any_ran, reached


def process_app(db: Database, row, driver: device.UIDriver, entshim: bool = False,
                stop_check=None) -> Outcome:
    app_id = row["app_id"]
    with db.connect() as c:
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        db.save_outcome(app_id, Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED)
        return Outcome.INCONCLUSIVE
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        db.save_outcome(app_id, Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED)
        return Outcome.INCONCLUSIVE

    db.clear_dynamic_runs(app_id)
    per_config: list[tuple[BypassStage, set[str]]] = []
    runs: list[ConfigRun] = []

    # Stage 0: baseline, no bypass.
    s0 = run_config(app_id, bundle_id, decrypted, "stage0", driver, entshim=entshim,
                    stop_check=stop_check)
    runs.append(s0)
    db.add_dynamic_run(app_id, "stage0", "ran" if s0.ran else "fail",
                       s0.crash_class, len(s0.hosts), s0.login_status, log=s0.run_log)
    if s0.hosts:
        db.save_outcome(app_id, Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE)
        db.set_stage(app_id, Stage.DYNAMIC_DONE)
        return Outcome.NOT_PINNED

    # First bypass rung: plain dylib.
    dylib = run_config(app_id, bundle_id, decrypted, BypassStage.DYLIB.value, driver,
                       entshim=entshim, stop_check=stop_check)
    runs.append(dylib)
    per_config.append((BypassStage.DYLIB, dylib.hosts))
    db.add_dynamic_run(app_id, BypassStage.DYLIB.value, "ran" if dylib.ran else "fail",
                       dylib.crash_class, len(dylib.hosts), dylib.login_status, log=dylib.run_log)

    # Decide the tail. If the dylib crashed, disambiguate with a control re-sign.
    ladder: list[BypassStage] = []
    if not dylib.hosts:
        if dylib.crashed:
            control = run_config(app_id, bundle_id, decrypted, "control", driver,
                                 entshim=entshim, stop_check=stop_check)
            runs.append(control)
            db.add_dynamic_run(app_id, "control", "ran" if control.ran else "fail",
                               control.crash_class, len(control.hosts), control.login_status,
                               log=control.run_log)
            ladder = escalate.plan_ladder(control_crashed=control.crashed)
        else:
            ladder = [BypassStage.RENAMED_DYLIB, BypassStage.FRIDA]

    for stage in ladder:
        if escalate.is_manual_tail(stage):
            log.info("%s needs %s (manual tail); queued", app_id, stage.value)
            db.add_dynamic_run(app_id, stage.value, "queued_manual",
                               CrashClass.NONE, 0, "none")
            continue
        r = run_config(app_id, bundle_id, decrypted, stage.value, driver, entshim=entshim,
                       stop_check=stop_check)
        runs.append(r)
        per_config.append((stage, r.hosts))
        db.add_dynamic_run(app_id, stage.value, "ran" if r.ran else "fail",
                           r.crash_class, len(r.hosts), r.login_status, log=r.run_log)
        if r.hosts:
            break  # cheapest working stage found

    # Over bypass rungs only: a clean stage0 must not mask "every bypass crashed".
    all_crashed, any_ran, reached = ladder_tail_inputs(runs)
    login_completed = any(r.login_status in ("success", "not_needed") for r in runs)

    result = decide(OracleInput(
        stage0_app_hosts=s0.hosts,
        per_config_hosts=per_config,
        all_configs_crashed=all_crashed,
        any_config_ran=any_ran,
        reached_any_network=reached,
        login_required=False,
        login_completed=login_completed,
    ))
    state = WorkState.POSITIVE if result.label in (Outcome.BYPASSED, Outcome.PARTIAL) \
        else WorkState.DONE_NEGATIVE if result.label in (
            Outcome.NOT_PINNED, Outcome.PINNED_UNBYPASSED, Outcome.TAMPER_DETECTED) \
        else WorkState.UNTESTED  # INCONCLUSIVE: retry later
    db.save_outcome(app_id, result.label, result.bypass_cost, result.pinned, state)
    if state != WorkState.UNTESTED:
        db.set_stage(app_id, Stage.DYNAMIC_DONE)
    log.info("%s -> %s (cost=%s)", app_id, result.label.value, result.bypass_cost.value)
    return result.label


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    missing = CONFIG.missing_for_dynamic()
    if missing:
        log.error("cannot run dynamic stage; missing: %s", "; ".join(missing))
        return {}
    driver = device.default_driver()
    rows = db.apps_needing(Stage.DYNAMIC_DONE)
    if limit:
        rows = rows[:limit]
    tally: dict[str, int] = {}
    for row in rows:
        try:
            label = process_app(db, row, driver)
            tally[label.value] = tally.get(label.value, 0) + 1
        except Exception as e:
            log.exception("process_app %s failed: %s", row["app_id"], e)
    log.info("dynamic tally: %s", tally)
    return tally
