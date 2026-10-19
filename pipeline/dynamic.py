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
    # Device-side TLS rejections by THIS app's process (capture.tls_rejections):
    # the only direct, process-attributed evidence that the app refused our CA.
    tls_rejections: dict = None
    cleartext_hosts: set = None   # plain-HTTP hosts (reported, never a pinning verdict)

    @property
    def rejected(self) -> int:
        return int((self.tls_rejections or {}).get("rejected", 0))

    @property
    def rejected_hosts(self) -> set:
        return set((self.tls_rejections or {}).get("hosts", []))


@dataclass
class LaunchProbe:
    label: str
    built: bool
    installed: bool
    launched: bool
    alive: bool | None   # still running after the window; None = liveness unknown
    crashed: bool
    error: str = ""
    launch_failed: bool = False      # no pid AND no crash report: tooling, not the app
    crash_class: CrashClass = CrashClass.NONE
    crash_reason: str = ""
    intent: str = ""                 # tamper | entitlement | "" (escalate.crash_intent)

    @property
    def survived(self) -> bool:
        return self.launched and self.alive is True and not self.crashed

    @property
    def status(self) -> str:
        """ran | blocked | unknown. 'unknown' is a tooling gap (build, install,
        launch or liveness), never an observation about the app."""
        if not self.built or not self.installed or self.launch_failed:
            return "unknown"
        if self.survived:
            return "ran"
        if self.crashed or self.alive is False:
            return "blocked"
        return "unknown"

    def evidence(self) -> dict:
        return {"status": self.status, "launched": self.launched, "alive": self.alive,
                "crashed": self.crashed, "launch_failed": self.launch_failed,
                "crash_class": self.crash_class.value, "reason": self.crash_reason,
                "intent": self.intent, "error": self.error}


def _launch_probe(app_id: str, bundle_id: str, decrypted_ipa: str, label: str,
                  specs, sign_env, secs: int, entshim: bool = False,
                  stop_check=None) -> LaunchProbe:
    """Build + install + launch, watch liveness for `secs`, read the crash
    report, uninstall. No Proxyman capture: this only asks 'did the app stay
    running, and if not, what did it say on the way out?'.

    Three outcomes are kept apart because the verdict depends on it:
      ran      : launched and still alive at the end of the window
      blocked  : exited on its own (two consecutive misses) or left a crash report
      unknown  : build / install / launch tooling failed, or liveness could not
                 be read; never an observation about the app."""
    rs = CONFIG.signing.resolve(sign_env)
    prefer = "devicectl" if rs.get_task_allow else "pmd3"
    log.info("[%s] building (%s signing) ...", label, rs.env)
    ok, signed, err = instrument.build(app_id, decrypted_ipa, label, specs=specs,
                                       sign_env=sign_env, entshim=entshim)
    if not ok:
        log.warning("  build failed: %s", err)
        return LaunchProbe(label, False, False, False, None, False, err)
    inst, ierr = device.install_ipa(signed)
    if not inst:
        log.warning("  install failed: %s", ierr)
        return LaunchProbe(label, True, False, False, None, False, ierr)
    log.info("  installed; launching + watching liveness for %ss ...", secs)
    # Consume any report left on the device (e.g. the control run's) so this
    # probe's fetch only sees a crash that happened AFTER this launch.
    device.flush_crash_reports()
    pid = device.launch(bundle_id, prefer=prefer)
    launched = pid is not None
    if not launched:
        # No pid. A crash report means the app came up and died at launch
        # (SpringBoard reports it); no report means the LAUNCH failed (denied,
        # tunnel, tooling) and says nothing about the app.
        report = device.fetch_crash_report(bundle_id)
        device.uninstall(bundle_id)
        if report:
            reason = escalate.crash_reason(report)
            log.info("  died at launch: %s", reason[:160] or "(no reason)")
            return LaunchProbe(label, True, True, True, False, True, "",
                               crash_class=escalate.classify_crash(report, True, False),
                               crash_reason=reason, intent=escalate.crash_intent(reason))
        log.warning("  launch failed (no pid, no crash report): tooling, not the app")
        return LaunchProbe(label, True, True, False, None, False, "launch failed",
                           launch_failed=True)
    died = device.watch_liveness(bundle_id, secs, stop_check=stop_check)
    final = device.is_app_running(bundle_id)
    if died or final is False:
        alive: bool | None = False
    elif final is True:
        alive = True
    else:
        alive = None
        log.warning("  liveness unknown (device query failed); verdict will be inconclusive")
    report = device.fetch_crash_report(bundle_id)
    crashed = bool(report)
    crash_class = escalate.classify_crash(report, True, False) if report else CrashClass.NONE
    reason = escalate.crash_reason(report) if report else ""
    if alive is False and not report:
        reason = "exited during the window without a crash report (graceful exit)"
    intent = escalate.crash_intent(reason)
    log.info("  launched=True alive=%s crashed=%s class=%s%s", alive, crashed, crash_class.value,
             (" reason=" + reason[:140]) if reason else "")
    device.terminate(pid, bundle_id)
    device.uninstall(bundle_id)
    return LaunchProbe(label, True, inst, True, alive, crashed, "",
                       crash_class=crash_class, crash_reason=reason, intent=intent)


def inspect_storage(db: Database, row, sign_env: str | None = None,
                    monitor_seconds=None, entshim=False, driver=None, login=False,
                    stop_check=None) -> dict:
    """Data-storage inspection. Drives the app (through login when requested,
    so the post-auth writes exist), with StorageObserver injected to log each
    container file's Data Protection class and the app's Keychain items, then
    pulls the container via house_arrest/AFC and scans the stores.
    Full-container access needs dev signing (get-task-allow); ad-hoc can
    usually only vend Documents. A run whose app never launched or whose
    container could not be pulled is INCONCLUSIVE, with the reason."""
    import shutil
    from . import storage_scan

    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")
    # Post-login writes are what matter; a cold 6s peek saw onboarding state.
    secs = int(monitor_seconds) if monitor_seconds else 30

    rs = CONFIG.signing.resolve(sign_env)
    prefer = "devicectl" if rs.get_task_allow else "pmd3"
    if not rs.get_task_allow:
        log.warning("[storage] dist signing: house_arrest may vend Documents only; "
                    "use dev signing for full-container access")

    def _inconclusive(note: str, findings=None, stores=None) -> dict:
        db.save_storage_probe(app_id, "inconclusive", note, findings or [], stores or {})
        log.warning("[storage] inconclusive: %s", note)
        return {"verdict": "inconclusive", "note": note, "findings": findings or [],
                "stores": stores or {}}

    log.info("[storage] building (%s signing) + installing (SideloadFix + StorageObserver)", rs.env)
    specs = instrument.custom_specs(["sideloadfix", "storageobs"], aliased=False)
    ok, signed, err = instrument.build(app_id, decrypted, "storage", specs=specs,
                                       sign_env=sign_env, entshim=entshim)
    if not ok:
        raise RuntimeError(f"build failed: {err}")
    installed, ierr = device.install_ipa(signed)
    if not installed:
        raise RuntimeError(f"install failed: {ierr}")

    creds = None
    if login:
        from . import attestation
        creds = attestation.creds_for(attestation.load_accounts(), app_id, bundle_id)
        if not creds:
            log.info("[storage] UI login requested but no accounts.json entry for %s / %s",
                     app_id, bundle_id)
    if driver is None:
        driver = device.default_driver(credentials=creds or None)
    elif creds and hasattr(driver, "credentials"):
        driver.credentials = creds

    log.info("[storage] driving for %ss%s (observer logs protection classes + Keychain) ...",
             secs, " with UI login" if creds else "")
    box: dict = {}

    def _drive():
        box["dr"] = driver.drive(bundle_id, secs, login=bool(creds), prefer=prefer,
                                 stop_check=stop_check)
    syslog_text = device.capture_syslog(during=_drive, grep="STORAGEOBS")
    dr = box.get("dr")
    if dr is None or not dr.launched:
        device.uninstall(bundle_id)
        return _inconclusive("The app did not launch (no pid); nothing was written to inspect.")
    obs = storage_scan.parse_observer(syslog_text or "")
    if obs["loaded"]:
        log.info("[storage] observer: %d dump(s), %d file class(es), %d Keychain item(s)",
                 obs["dumps"], len(obs["files"]), len(obs["keychain"]))
    else:
        log.info("[storage] observer trail missing (dylib not loaded or syslog unavailable); "
                 "protection classes will be unknown")

    dest = CONFIG.paths.work_dir / f"container_{app_id}"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    pulled_any = False
    reasons: list[str] = []
    for sub in ("Library", "Documents", "tmp"):
        got, why = device.pull_container_ex(bundle_id, sub, dest)
        if got:
            pulled_any = True
            log.info("[storage] pulled %s", sub)
        elif why:
            reasons.append(f"{sub}: {why}")
    device.uninstall(bundle_id)

    if not pulled_any:
        # Nothing on disk, but the observer may still have inventoried the
        # Keychain / file classes from inside the process.
        findings, stores = storage_scan.apply_observer([], {}, obs)
        why = "; ".join(sorted(set(reasons))[:3]) or "no files came back"
        note = f"Could not pull the app container ({why})."
        if findings:
            note += " Keychain inventory below comes from the in-process observer only."
        return _inconclusive(note, findings, stores)

    findings, stores = storage_scan.scan_container(dest)
    findings, stores = storage_scan.apply_observer(findings, stores, obs)
    verdict, note = storage_scan.verdict_of(findings, observed=bool(obs["files"]))
    if getattr(dr, "died", False) or dr.crashed:
        note += " The app exited during the run; the stores reflect a partial session."
    if creds and dr.login_status not in ("success", "not_needed"):
        note += f" Login status: {dr.login_status}; post-login data may be missing."
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


# Static markers that show an INTENTIONAL integrity check shipped in the app,
# not an SDK that merely reports device state (sysctl/ptrace/'jailbroken' are
# in every analytics SDK). Used only to grade a blocked control run.
_STATIC_TAMPER_INTENT = ("IOSSecuritySuite", "FreeRASP", "amIReverseEngineered",
                         "checkInjectedLibraries", "amIJailbroken")


def _static_tamper_markers(db: Database, app_id: str) -> list[str]:
    try:
        prof = db.get_static_profile(app_id)
        if not prof:
            return []
        import json as _json
        mp = _json.loads(prof["matched_patterns"] or "{}")
        hits = set(mp.get("anti_tamper") or []) | set(mp.get("anti_debug") or [])
        return sorted(h for h in hits if h in _STATIC_TAMPER_INTENT)
    except Exception:  # noqa: BLE001 - corroboration only
        return []


_SLF_RECOVERS = ("keychain access group, app-group container and bundle identity are the "
                 "only things SideloadFix papers over")


def sideload_verdict(control: LaunchProbe, fixed: LaunchProbe,
                     static_markers: list[str] | None = None) -> tuple[str, str, dict]:
    """Pure verdict for the control (plain re-sign) vs SideloadFix pair.

    SideloadFix fixes exactly: keychain access groups, app-group containers
    and NSBundle identity. A control that dies and a fix build that runs
    therefore shows RE-SIGN FRAGILITY that those shims recover; it is an
    anti-resign CHECK only when something says so: the crash reason names
    tampering, or the binary ships an integrity SDK (static_markers).

      no_detection             both run
      anti_resign              control blocked with tamper intent, fix runs
      resign_fragile           control blocked, fix runs, no intent evidence
      resign_broken            both blocked by a kernel code-sign kill (our build)
      entitlement_crash        both blocked, reason names a stripped entitlement
      anti_resign_unrecovered  both blocked, tamper intent (SideloadFix cannot help)
      blocked_unrecovered      both blocked, cause unknown
      inconclusive             a tooling gap on either arm, or fix-dead/control-alive
    Returns (verdict, note, evidence)."""
    static_markers = list(static_markers or [])
    ev = {"control": control.evidence(), "fixed": fixed.evidence(),
          "static_markers": static_markers}
    c, f = control.status, fixed.status
    intents = {control.intent, fixed.intent} - {""}
    tamper = "tamper" in intents or bool(static_markers)
    why = control.crash_reason or fixed.crash_reason
    why_s = f" Reason: {why[:240]}" if why else ""
    src = ("crash message" if "tamper" in intents else
           ("static marker " + ", ".join(static_markers)) if static_markers else "")

    if c == "unknown" or f == "unknown":
        arm = "control" if c == "unknown" else "SideloadFix"
        pr = control if c == "unknown" else fixed
        gap = (pr.error or ("liveness could not be read" if pr.launched else "launch failed"))
        return ("inconclusive", f"The {arm} arm has a tooling gap ({gap}); the app was not "
                "observed. Re-run.", ev)
    if c == "ran" and f == "ran":
        return ("no_detection", "Runs with a plain re-sign: no anti-resign check and no "
                "re-sign fragility.", ev)
    if c == "blocked" and f == "ran":
        if tamper:
            return ("anti_resign", f"A plain re-sign is blocked and the {src} shows an intentional "
                    f"integrity check; SideloadFix defeats it.{why_s}", ev)
        return ("resign_fragile", "A plain re-sign cannot run but recovers under SideloadFix, and "
                f"nothing names an intentional check: {_SLF_RECOVERS}, so this is most likely a "
                f"missing entitlement (keychain / app group), not anti-tamper.{why_s}", ev)
    if c == "blocked" and f == "blocked":
        if CrashClass.KERNEL_CODESIGN in (control.crash_class, fixed.crash_class):
            return ("resign_broken", "Both builds were killed by the kernel for an invalid code "
                    f"signature: the re-sign itself is broken, not the app.{why_s}", ev)
        if "entitlement" in intents and not tamper:
            return ("entitlement_crash", "Both builds die on a stripped entitlement the shims do "
                    f"not cover; re-run with the entitlement shim enabled.{why_s}", ev)
        if tamper:
            return ("anti_resign_unrecovered", f"Both builds are blocked and the {src} shows an "
                    f"intentional integrity check SideloadFix cannot defeat.{why_s}", ev)
        return ("blocked_unrecovered", "Neither build stayed running and the crash evidence does "
                f"not say why.{why_s}", ev)
    return ("inconclusive", "Ran without SideloadFix but not with it: anomalous (injection "
            f"itself may be detected, or a flaky launch). Re-run.{why_s}", ev)


def detect_sideload(db: Database, row, sign_env: str | None = None,
                    monitor_seconds=None, entshim=False, stop_check=None) -> dict:
    """Re-sign fragility / anti-resign detection via a differential launch:
      control : plain re-sign, NOTHING injected (the entitlement shim, if
                requested, is the one exception and is noted in the verdict).
      fix     : SideloadFix injected.
    Each arm watches liveness for the window and keeps its crash reason; the
    pair is graded by sideload_verdict()."""
    app_id = row["app_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    bundle_id = _resolve_bundle_id(db, app_id, decrypted, row["bundle_id"])
    if not bundle_id:
        raise RuntimeError("no bundle id (not in DB and unreadable from IPA)")
    # Integrity checks often run after the first network round-trip or on a
    # background queue; a 5s peek missed them. Liveness is polled throughout.
    secs = int(monitor_seconds) if monitor_seconds else 20

    log.info("[sideload] control run: plain re-sign, no SideloadFix%s",
             " (+ entitlement shim: not a plain control for image-enumerating apps)" if entshim else "")
    control = _launch_probe(app_id, bundle_id, decrypted, "sideload:control", [], sign_env, secs,
                            entshim=entshim, stop_check=stop_check)
    if stop_check and stop_check():
        raise RuntimeError("cancelled")
    log.info("[sideload] fix run: SideloadFix injected")
    slf_specs = instrument.custom_specs(["sideloadfix"], aliased=False)
    fixed = _launch_probe(app_id, bundle_id, decrypted, "sideload:sideloadfix", slf_specs, sign_env, secs,
                          entshim=entshim, stop_check=stop_check)

    markers = _static_tamper_markers(db, app_id)
    verdict, note, evidence = sideload_verdict(control, fixed, markers)
    if entshim:
        evidence["entshim"] = True
    db.save_sideload_probe(app_id, verdict, note, control.survived, fixed.survived,
                           control.crashed, fixed.crashed, evidence=evidence)
    log.info("[sideload] verdict=%s (%s)", verdict, note)
    return {"verdict": verdict, "note": note, "control": control, "fixed": fixed,
            "evidence": evidence}


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
    # Drive under a device syslog capture: CFNetwork / boringssl log every TLS
    # rejection under the app's process name, which the proxy never sees.
    exe_name = instrument.executable_name_from_ipa(decrypted_ipa)
    box: dict = {}

    def _drive():
        box["dr"] = driver.drive(bundle_id, secs, login=bool(creds), prefer=prefer,
                                 stop_check=stop_check)
    syslog_text = device.capture_syslog(during=_drive, grep="")
    if "dr" not in box:   # capture helper bailed before driving (should not happen)
        _drive()
    dr = box["dr"]

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
    hosts = capture.app_hosts(flows)                 # TLS hosts only (https/wss)
    clear = capture.cleartext_hosts(flows)
    reached = capture.reached_any_network(flows)   # non-excluded hosts only
    rej = capture.tls_rejections(syslog_text or "", {exe_name} if exe_name else None)
    if rej["rejected"] or rej["cancelled"]:
        log.info("  device syslog: %d TLS rejection(s), %d challenge cancellation(s) by %s%s",
                 rej["rejected"], rej["cancelled"], exe_name or "the app",
                 (" on " + ", ".join(rej["hosts"][:4])) if rej["hosts"] else "")
    if clear:
        log.info("  %d cleartext host(s) (not evidence about pinning): %s",
                 len(clear), ", ".join(sorted(clear)[:4]))

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
                     conn_outcomes=conn_outcomes, flows=flows,
                     tls_rejections=rej, cleartext_hosts=clear)


# Catalog ids that actually defeat pinning / hooks. Injecting only helper dylibs
# (sideloadfix, entshim, attest) is NOT a bypass, so traffic seen with only those
# loaded means the host was never pinned. The Frida gadget is instrumentation:
# without a pinning script loaded through it (none is, yet) it bypasses
# nothing, so a gadget-only run can neither prove nor disprove pinning.
BYPASS_DYLIB_IDS = frozenset({"ssks", "evasion"})
INSTRUMENT_ONLY_IDS = frozenset({"frida"})
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
    gadget_only = (not has_bypass) and any(x in INSTRUMENT_ONLY_IDS for x in dylib_ids)
    if run.hosts:
        if has_bypass:
            # One run, no baseline: traffic under a bypass is 'bypassed' only
            # in the sense that it is visible; whether it was pinned is not
            # known. Flagged pinned=False so aggregates are not inflated.
            return Outcome.BYPASSED, BypassStage.DYLIB, False, WorkState.POSITIVE
        if gadget_only:
            return Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED
        if run.rejected:
            # Visible hosts AND the app rejected our CA for others: pinned
            # endpoints exist and nothing was bypassed.
            return Outcome.PINNED_UNBYPASSED, BypassStage.NONE, True, WorkState.DONE_NEGATIVE
        return Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE
    stage = BypassStage.DYLIB if has_bypass else BypassStage.NONE
    if run.crashed:
        return Outcome.TAMPER_DETECTED, stage, False, WorkState.UNTESTED
    if run.reached_network or run.rejected:
        return Outcome.PINNED_UNBYPASSED, stage, bool(run.rejected) or has_bypass, WorkState.UNTESTED
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

    reliable = clean.ran and not clean.crashed
    res = classify_pinning_runs(clean, byp)
    for h, (verdict, sb, sc) in sorted(res["probes"].items()):
        db.add_pinning_probe(app_id, h, verdict, seen_bypass=sb, seen_clean=sc)

    if not reliable:
        log.warning("[pinning] clean run did not launch cleanly (crash=%s); "
                    "open/bypassable split is UNCERTAIN", clean.crashed)
    log.info("[pinning] %d bypassable-pinned (%d unverified), %d hard-pinned, %d upstream lead(s), "
             "%d open, %d unresolved; CA rejections clean=%d bypass=%d",
             len(res["pinned"]), len(res["unverified"]), len(res["hard_pinned"]),
             len(res["leads"]), len(res["not_pinned"]), len(res["unresolved"]),
             clean.rejected, byp.rejected)
    if res["pinned"]:
        log.info("[pinning] bypassable: %s", ", ".join(res["pinned"]))
    if res["unverified"]:
        log.info("[pinning] revealed only in the bypass window, never contacted at baseline "
                 "(not counted as pinned): %s", ", ".join(res["unverified"]))
    if res["hard_pinned"]:
        log.info("[pinning] HARD-PINNED (app rejected our CA even with SSL Kill Switch): %s",
                 ", ".join(res["hard_pinned"]))
    if res["leads"]:
        log.info("[pinning] upstream TLS failures (lead only, confirm manually): %s",
                 ", ".join(res["leads"]))

    outcome, stage, pinned, state = res["outcome"]
    db.save_outcome(app_id, outcome, stage, pinned, state)
    log.info("[pinning] outcome: %s", outcome.value)

    return {"pinned": res["pinned"], "hard_pinned": res["hard_pinned"],
            "not_pinned": res["not_pinned"], "unresolved": res["unresolved"],
            "unverified": res["unverified"], "leads": res["leads"],
            "rejections": {"clean": clean.rejected, "bypass": byp.rejected},
            "outcome": outcome.value,
            "reliable": reliable, "crashed": False, "crashed_bypass": False,
            "clean_reached": clean.reached_network, "bypass_reached": byp.reached_network}


def pinning_verdict(reliable: bool, verified: int, unverified: int, open_hosts: int,
                    hard_pinned: int, rejected_clean: int, rejected_bypass: int
                    ) -> tuple[Outcome, BypassStage, bool, WorkState]:
    """Pure app-level verdict for the two-run probe.

    Evidence, strongest first:
      hard_pinned / rejected_bypass : the app rejected our CA WITH the bypass
                                      loaded (syslog, process-attributed).
      verified                      : hosts that decrypted only under the bypass
                                      AND were contacted at baseline (trace or
                                      rejection), i.e. a real differential.
      unverified                    : hosts first seen in the bypass window; a
                                      rejection at baseline explains them,
                                      otherwise they are window noise.
      rejected_clean                : the app rejected our CA at baseline.
      open_hosts                    : decrypted without any bypass.
    Upstream-trace 'leads' never reach this function: they are not evidence."""
    if hard_pinned or rejected_bypass:
        if verified or (unverified and rejected_clean):
            return Outcome.PARTIAL, BypassStage.DYLIB, True, WorkState.POSITIVE
        return Outcome.PINNED_UNBYPASSED, BypassStage.NONE, True, WorkState.DONE_NEGATIVE
    if not reliable:
        return Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED
    if verified or (unverified and rejected_clean):
        return Outcome.BYPASSED, BypassStage.DYLIB, True, WorkState.POSITIVE
    if rejected_clean:
        # Rejected at baseline, but the bypass run neither revealed the host
        # nor rejected: pinned, bypass unreproduced. Retry rather than guess.
        return Outcome.INCONCLUSIVE, BypassStage.NONE, True, WorkState.UNTESTED
    if open_hosts:
        return Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE
    return Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED


def classify_pinning_runs(clean: ConfigRun, byp: ConfigRun) -> dict:
    """Pure per-host + app-level classification of the clean/bypass pair.
    probes: host -> (verdict, seen_bypass, seen_clean) with verdicts
      pinned        decrypted only under the bypass, contacted at baseline
      unverified    decrypted only under the bypass, never contacted at baseline
      uncertain     'pinned' shape but the baseline did not launch cleanly, or a
                    baseline rejection the bypass run did not reproduce
      not_pinned    decrypted without the bypass
      pinned_hard   the app rejected our CA with the bypass loaded (syslog)
      pinned_lead   upstream TLS failure in Proxyman's trace (weak, unattributed)
      unresolved    never resolved in DNS (dead / sinkholed)"""
    reliable = clean.ran and not clean.crashed
    clean_traces = clean.conn_outcomes or {}
    byp_conn = byp.conn_outcomes or {}
    decrypted = byp.hosts | clean.hosts
    bypassable = sorted(byp.hosts - clean.hosts)
    both = sorted(byp.hosts & clean.hosts)
    clean_only = sorted(clean.hosts - byp.hosts)
    clean_rej_hosts = clean.rejected_hosts
    byp_rej_hosts = byp.rejected_hosts

    # A host that only appeared in the bypass window is a differential only if
    # the baseline run actually contacted it (any trace outcome, or a logged
    # rejection). Without a baseline trace export nothing can be verified, so
    # the old behaviour (trust the diff) is kept.
    if clean_traces:
        verified = [h for h in bypassable if h in clean_traces or h in clean_rej_hosts]
        unverified = [h for h in bypassable if h not in verified]
    else:
        verified, unverified = bypassable, []

    hard_pinned = sorted(byp_rej_hosts - decrypted)
    leads = sorted(h for h, o in byp_conn.items()
                   if o == "pinned" and h not in decrypted and h not in hard_pinned)
    unresolved = sorted(h for h, o in byp_conn.items()
                        if o == "unresolved" and h not in decrypted
                        and h not in hard_pinned and h not in leads)
    rejected_only = sorted(clean_rej_hosts - decrypted - set(hard_pinned))

    probes: dict[str, tuple[str, bool, bool]] = {}
    for h in verified:
        probes[h] = ("pinned" if reliable else "uncertain", True, False)
    for h in unverified:
        probes[h] = ("unverified", True, False)
    for h in both:
        probes[h] = ("not_pinned", True, True)
    for h in clean_only:
        probes[h] = ("not_pinned", False, True)
    for h in hard_pinned:
        probes[h] = ("pinned_hard", False, False)
    for h in rejected_only:
        probes[h] = ("uncertain", False, False)
    for h in leads:
        probes[h] = ("pinned_lead", False, False)
    for h in unresolved:
        probes[h] = ("unresolved", False, False)

    outcome = pinning_verdict(reliable, len(verified), len(unverified), len(both) + len(clean_only),
                              len(hard_pinned), clean.rejected, byp.rejected)
    return {"pinned": verified, "unverified": unverified, "not_pinned": both + clean_only,
            "hard_pinned": hard_pinned, "leads": leads, "unresolved": unresolved,
            "rejected_only": rejected_only, "probes": probes, "outcome": outcome}


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

    # Stage 0: baseline (SideloadFix only, no bypass). A crashed baseline is
    # retried once so a flaky launch does not leave the ladder without one.
    s0 = run_config(app_id, bundle_id, decrypted, "stage0", driver, entshim=entshim,
                    stop_check=stop_check)
    if s0.crashed and not (stop_check and stop_check()):
        log.info("stage0 crashed; retrying the baseline once")
        s0 = run_config(app_id, bundle_id, decrypted, "stage0", driver, entshim=entshim,
                        stop_check=stop_check)
    runs.append(s0)
    db.add_dynamic_run(app_id, "stage0", "ran" if s0.ran else "fail",
                       s0.crash_class, len(s0.hosts), s0.login_status, log=s0.run_log)
    # Visible TLS traffic with no CA rejection anywhere: nothing is pinned. If
    # the app rejected our CA for other endpoints, the ladder still runs.
    if s0.hosts and not s0.rejected:
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
    login_attempted = any(r.login_status == "attempted" for r in runs)

    result = decide(OracleInput(
        stage0_app_hosts=s0.hosts,
        per_config_hosts=per_config,
        all_configs_crashed=all_crashed,
        any_config_ran=any_ran,
        reached_any_network=reached,
        login_required=login_attempted and not login_completed,
        login_completed=login_completed,
        stage0_crashed=s0.crashed,
        baseline_tls_rejected=bool(s0.rejected),
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
