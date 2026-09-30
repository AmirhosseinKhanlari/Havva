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


def run_config(app_id: str, bundle_id: str, decrypted_ipa: str, config: str,
               driver: device.UIDriver, specs=None) -> ConfigRun:
    """Build + install + drive + capture one config. If `specs` is given, inject
    exactly those dylibs (a custom selection)."""
    log.info("[%s] building instrumented IPA", config)
    ok, signed, err = instrument.build(app_id, decrypted_ipa, config, specs=specs)
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

    creds = None  # supplied per app by attestation/auth stage when available
    log.info("launching + driving app for %ss (capturing traffic) ...", CONFIG.runtime.monitor_seconds)
    dr = driver.drive(bundle_id, CONFIG.runtime.monitor_seconds, login=bool(creds))

    har_path = CONFIG.paths.results_dir / f"{app_id}_{config}.har"
    capture.export_har(har_path)
    har = capture.load_har(har_path)
    flows = capture.har_to_flows(har, CONFIG.test_device.client_ip)
    hosts = capture.app_hosts(flows)
    reached = capture.reached_any_network(flows)
    if dr.crashed:
        log.info("  app crashed on launch (possible tamper detection)")
    elif hosts:
        log.info("  captured %d app host(s): %s", len(hosts), ", ".join(sorted(hosts)[:6]))
    elif reached:
        log.info("  reached network but no plaintext hosts (still pinned?)")
    else:
        log.info("  no traffic captured")

    crash_class = escalate.classify_crash(dr.crash_report, dr.launched, reached)
    device.uninstall(bundle_id)
    log.info("  uninstalled")

    return ConfigRun(config, ran=dr.launched and not dr.crashed, crashed=dr.crashed,
                     crash_class=crash_class, hosts=hosts, reached_network=reached,
                     login_status=dr.login_status, crash_report=dr.crash_report)


def run_custom(db: Database, row, driver: device.UIDriver,
               dylib_ids: list[str], aliased: bool = True) -> ConfigRun:
    """Run ONE dynamic pass injecting the user-selected dylibs, record it, and
    save an outcome. Returns the ConfigRun."""
    app_id = row["app_id"]
    bundle_id = row["bundle_id"]
    ac = db.get_acquisition(app_id)
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    specs = instrument.custom_specs(dylib_ids, aliased=aliased)
    label = "custom:" + ",".join(dylib_ids)
    run = run_config(app_id, bundle_id, decrypted, label, driver, specs=specs)
    db.add_dynamic_run(app_id, label, "ran" if run.ran else "fail",
                       run.crash_class, len(run.hosts), run.login_status)
    outcome = (Outcome.BYPASSED if run.hosts else
               Outcome.TAMPER_DETECTED if run.crashed else
               Outcome.PINNED_UNBYPASSED if run.reached_network else Outcome.INCONCLUSIVE)
    state = WorkState.POSITIVE if outcome == Outcome.BYPASSED else WorkState.UNTESTED
    db.save_outcome(app_id, outcome, BypassStage.DYLIB, True, state)
    return run


def process_app(db: Database, row, driver: device.UIDriver) -> Outcome:
    app_id = row["app_id"]
    bundle_id = row["bundle_id"]
    with db.connect() as c:
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted:
        db.save_outcome(app_id, Outcome.INCONCLUSIVE, BypassStage.NONE, False, WorkState.UNTESTED)
        return Outcome.INCONCLUSIVE

    per_config: list[tuple[BypassStage, set[str]]] = []
    runs: list[ConfigRun] = []

    # Stage 0: baseline, no bypass.
    s0 = run_config(app_id, bundle_id, decrypted, "stage0", driver)
    runs.append(s0)
    db.add_dynamic_run(app_id, "stage0", "ran" if s0.ran else "fail",
                       s0.crash_class, len(s0.hosts), s0.login_status)
    if s0.hosts:
        db.save_outcome(app_id, Outcome.NOT_PINNED, BypassStage.NONE, False, WorkState.DONE_NEGATIVE)
        db.set_stage(app_id, Stage.DYNAMIC_DONE)
        return Outcome.NOT_PINNED

    # First bypass rung: plain dylib.
    dylib = run_config(app_id, bundle_id, decrypted, BypassStage.DYLIB.value, driver)
    runs.append(dylib)
    per_config.append((BypassStage.DYLIB, dylib.hosts))
    db.add_dynamic_run(app_id, BypassStage.DYLIB.value, "ran" if dylib.ran else "fail",
                       dylib.crash_class, len(dylib.hosts), dylib.login_status)

    # Decide the tail. If the dylib crashed, disambiguate with a control re-sign.
    ladder: list[BypassStage] = []
    if not dylib.hosts:
        if dylib.crashed:
            control = run_config(app_id, bundle_id, decrypted, "control", driver)
            runs.append(control)
            db.add_dynamic_run(app_id, "control", "ran" if control.ran else "fail",
                               control.crash_class, len(control.hosts), control.login_status)
            ladder = escalate.plan_ladder(control_crashed=control.crashed)
        else:
            ladder = [BypassStage.RENAMED_DYLIB, BypassStage.FRIDA]

    for stage in ladder:
        if escalate.is_manual_tail(stage):
            log.info("%s needs %s (manual tail); queued", app_id, stage.value)
            db.add_dynamic_run(app_id, stage.value, "queued_manual",
                               CrashClass.NONE, 0, "none")
            continue
        r = run_config(app_id, bundle_id, decrypted, stage.value, driver)
        runs.append(r)
        per_config.append((stage, r.hosts))
        db.add_dynamic_run(app_id, stage.value, "ran" if r.ran else "fail",
                           r.crash_class, len(r.hosts), r.login_status)
        if r.hosts:
            break  # cheapest working stage found

    any_ran = any(r.ran for r in runs if r.config != "stage0") or s0.ran
    all_crashed = all(r.crashed for r in runs if r.config not in ("stage0", "control")) \
        and not any_ran
    reached = any(r.reached_network for r in runs)
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
