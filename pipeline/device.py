"""Stage E: device runner (non-jailbroken iPhone XR).

Install / launch / drive / terminate an app and retrieve crash reports. The key
lesson from paper 1: cold-launching under-triggers pinned handshakes, so we drive
the UI. Two drivers are provided:

  ColdLaunchDriver : launch, wait, terminate (paper-1 behavior; the fallback)
  AppiumDriver     : best-effort UI exercise + heuristic auto-login via WDA

Which driver is used depends on whether Appium is reachable. The AI-agent driver
(vphone-mcp style) can be added as another UIDriver without touching callers.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import CONFIG
from .util import get_logger, run_cmd

log = get_logger("device", CONFIG.paths.log_dir)

# xcrun must resolve the full Xcode toolchain -- the Command Line Tools lack
# `devicectl`, so a job that inherits a bare env would fail to launch anything.
_DEVELOPER_DIR = os.environ.get("DEVELOPER_DIR") or "/Applications/Xcode.app/Contents/Developer"


def _xcrun_env() -> dict:
    return {**os.environ, "DEVELOPER_DIR": _DEVELOPER_DIR}


@dataclass
class DriveResult:
    launched: bool
    login_status: str = "none"   # none | attempted | success | not_needed
    crashed: bool = False        # bool(crash_report) or died
    crash_report: str = ""
    died: bool = False           # live liveness-detected exit (process gone mid-window)


# ---- Low-level device ops ---------------------------------------------------

def _udid() -> str:
    return CONFIG.test_device.udid


def install_ipa(signed_ipa: str | Path, remove_after: bool = True) -> tuple[bool, str]:
    signed_ipa = Path(signed_ipa)
    p = run_cmd(["ideviceinstaller", "-u", _udid(), "-i", str(signed_ipa)], timeout=300)
    ok = p.ok and "Complete" in (p.stdout + p.stderr)
    # Re-signed IPAs are 300-400MB each; once installed, the staging copy under
    # work/ is dead weight. Delete it so runs don't pile up and fill the disk.
    # Only touch files under work/ (never the decrypted-IPA cache in ipas/).
    if ok and remove_after:
        try:
            if CONFIG.paths.work_dir.resolve() in signed_ipa.resolve().parents:
                signed_ipa.unlink(missing_ok=True)
        except Exception:
            pass
    return ok, (p.stderr or p.stdout)[:300]


def uninstall(bundle_id: str) -> None:
    run_cmd(["ideviceinstaller", "-u", _udid(), "-U", bundle_id], timeout=120)


# ---- pymobiledevice3 launcher (DVT process-control, ad-hoc apps, no root) ---
# devicectl's launch is a *debug* launch and is denied for apps signed without
# get-task-allow (ad-hoc/distribution). DVT process-control (how Instruments
# launches App Store apps) has no such requirement, so it launches our ad-hoc
# re-signed apps. On macOS its native RemoteXPC tunnel needs no root.

_tunnel_proc: "subprocess.Popen | None" = None
_tunnel_rsd: "tuple[str, str] | None" = None
_tunnel_log_fh = None            # open handle of the tunnel's log file (closed on restart)
_tunnel_atexit_registered = False


def _pmd3() -> str:
    return CONFIG.test_device.pmd3_bin


def pmd3_available() -> bool:
    return bool(_pmd3()) and Path(_pmd3()).exists()


def ensure_tunnel(timeout: int = 30) -> "tuple[str, str] | None":
    """Start (once per process) a rootless native tunnel and return its RSD
    (host, port). Cached for the session; restarted if the process died."""
    global _tunnel_proc, _tunnel_rsd, _tunnel_log_fh, _tunnel_atexit_registered
    if _tunnel_proc is not None and _tunnel_proc.poll() is None and _tunnel_rsd:
        return _tunnel_rsd
    if _tunnel_proc is not None:
        log.warning("pmd3 tunnel died (rc=%s); restarting", _tunnel_proc.poll())
    _tunnel_rsd = None
    log_path = CONFIG.paths.work_dir / "pmd3_tunnel.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    # Close the previous log handle before opening a new one (a restart would
    # otherwise leak one fd per restart for the life of the process).
    if _tunnel_log_fh is not None:
        try:
            _tunnel_log_fh.close()
        except Exception:
            pass
        _tunnel_log_fh = None
    f = log_path.open("w")
    _tunnel_log_fh = f
    try:
        _tunnel_proc = subprocess.Popen(
            [_pmd3(), "remote", "start-tunnel", "--native", "--udid", _udid()],
            stdout=f, stderr=subprocess.STDOUT, env=_xcrun_env())
    except FileNotFoundError:
        log.error("pymobiledevice3 not found at %s", _pmd3())
        _tunnel_proc = None
        return None
    if not _tunnel_atexit_registered:
        atexit.register(stop_tunnel)
        _tunnel_atexit_registered = True
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(1)
        try:
            txt = log_path.read_text()
        except OSError:
            txt = ""
        host = port = ""
        for line in txt.splitlines():
            if "RSD Address:" in line:
                host = line.split("RSD Address:")[1].strip()
            elif "RSD Port:" in line:
                port = line.split("RSD Port:")[1].strip()
        if host and port:
            _tunnel_rsd = (host, port)
            log.info("pmd3 native tunnel up (rsd %s %s)", host, port)
            return _tunnel_rsd
        if _tunnel_proc.poll() is not None:
            log.error("pmd3 tunnel exited early: %s", txt[-300:])
            return None
    log.error("pmd3 tunnel did not report an RSD within %ss", timeout)
    return None


def stop_tunnel() -> None:
    global _tunnel_proc, _tunnel_rsd, _tunnel_log_fh
    if _tunnel_proc is not None:
        try:
            _tunnel_proc.terminate()
            _tunnel_proc.wait(timeout=5)
        except Exception:
            try:
                _tunnel_proc.kill()
            except Exception:
                pass
    _tunnel_proc = None
    _tunnel_rsd = None
    if _tunnel_log_fh is not None:
        try:
            _tunnel_log_fh.close()
        except Exception:
            pass
        _tunnel_log_fh = None


def _tunnel_alive() -> bool:
    """Whether the cached pmd3 tunnel is still up (the RSD is only trustworthy
    while the tunnel process lives)."""
    return (_tunnel_proc is not None and _tunnel_proc.poll() is None
            and bool(_tunnel_rsd))


def _launch_pmd3(bundle_id: str) -> int | None:
    rsd = ensure_tunnel()
    if not rsd:
        return None
    host, port = rsd
    p = run_cmd([_pmd3(), "developer", "dvt", "launch", bundle_id,
                 "--rsd", host, port, "--kill-existing"], timeout=120, env=_xcrun_env())
    blob = p.stdout + p.stderr
    m = re.search(r"launched with pid (\d+)", blob, re.I)
    if m:
        return int(m.group(1))
    low = blob.lower()
    if "failed to launch" in low or "dtxnserror" in low or "failed." in low:
        log.warning("pmd3 launch failed for %s: %s", bundle_id, _launch_reason(blob))
        return None
    log.warning("pmd3 launch unclear for %s: %s", bundle_id, (p.stderr or p.stdout)[-200:])
    return None


def pid_running(pid: int | None) -> bool | None:
    """Whether `pid` is currently running (via pmd3 proclist). Returns True/False,
    or None if we can't determine it (so callers don't false-positive)."""
    if not pid or not pmd3_available():
        return None
    rsd = ensure_tunnel()
    if not rsd:
        return None
    host, port = rsd
    p = run_cmd([_pmd3(), "developer", "dvt", "proclist", "--rsd", host, port],
                timeout=30, env=_xcrun_env())
    out = (p.stdout or "").strip()
    if not out:
        return None
    try:
        import json
        procs = json.loads(out)
        return pid in {int(x.get("pid")) for x in procs if x.get("pid") is not None}
    except Exception:  # noqa: BLE001
        return bool(re.search(rf"\b{pid}\b", out))  # fallback: pid token present


def launch(bundle_id: str, prefer: str = "auto") -> int | None:
    """Launch an app. `prefer`:
      "devicectl" : debug launch first (dev/get-task-allow signature); pmd3 fallback.
      "pmd3"/"auto": DVT process-control first (works for ad-hoc); devicectl fallback.
    DVT is the default because ad-hoc re-signing is our common case."""
    if prefer == "devicectl":
        pid = _launch_devicectl(bundle_id)
        if pid is not None:
            return pid
        if pmd3_available():
            log.info("devicectl launch failed for %s; trying pmd3", bundle_id)
            return _launch_pmd3(bundle_id)
        return None
    if pmd3_available():
        pid = _launch_pmd3(bundle_id)
        if pid is not None:
            return pid
        log.info("pmd3 launch failed for %s; trying devicectl", bundle_id)
    return _launch_devicectl(bundle_id)


def _launch_devicectl(bundle_id: str) -> int | None:
    """Launch via devicectl (debug launch; needs a get-task-allow signature).
    Exports DEVELOPER_DIR so xcrun finds devicectl and reads the verbose text
    because devicectl exits 0 even when SpringBoard denies the launch."""
    out = CONFIG.paths.work_dir / f"launch_{bundle_id}.json"
    out.unlink(missing_ok=True)
    p = run_cmd(["xcrun", "devicectl", "device", "process", "launch",
                 "--device", _udid(), bundle_id, "--json-output", str(out),
                 "--verbose"], timeout=120, env=_xcrun_env())
    # A parsed pid is a definitive success.
    try:
        data = json.loads(out.read_text())
        pid = data.get("result", {}).get("process", {}).get("processIdentifier")
        if pid:
            return int(pid)
    except (OSError, ValueError, TypeError):
        pass
    # NB: devicectl exits 0 even when SpringBoard denies the launch, so we must
    # read the text, not the exit code. These markers only appear on failure.
    blob = p.stdout + p.stderr
    low = blob.lower()
    denied = any(m in low for m in (
        "failed to launch", "unable to launch", "requestdenied",
        "coredeviceerror", "fbsopenapplication"))
    if denied:
        log.warning("launch denied for %s: %s", bundle_id, _launch_reason(blob))
        return None
    if "running" in low or "launched" in low:
        return -1  # launched, pid unknown
    log.warning("launch failed for %s: %s", bundle_id, (p.stderr or p.stdout)[-200:])
    return None


def _launch_reason(blob: str) -> str:
    """Pull the human-readable failure reason out of devicectl's verbose text."""
    for line in blob.splitlines():
        if "NSLocalizedFailureReason" in line:
            return line.split("=", 1)[-1].strip()
    low = blob.lower()
    if "invalid code signature" in low or "not been explicitly trusted" in low:
        return ("app signed ad-hoc (get-task-allow=false); devicectl's debug "
                "launch is denied. Use a Development profile or a SpringBoard launch.")
    return blob[-200:]


def terminate(pid: int, bundle_id: str = "") -> None:
    if not pid or pid <= 0:
        return
    # If we launched via the pmd3 tunnel, kill through it; devicectl's terminate
    # is denied for the same ad-hoc apps its launch is. Only trust the cached
    # RSD while the tunnel process is alive; a dead tunnel would make the kill
    # silently no-op and leave the app running into the next run.
    if pmd3_available() and _tunnel_rsd:
        rsd = _tunnel_rsd if _tunnel_alive() else None
        if rsd is None:
            log.warning("pmd3 tunnel is down (rc=%s); restarting it to terminate pid %s",
                        _tunnel_proc.poll() if _tunnel_proc is not None else "n/a", pid)
            rsd = ensure_tunnel()
        if rsd:
            run_cmd([_pmd3(), "developer", "dvt", "kill", str(pid),
                     "--rsd", rsd[0], rsd[1]], timeout=30, env=_xcrun_env())
            return
        log.warning("pmd3 tunnel unavailable; falling back to devicectl terminate for pid %s", pid)
    run_cmd(["xcrun", "devicectl", "device", "process", "terminate",
             "--device", _udid(), "--pid", str(pid)], timeout=60, env=_xcrun_env())


def pull_container_ex(bundle_id: str, remote: str, local: "str | Path") -> tuple[bool, str]:
    """Pull `remote` (a path inside the app's data container) to `local` via
    house_arrest/AFC. Works over plain lockdown (no tunnel). Full-container
    access needs a dev-signed (get-task-allow) app; ad-hoc vends Documents only.
    Returns (got_files, reason): the reason names WHY nothing came back
    (tool missing, device locked, app not installed, signing) so the verdict
    does not blame signing for every failure. Only regular FILES count: a
    pull that creates empty directories has pulled nothing."""
    if not pmd3_available():
        return False, "pymobiledevice3 not available"
    local = Path(local)
    local.mkdir(parents=True, exist_ok=True)
    before = sum(1 for f in local.rglob("*") if f.is_file())
    p = run_cmd([_pmd3(), "apps", "pull", bundle_id, remote, str(local), "--udid", _udid()],
                timeout=180, env=_xcrun_env())
    got = sum(1 for f in local.rglob("*") if f.is_file()) > before
    if got:
        return True, ""
    err = ((p.stderr or "") + (p.stdout or "")).strip()
    low = err.lower()
    if "passwordprotected" in low or "device is locked" in low or "locked" in low:
        reason = "device is locked (unlock it and re-run)"
    elif "installationlookupfailed" in low or "not installed" in low:
        reason = "app not installed when the pull ran"
    elif "vendcontainer" in low or "house_arrest" in low or "permission" in low or "denied" in low:
        reason = ("container not vended (needs Development signing / get-task-allow; "
                  "ad-hoc only vends Documents)")
    elif p.returncode == 124:
        reason = "pull timed out"
    elif err:
        reason = "pull failed: " + err[-160:]
    else:
        reason = "nothing in that container path"
    return False, reason


def pull_container(bundle_id: str, remote: str, local: "str | Path") -> bool:
    """Boolean wrapper over pull_container_ex (kept for callers that only need yes/no)."""
    return pull_container_ex(bundle_id, remote, local)[0]


def _installed_exe_name(bundle_id: str) -> str:
    """CFBundleExecutable of the app we staged for this bundle id, read from the
    Info.plist of a re-signed bundle under work/ (inst_*/Payload/*.app). "" when
    nothing is staged. Used to attribute crash reports / processes by executable
    name exactly, never by a substring of the bundle id."""
    import plistlib
    try:
        plists = sorted(CONFIG.paths.work_dir.glob("inst_*/Payload/*.app/Info.plist"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return ""
    for pl in plists:
        try:
            with pl.open("rb") as fh:
                info = plistlib.load(fh)
        except Exception:  # noqa: BLE001
            continue
        if info.get("CFBundleIdentifier") == bundle_id:
            return str(info.get("CFBundleExecutable") or "")
    return ""


def _exe_name_for(bundle_id: str) -> str:
    """Best-effort executable name: the staged Info.plist's CFBundleExecutable,
    else (fallback ONLY) the bundle id's last component."""
    return _installed_exe_name(bundle_id) or bundle_id.rsplit(".", 1)[-1].strip()


def is_app_running(bundle_id: str) -> bool | None:
    """Tri-state liveness: True if an app with this bundle id is in the device's
    running-process list, False if a SUCCESSFULLY read process list does not
    contain it, None when the answer is unknown (proclist timeout / non-zero /
    empty / unparseable, devicectl timeout, missing or unparseable procs.json).
    Used by sideload detection: an app that detects re-signing often just exits
    (no crash log), so liveness is a better signal than crash reports -- but a
    transient tool failure must never be read as "the app exited"."""
    if pmd3_available():
        rsd = ensure_tunnel()
        if rsd:
            p = run_cmd([_pmd3(), "developer", "dvt", "proclist", "--rsd", rsd[0], rsd[1]],
                        timeout=30, env=_xcrun_env())
            out = (p.stdout or "").strip()
            if not p.ok or not out:
                log.info("proclist unavailable (rc=%s): %s", p.returncode,
                         (p.stderr or "")[-160:])
                return None
            try:
                procs = json.loads(out)
            except (ValueError, TypeError):
                log.info("proclist output not JSON (%d bytes)", len(out))
                return None
            if not isinstance(procs, list):
                return None
            return any(isinstance(e, dict) and e.get("bundleIdentifier") == bundle_id
                       for e in procs)
    out_path = CONFIG.paths.work_dir / "procs.json"
    out_path.unlink(missing_ok=True)  # never re-read a stale list from a prior call
    p = run_cmd(["xcrun", "devicectl", "device", "info", "processes", "--device", _udid(),
                 "--json-output", str(out_path)], timeout=60, env=_xcrun_env())
    if p.returncode == 124:
        log.info("devicectl processes timed out")
        return None
    try:
        data = json.loads(out_path.read_text())
    except (OSError, ValueError):
        return None
    procs = (data.get("result") or {}).get("runningProcesses") if isinstance(data, dict) else None
    if not isinstance(procs, list):
        return None
    exe = _exe_name_for(bundle_id)
    suffix = f"/{exe}.app/{exe}" if exe else ""
    for pr in procs:
        if not isinstance(pr, dict):
            continue
        bid = pr.get("bundleIdentifier")
        if bid:
            if bid == bundle_id:
                return True
            continue
        path = str(pr.get("executable") or "").rstrip("/")
        if suffix and path.endswith(suffix):
            return True
    return False


def _watch_liveness(bundle_id: str, duration: float, grace: int = 8, poll: int = 4,
                    stop_check=None) -> bool:
    """Keep the run window open for `duration`s while polling that the app stays
    running; return True if it exited ON ITS OWN before the window ended (a crash or
    an anti-tamper graceful exit that leaves no crash report). A grace period lets
    it finish launching first. False if it stayed up (we'll terminate it normally).

    The app is declared dead only after TWO consecutive informative `False` polls;
    `None` (liveness unknown: tool hiccup) is neither counted nor resets the count."""
    end = time.time() + duration
    time.sleep(min(grace, max(0.0, duration)))
    misses = 0
    while time.time() < end:
        if stop_check is not None and stop_check():
            return False
        state = is_app_running(bundle_id)
        if state is False:
            misses += 1
            if misses >= 2:
                return True
        elif state is True:
            misses = 0
        time.sleep(poll)
    return False


def watch_liveness(bundle_id: str, duration: float, stop_check=None) -> bool:
    """Public wrapper over _watch_liveness: True if the app exited on its own."""
    return _watch_liveness(bundle_id, duration, stop_check=stop_check)


def capture_syslog(seconds: int | None = None, during=None, grep: str = "OBSERVER",
                   on_line=None, stop_check=None, tick=None, tick_every: int = 5) -> str:
    """Stream the device syslog over USB (no jailbreak) while either sleeping
    `seconds` or running the `during` callable, returning lines matching `grep`.
    Used to read the AttestObserver marker trail while the app is exercised.

    If `on_line` is given (and `during` is not), the growing logfile is tailed for
    `seconds` and each matching line is forwarded to `on_line` as it appears, so a
    caller can stream the trail live (e.g. to a job console during manual use)."""
    import subprocess
    import time as _t
    out = CONFIG.paths.work_dir / "syslog.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        try:
            p = subprocess.Popen(["idevicesyslog", "-u", _udid()], stdout=f,
                                 stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            log.error("idevicesyslog not found (install libimobiledevice); "
                      "running the drive without a syslog trail")
            # The drive must still happen (install/launch/crash attribution depend
            # on it); we only lose the marker trail.
            if during is not None:
                during()
            return ""
        _t.sleep(1)  # let the stream attach before the app runs
        try:
            if during is not None and on_line is not None:
                # Run the driver in a thread and tail the log live for as long as the
                # drive takes (robust to a multi-minute WDA build before the app even
                # runs), so markers stream to the console in UI-automation mode too.
                import threading as _th
                done = {"v": False}
                failure: dict = {}

                def _runner():
                    try:
                        during()
                    except BaseException as e:  # noqa: BLE001 -- re-raised on the caller's thread
                        failure["exc"] = e
                    finally:
                        done["v"] = True

                _t_thread = _th.Thread(target=_runner, daemon=True)
                _t_thread.start()
                stopped = False
                with open(out, "r", errors="replace") as rf:
                    while not done["v"]:
                        if stop_check is not None and stop_check():
                            stopped = True
                            break
                        line = rf.readline()
                        if not line:
                            _t.sleep(0.3)
                            continue
                        if grep in line:
                            try:
                                on_line(line.rstrip("\n"))
                            except Exception:  # noqa: BLE001
                                pass
                if stopped:
                    # Give the driver a chance to honor its own stop_check and
                    # release the device before we tear the syslog down.
                    _t_thread.join(timeout=30)
                    if _t_thread.is_alive():
                        log.warning("drive thread still running 30s after Stop; "
                                    "abandoning it (daemon)")
                else:
                    _t_thread.join(timeout=10)
                if "exc" in failure:
                    # A drive failure must surface, not be read as "no crash".
                    raise failure["exc"]
            elif during is not None:
                during()
            elif on_line is not None:
                deadline = _t.time() + (seconds or CONFIG.runtime.monitor_seconds)
                last_tick = _t.time()
                with open(out, "r", errors="replace") as rf:
                    while _t.time() < deadline:
                        if stop_check is not None and stop_check():
                            break  # user hit Stop
                        if tick is not None and (_t.time() - last_tick) >= tick_every:
                            last_tick = _t.time()
                            try:
                                if tick():
                                    break  # tick asked to stop (e.g. app crashed)
                            except Exception:  # noqa: BLE001
                                pass
                        line = rf.readline()
                        if not line:
                            _t.sleep(0.3)
                            continue
                        if grep in line:
                            try:
                                on_line(line.rstrip("\n"))
                            except Exception:  # noqa: BLE001
                                pass
            else:
                _t.sleep(seconds or CONFIG.runtime.monitor_seconds)
        finally:
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
    try:
        lines = out.read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(l for l in lines if grep in l)


def flush_crash_reports() -> None:
    """Copy-and-remove all existing crash reports off the device (no -k) so a later
    fetch only sees reports generated AFTER this call. Prevents a stale report from
    an earlier run being mis-read as this run's crash. Best-effort."""
    import shutil
    dest = CONFIG.paths.work_dir / "crash"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    run_cmd(["idevicecrashreport", "-u", _udid(), str(dest)], timeout=120)  # no -k: removes from device
    shutil.rmtree(dest, ignore_errors=True)  # discard; we only want FUTURE reports


# .ips files that are not process crashes (memory-pressure kills, wifi/stack
# dumps, log snapshots). They mention every running process, so a name-based
# match on them would attribute a crash the app never had.
_NONCRASH_IPS_PREFIXES = ("JetsamEvent", "wifi", "stacks", "log-")


def _parse_ips(txt: str) -> tuple[dict, dict]:
    """Tolerant modern-.ips parser: (header, body). The first line is a JSON
    header, the remainder a JSON body. Either may be missing/unparseable, in
    which case the corresponding dict is empty (both empty => legacy text)."""
    header: dict = {}
    body: dict = {}
    first, _, rest = txt.partition("\n")
    try:
        h = json.loads(first)
        if isinstance(h, dict):
            header = h
    except ValueError:
        pass
    rest = rest.strip()
    if not header and txt.lstrip().startswith("{") and not rest.startswith("{"):
        rest = txt.strip()  # single-document JSON (no separate header line)
    if rest.startswith("{"):
        try:
            b = json.loads(rest)
            if isinstance(b, dict):
                body = b
        except ValueError:
            pass
    return header, body


def _report_matches(fname: str, txt: str, bundle_id: str, exe_name: str) -> bool:
    """Exact attribution of one crash report to `bundle_id`. Modern .ips: the
    header/body bundleID (or bundleInfo.CFBundleIdentifier) must equal the bundle
    id, or procName/app_name must equal the app's executable name (when known).
    Legacy text (.crash / non-JSON .ips): the FULL bundle id string must appear.
    Non-crash .ips types are skipped unless they explicitly name the bundle id."""
    if fname.startswith(_NONCRASH_IPS_PREFIXES):
        return bundle_id in txt
    header, body = _parse_ips(txt)
    if not header and not body:
        return bundle_id in txt  # legacy text report: full bundle id only
    if body.get("bundleID") == bundle_id or header.get("bundleID") == bundle_id:
        return True
    binfo = body.get("bundleInfo")
    if isinstance(binfo, dict) and binfo.get("CFBundleIdentifier") == bundle_id:
        return True
    if exe_name:
        if body.get("procName") == exe_name or header.get("app_name") == exe_name:
            return True
    return False


def fetch_crash_report(bundle_id: str, exe_name: str | None = None) -> str:
    """Copy crash reports off the device (consuming them: no -k, so each report
    is seen by exactly one fetch; reports are flushed before a run) and return
    the text of the report(s) attributed EXACTLY to this bundle (newest first),
    or "". `exe_name` (CFBundleExecutable) enables the procName match; when not
    given it is read from the staged bundle under work/ if available."""
    import shutil
    dest = CONFIG.paths.work_dir / "crash"
    shutil.rmtree(dest, ignore_errors=True)  # clear local accumulation from prior runs
    dest.mkdir(parents=True, exist_ok=True)
    run_cmd(["idevicecrashreport", "-u", _udid(), str(dest)], timeout=120)
    if exe_name is None:
        exe_name = _installed_exe_name(bundle_id)  # never the bundle-id suffix
    files = list(dest.rglob("*.ips")) + list(dest.rglob("*.crash"))
    try:
        files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    except OSError:
        pass
    hits = []
    for f in files:
        try:
            txt = f.read_text(errors="replace")
        except OSError:
            continue
        if _report_matches(f.name, txt, bundle_id, exe_name or ""):
            hits.append(txt)
    return "\n\n".join(hits)


# ---- UI drivers -------------------------------------------------------------

class UIDriver(Protocol):
    def drive(self, bundle_id: str, duration: int, login: bool,
              prefer: str = "auto", stop_check=None) -> DriveResult: ...


class ColdLaunchDriver:
    """Launch, wait, terminate. No UI interaction (paper-1 behavior)."""

    def drive(self, bundle_id: str, duration: int, login: bool,
              prefer: str = "auto", stop_check=None) -> DriveResult:
        pid = launch(bundle_id, prefer=prefer)
        if pid is None:
            report = fetch_crash_report(bundle_id)
            return DriveResult(launched=False, crashed=bool(report), crash_report=report)
        died = _watch_liveness(bundle_id, duration, stop_check=stop_check)  # True if it exited on its own
        report = fetch_crash_report(bundle_id)
        terminate(pid, bundle_id)
        return DriveResult(launched=True, crashed=bool(report) or died, died=died,
                           crash_report=report or ("app exited during run (process gone; "
                                                   "likely anti-tamper)" if died else ""))


class AppiumDriver:
    """Best-effort UI exercise + heuristic auto-login over WebDriverAgent.

    Requires an Appium server (Appium-Python-Client). Falls back to cold launch
    if it cannot connect. Login is heuristic: find username/password fields, type
    provided creds, tap a login/sign-in control.
    """

    def __init__(self, server_url: str | None = None,
                 credentials: dict[str, str] | None = None):
        self.server_url = server_url or CONFIG.appium.server_url
        self.credentials = credentials or {}

    def _make_driver(self, bundle_id: str, launch: bool = True):
        """Open a WDA session for `bundle_id`. With `launch=False` the session is
        created WITHOUT launching or terminating the app (appium:autoLaunch=false),
        so an already-running, instrumented process (e.g. with a Frida script
        attached) is left untouched; the caller then activates it."""
        from appium import webdriver
        from appium.options.ios import XCUITestOptions
        a = CONFIG.appium
        opts = XCUITestOptions()
        opts.udid = _udid()
        opts.bundle_id = bundle_id
        opts.platform_name = "iOS"
        opts.automation_name = "XCUITest"
        if not launch:
            opts.set_capability("appium:autoLaunch", False)
        # WDA signing for a real (non-jailbroken) device.
        if a.xcode_org_id:
            opts.set_capability("appium:xcodeOrgId", a.xcode_org_id)
            opts.set_capability("appium:xcodeSigningId", a.xcode_signing_id)
        if a.wda_bundle_id:
            opts.set_capability("appium:updatedWDABundleId", a.wda_bundle_id)
        # Do not reinstall/relaunch the target; we manage install ourselves.
        opts.set_capability("appium:noReset", True)
        # Auto-accept native permission prompts (notifications, tracking, location,
        # contacts) so onboarding reaches the login screen without per-app handling.
        # In-app "Accept / Continue" buttons are ordinary views; the generic
        # navigator taps those. See _skip_onboarding.
        opts.set_capability("appium:autoAcceptAlerts", True)
        return webdriver.Remote(self.server_url, options=opts)

    @staticmethod
    def _is_wda_auth_error(e: Exception) -> bool:
        """The 'hold both volume buttons' stop gesture revokes UI-testing auth,
        after which WDA sessions fail with XCTDaemonErrorDomain Code=41
        'Not authorized for performing UI testing actions'."""
        s = str(e).lower()
        return ("not authorized for performing ui testing" in s
                or "code=41" in s
                or ("unable to start webdriveragent session" in s
                    and "xctdaemonerrordomain" in s))

    @staticmethod
    def _is_app_launch_crash(e: Exception) -> bool:
        """Appium reports an app that crashes on launch as 'Cannot launch <app>
        application ... check the device log for possible crash report occurrences'
        -- i.e. the app (not WDA) died, typically anti-tamper on a re-signed build."""
        s = str(e).lower()
        return "cannot launch" in s and ("application" in s or "crash report" in s)

    def _reset_wda(self) -> bool:
        """Uninstall the WebDriverAgent runner so the next session rebuilds +
        reinstalls it, clearing a revoked UI-testing authorization (the hold-both-
        volume-buttons stop). The installed runner's bundle id has a '.xctrunner'
        suffix, so uninstall that (and the bare id as a fallback). Returns True if
        it removed the runner."""
        wda = CONFIG.appium.wda_bundle_id
        if not wda:
            log.warning("cannot reset WDA: APPIUM_WDA_BUNDLE not set")
            return False
        runner = wda if wda.endswith(".xctrunner") else wda + ".xctrunner"
        log.info("WDA UI-testing auth revoked; uninstalling %s to rebuild it", runner)
        removed = False
        for bid in (runner, wda):
            try:
                uninstall(bid)
                removed = True
            except Exception as e:  # noqa: BLE001
                log.info("WDA uninstall %s: %s", bid, e)
        time.sleep(2)
        return removed

    def drive(self, bundle_id: str, duration: int, login: bool,
              prefer: str = "auto", stop_check=None) -> DriveResult:
        try:
            drv = self._make_driver(bundle_id)
        except Exception as e:
            # Auto-recover from a revoked UI-testing authorization (volume-button
            # stop): reinstall WDA and retry once before giving up.
            if self._is_wda_auth_error(e) and self._reset_wda():
                try:
                    drv = self._make_driver(bundle_id)
                except Exception as e2:
                    if self._is_wda_auth_error(e2):
                        log.warning(
                            "WDA still UI-testing-unauthorized after reinstall. Ensure "
                            "Developer Mode is on and the device is unlocked. "
                            "Falling back to cold-launch (no UI driving).")
                    else:
                        log.warning("appium connect failed after WDA reset (%s); cold-launch", e2)
                    return ColdLaunchDriver().drive(bundle_id, duration, login, prefer=prefer,
                                                    stop_check=stop_check)
            elif self._is_app_launch_crash(e):
                # Not a WDA problem: the app itself crashes on launch (anti-tamper /
                # integrity enforcement refusing to run re-signed). Don't bother
                # cold-launching a crasher -- report it as a crash.
                log.warning("app crashes on launch under WDA (anti-tamper?): %s", bundle_id)
                report = fetch_crash_report(bundle_id)
                return DriveResult(launched=False, crashed=True, crash_report=report)
            else:
                log.warning("appium connect failed (%s); cold-launch fallback", e)
                return ColdLaunchDriver().drive(bundle_id, duration, login, prefer=prefer,
                                                stop_check=stop_check)

        login_status = "none"
        died = False
        try:
            deadline = time.time() + duration
            if login and self.credentials:
                login_status = self._attempt_login(drv)
            # A long login must never consume the whole window: the exercise /
            # liveness phase always gets at least a minimum window, otherwise a
            # post-login anti-tamper exit would go unobserved.
            remaining = max(deadline - time.time(), 15.0)
            if login_status == "success":
                # Logged in: stop driving the UI (further random taps could leave
                # the authenticated screen or hit 'log out'). Hold the session so
                # the app's post-login/gated requests still fire and get captured.
                log.info("login success; holding session (no further UI exercise)")
                died = _watch_liveness(bundle_id, remaining, stop_check=stop_check)
            else:
                # Not logged in: tap through a few tabs / buttons to trigger network.
                died = self._exercise(drv, time.time() + remaining, bundle_id,
                                      stop_check=stop_check)
        except Exception as e:
            log.info("appium drive note: %s", e)
        finally:
            try:
                drv.quit()
            except Exception:
                pass

        report = fetch_crash_report(bundle_id)
        return DriveResult(launched=True, login_status=login_status,
                           crashed=bool(report) or died, died=died,
                           crash_report=report or ("app exited during run (process gone; "
                                                   "likely anti-tamper)" if died else ""))

    def drive_attached(self, bundle_id: str, duration: int, stop_check=None) -> DriveResult:
        """Exercise an ALREADY-RUNNING app without relaunching it: open a WDA
        session with autoLaunch off, bring the app to the foreground
        (activate_app), then run the generic exercise + liveness loop for
        `duration`s. Needed so an attached Frida script survives the second drive
        of a probe (a normal drive would terminate+relaunch and unload the hook).
        Returns DriveResult(launched=False) on any Appium failure."""
        try:
            drv = self._make_driver(bundle_id, launch=False)
        except Exception as e:  # noqa: BLE001
            log.warning("appium attach failed for %s: %s", bundle_id, e)
            return DriveResult(launched=False)
        died = False
        try:
            try:
                drv.activate_app(bundle_id)
            except Exception as e:  # noqa: BLE001
                log.warning("activate_app failed for %s: %s", bundle_id, e)
                return DriveResult(launched=False)
            deadline = time.time() + max(float(duration), 0.0)
            died = self._exercise(drv, deadline, bundle_id, stop_check=stop_check)
        except Exception as e:  # noqa: BLE001
            log.info("appium attached-drive note: %s", e)
        finally:
            try:
                drv.quit()
            except Exception:
                pass
        report = fetch_crash_report(bundle_id)
        return DriveResult(launched=True, crashed=bool(report) or died, died=died,
                           crash_report=report or ("app exited during run (process gone; "
                                                   "likely anti-tamper)" if died else ""))

    # ---- login orchestration -------------------------------------------

    def _attempt_login(self, drv) -> str:
        """Generic 'reach the login state, then log in' navigator, driven by the
        accessibility tree (no per-app flow, no vision). Each round: (1) try the
        configured login method; (2) tap a login-intent control to open the login
        screen; (3) otherwise advance past onboarding / consent / permission screens
        (WhatsApp's 'Agree and continue', carousels, etc.). System permission alerts
        are auto-accepted by the session (autoAcceptAlerts). Gives up after ~12
        rounds. Login always runs BEFORE advancing, so we never skip past the field
        we came for.

        Optional per-app override: accounts.json may carry `pre_login_taps`, a list
        of labels tapped once up front, for the rare app the heuristics miss."""
        import time as _t
        _t.sleep(5)  # let the launch splash clear before the first attempt
        for lbl in (self.credentials.get("pre_login_taps") or []):
            if self._tap_label(drv, (lbl,)):
                _t.sleep(1.2)
        for _ in range(12):
            status = self._run_method(drv)
            if status != "none":
                return status
            if self._goto_login(drv):
                status = self._run_method(drv)
                if status != "none":
                    return status
            # Still nothing actionable: this may be an onboarding carousel or a
            # consent/permission screen that must be advanced to reach login. Try the
            # heuristic advance; if that finds nothing, ask the typed-decision model
            # (Jev) to pick a control from the visible labels; last, swipe a carousel.
            if not self._skip_onboarding(drv):
                if not self._llm_advance(drv):
                    self._swipe_left(drv)
            _t.sleep(2)
        return "none"

    def _collect_labels(self, drv, types: tuple[str, ...], limit: int = 20,
                        maxlen: int = 60) -> list[str]:
        """Normalized, de-duplicated labels of visible elements of the given types.
        Used to hand the on-screen choices to the decision-model fallback."""
        out: list[str] = []
        for t in types:
            for e in self._find(drv, f"XCUIElementType{t}"):
                try:
                    if not e.is_displayed():
                        continue
                    lab = self._norm_label(e.get_attribute("label") or e.get_attribute("name"))
                except Exception:
                    continue
                if lab and len(lab) <= maxlen and lab not in out:
                    out.append(lab)
                if len(out) >= limit:
                    return out
        return out

    def _llm_advance(self, drv) -> bool:
        """Stall fallback: ask the typed-decision model which visible control
        advances toward login, and tap it. No-op (returns False) when no API key is
        configured or the model declines / is unsure. Sends only element labels."""
        try:
            from . import llm_driver
        except Exception:  # noqa: BLE001
            return False
        if not llm_driver.available():
            return False
        candidates = self._collect_labels(drv, ("Button", "Link"))
        if not candidates:
            return False
        summary = " | ".join(self._collect_labels(drv, ("StaticText",), limit=6, maxlen=90))
        pick = llm_driver.choose_next_control(candidates, summary)
        if pick and self._tap_label(drv, (pick,)):
            import time as _t
            _t.sleep(1.5)
            return True
        return False

    def _skip_onboarding(self, drv) -> bool:
        """Advance past an onboarding / consent / permission screen toward login.
        Returns True if it tapped an advance control. Login-intent controls are
        handled earlier (_goto_login); this is the catch-all for screens with no
        login affordance yet. Consent/accept labels come first so e.g. WhatsApp's
        'Agree and continue' is matched before a generic 'Continue'."""
        import time as _t
        if self._tap_label(drv, (
                # consent / terms
                "Agree and continue", "Agree & Continue", "Agree & continue",
                "I Agree", "I agree", "Agree", "Accept All", "I Accept", "Accept",
                # permission / info pre-prompts
                "Allow All", "Allow", "Got it", "Got It", "Continue", "Next",
                # generic advance / dismiss (last, least specific)
                "Get Started", "Get started", "Done", "OK",
                "Maybe later", "Not now", "No thanks", "Skip")):
            _t.sleep(1.5)
            return True
        return False

    def _swipe_left(self, drv) -> None:
        """Horizontal swipe (advance a welcome/onboarding carousel page)."""
        try:
            sz = drv.get_window_size()
            w, h = sz["width"], sz["height"]
            drv.execute_script("mobile: dragFromToForDuration",
                               {"fromX": int(w * 0.85), "fromY": int(h * 0.5),
                                "toX": int(w * 0.15), "toY": int(h * 0.5), "duration": 0.3})
        except Exception:
            pass

    def _run_method(self, drv) -> str:
        """Dispatch on credentials['method']: phone (+Google Voice OTP), native
        email/password, or Google button. Returns none|attempted|success."""
        method = self.credentials.get("method", "auto")
        if method == "phone":
            return self._login_phone(drv)
        if method in ("auto", "native"):
            status = self._login_native(drv)
            if status != "none":
                return status
        if method in ("auto", "google"):
            return self._login_google(drv)
        return "none"

    def _goto_login(self, drv) -> bool:
        """From a welcome/landing screen, tap an entry control to reach the actual
        login screen. Returns True if it tapped something."""
        import time as _t
        if self._tap_label(drv, ("Log In", "Login", "Log in", "Sign In", "Sign in",
                                 "I already have an account", "Already have an account",
                                 "Already a member", "I have an account", "Continue with email")):
            _t.sleep(2)
            return True
        return False

    # ---- phone number + Google Voice OTP -------------------------------

    def _login_phone(self, drv) -> str:
        """Type the Google Voice number, trigger the SMS, then fetch the code from
        Gmail (GV forwards texts there) and enter it. Returns attempted|none.

        Handles both phone-field layouts: a single E.164 field, and a split
        country-code + national-number pair (WhatsApp's CountryCodeTextField /
        PhoneNumberTextField). The country code and national number are derived from
        the stored E.164 number, or taken from `country_code` / `national_number` in
        accounts.json when present."""
        import re as _re
        import time as _t
        from . import otp
        phone = self.credentials.get("phone", "")
        if not phone:
            return "none"
        fields = self._find(drv, "XCUIElementTypeTextField")
        if not fields:
            return "none"

        def _blob(e):
            return " ".join(self._norm_label(e.get_attribute(a))
                            for a in ("name", "label", "placeholderValue"))

        def _is_otp_blob(b: str) -> bool:
            # A "verification code" / "OTP" / "SMS code" / "PIN" field is the code
            # entry, never the country-code or phone-number field.
            return any(k in b for k in ("verification", "otp", "sms", "pin"))

        country_f = number_f = None
        for e in fields:
            b = _blob(e)
            if _is_otp_blob(b):
                continue
            if country_f is None and ("country" in b or ("code" in b and "phone" not in b)):
                country_f = e
            elif number_f is None and ("phone" in b or "number" in b):
                number_f = e
        digits = _re.sub(r"\D", "", phone)
        cc = str(self.credentials.get("country_code", "")) or (digits[:-10] if len(digits) > 10 else "")
        nat = str(self.credentials.get("national_number", "")) or (digits[-10:] if len(digits) > 10 else digits)

        def _set(e, text):
            try:
                e.clear()
            except Exception:
                pass
            e.send_keys(text)

        t0 = _t.time()
        try:
            if country_f is not None and number_f is not None:
                if cc:
                    _set(country_f, cc)       # e.g. "1" -> WhatsApp shows "+1"
                _set(number_f, nat)           # national digits only
            else:
                f = number_f or fields[0]
                number_f = f
                _set(f, phone if phone.startswith("+") else "+" + digits)
        except Exception:
            return "attempted"
        self._tap_label(drv, ("Continue", "Next", "Send code", "Get code", "Send",
                              "Submit", "Verify", "Log In", "Sign In"))
        code = otp.fetch(after=t0, timeout=int(self.credentials.get("otp_timeout", 90)))
        if not code:
            return "attempted"
        _t.sleep(1)
        # Code entry: either one field, or N single-digit boxes. The phone-number
        # field (still on screen for inline-OTP layouts) is NEVER a candidate.
        number_id = self._elem_id(number_f)
        cfields = [e for e in (self._find(drv, "XCUIElementTypeTextField")
                               + self._find(drv, "XCUIElementTypeSecureTextField"))
                   if number_id is None or self._elem_id(e) != number_id]
        try:
            if len(cfields) == 1:
                cfields[0].send_keys(code)
            elif len(cfields) >= len(code):
                for i, ch in enumerate(code):
                    cfields[i].send_keys(ch)
            else:
                return "attempted"
        except Exception:
            return "attempted"
        sig_before = self._screen_sig(drv)
        self._tap_label(drv, ("Continue", "Next", "Verify", "Submit", "Confirm",
                              "Log In", "Sign In"))
        _t.sleep(3)  # let the verification round-trip and the screen settle
        # Success = the confirm moved us off the phone/OTP screen: no phone/OTP
        # looking field remains AND the screen actually changed.
        try:
            leftover = [e for e in (self._find(drv, "XCUIElementTypeTextField")
                                    + self._find(drv, "XCUIElementTypeSecureTextField"))
                        if self._is_phone_or_otp_field(e)]
        except Exception:
            return "attempted"
        if not leftover and self._screen_sig(drv) != sig_before:
            return "success"
        return "attempted"

    @staticmethod
    def _elem_id(e):
        """Stable identity of a WebDriver element (its WDA element id), or None."""
        if e is None:
            return None
        return getattr(e, "id", None) or getattr(e, "_id", None) or id(e)

    def _is_phone_or_otp_field(self, e) -> bool:
        try:
            b = " ".join(self._norm_label(e.get_attribute(a))
                         for a in ("name", "label", "placeholderValue"))
        except Exception:
            return False
        return any(k in b for k in ("phone", "number", "code", "otp", "verification"))

    def _screen_sig(self, drv) -> str:
        """Cheap fingerprint of the current screen (labels of the visible
        controls/texts) used to tell whether a tap changed the screen."""
        try:
            labs = self._collect_labels(drv, ("StaticText", "Button", "TextField",
                                              "SecureTextField", "Image"),
                                        limit=60, maxlen=120)
            return "|".join(labs)
        except Exception:
            try:
                return str(drv.page_source)
            except Exception:
                return ""

    # ---- helpers --------------------------------------------------------

    def _find(self, drv, class_name: str) -> list:
        from appium.webdriver.common.appiumby import AppiumBy
        try:
            return drv.find_elements(AppiumBy.CLASS_NAME, class_name)
        except Exception:
            return []

    @staticmethod
    def _norm_label(s: str | None) -> str:
        """Normalize an accessibility label for matching: drop invisible bidi marks
        (iOS prefixes many labels with U+200E/U+200F), collapse whitespace, lower."""
        s = (s or "").replace("‎", "").replace("‏", "").replace("‪", "").replace("‬", "")
        return " ".join(s.split()).strip().lower()

    # Labels that negate/dismiss. A wanted "Allow"/"Agree" must never tap
    # "Don't Allow"/"Disagree"; only a wanted negation may tap one.
    _NEGATIONS = ("don't", "don’t", "do not", "disagree", "decline", "not now",
                  "no thanks", "cancel", "reject")
    # Bare entry labels for which an SSO variant ("continue with google") is a
    # different control and must not be tapped.
    _BARE_ENTRY = ("continue", "next", "sign in", "log in", "login")

    @classmethod
    def _is_negation(cls, lab: str) -> bool:
        return any(n in lab for n in cls._NEGATIONS)

    def _tap_label(self, drv, labels: tuple[str, ...]) -> bool:
        """Tap the control whose label/name matches one of `labels`, trying the
        wanted labels IN ORDER (earlier labels win over later ones regardless of
        element order). Matching is bidi/whitespace-normalized and prioritizes real
        controls: Buttons/Links match on equality or a word-bounded substring
        ("agree" never matches "disagree", "allow" never matches "don't allow");
        StaticText/Cell/Other match only on exact equality, so a descriptive
        paragraph that merely mentions the label (e.g. WhatsApp's 'Tap "Agree and
        continue" to accept ...') never hijacks the tap away from the actual button.
        Negating labels are skipped unless the wanted label is itself a negation,
        and a bare "continue"/"next"/"sign in"/"log in" never taps an SSO button
        ("continue with google")."""
        from appium.webdriver.common.appiumby import AppiumBy
        wanted = [self._norm_label(x) for x in labels if x]
        wanted = [w for w in wanted if w]
        if not wanted:
            return False

        cache: dict[str, list] = {}

        def _candidates(t):
            if t not in cache:
                try:
                    els = drv.find_elements(AppiumBy.CLASS_NAME, f"XCUIElementType{t}")
                except Exception:
                    els = []
                cache[t] = [(e, _label_of(e)) for e in els]
            return cache[t]

        def _label_of(e):
            try:
                return self._norm_label(e.get_attribute("label") or e.get_attribute("name"))
            except Exception:
                return ""

        def _click(e) -> bool:
            try:
                if e.is_displayed() and e.is_enabled():
                    e.click()
                    return True
            except Exception:
                pass
            return False

        for w in wanted:
            w_neg = self._is_negation(w)
            pat = re.compile(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])")
            # 1) Real tappable controls: equality OR word-bounded substring.
            for t in ("Button", "Link"):
                for e, lab in _candidates(t):
                    if not lab:
                        continue
                    if lab != w:
                        if not pat.search(lab):
                            continue
                        if not w_neg and self._is_negation(lab):
                            continue  # "don't allow" for a wanted "allow"
                        if w in self._BARE_ENTRY and " with " in lab and " with " not in w:
                            continue  # SSO variant of a bare entry label
                    if _click(e):
                        return True
            # 2) Text/containers: exact equality only (avoid matching a paragraph).
            for t in ("StaticText", "Cell", "Other"):
                for e, lab in _candidates(t):
                    if lab == w and _click(e):
                        return True
        return False

    def _accept_native_alert(self, drv) -> None:
        """iOS shows a native 'App Wants to Use google.com to Sign In' alert;
        accept it so the web-auth session can open."""
        try:
            drv.switch_to.alert.accept()
            return
        except Exception:
            pass
        self._tap_label(drv, ("Continue", "Allow", "Sign In", "OK"))

    def _confirm_oauth(self, drv, tries: int = 12, delay: int = 2) -> bool:
        """After the Google account is selected, poll for and tap the final
        consent/'Continue' in whatever form it appears: a native alert, a labeled
        native button, or a webview button. Stops once nothing is left to confirm
        (the sheet dismissed). Returns True if it tapped a confirm at least once."""
        import time as _t
        # EXACT labels only: "Continue with Google"/"Continue with Apple" also
        # contain "Continue", so a CONTAINS match would re-tap the entry button.
        labels = ("Continue", "Allow", "Weiter", "Agree", "Accept", "Authorize",
                  "Confirm", "Open")
        tapped = False
        for _ in range(tries):
            did = False
            try:
                drv.switch_to.alert.accept()
                did = True
            except Exception:
                pass
            if not did and self._tap_exact_enabled(drv, labels):
                did = True
            if not did:
                did = self._tap_webview_confirm(drv)
            if did:
                tapped = True
                _t.sleep(delay)
                continue
            if tapped:
                break  # already confirmed and nothing left -> done
            # Google's consent 'Continue' can be below the fold (the blue down-arrow
            # FAB) and thus not visible/tappable yet; scroll up to reveal it.
            self._scroll_up(drv)
            _t.sleep(delay)
        return tapped

    def _scroll_up(self, drv) -> None:
        """Scroll the current content up (to reveal a below-the-fold button)."""
        try:
            sz = drv.get_window_size()
            w, h = sz["width"], sz["height"]
            drv.execute_script("mobile: dragFromToForDuration",
                               {"fromX": w // 2, "fromY": int(h * 0.75),
                                "toX": w // 2, "toY": int(h * 0.30), "duration": 0.4})
        except Exception:
            pass

    def _tap_exact_enabled(self, drv, names: tuple[str, ...]) -> bool:
        """Tap a button whose label/name EXACTLY equals one of `names` and is
        enabled + visible. Avoids matching 'Continue with Google' when we want the
        bare 'Continue' consent button, and skips disabled placeholders."""
        from appium.webdriver.common.appiumby import AppiumBy
        for name in names:
            try:
                safe = name.replace("'", "")
                pred = ("type == 'XCUIElementTypeButton' AND enabled == true AND "
                        f"visible == true AND (label == '{safe}' OR name == '{safe}')")
                els = drv.find_elements(AppiumBy.IOS_PREDICATE, pred)
                if els:
                    els[0].click()
                    return True
            except Exception:
                pass
        return False

    def _tap_webview_confirm(self, drv) -> bool:
        """Tap a Continue/Allow button inside a webview OAuth sheet (only works when
        it is an accessible WKWebView). No-op if there is no web context."""
        from appium.webdriver.common.appiumby import AppiumBy
        try:
            web = next((c for c in drv.contexts if "WEBVIEW" in c), None)
        except Exception:
            return False
        if not web:
            return False
        ok = False
        try:
            drv.switch_to.context(web)
            for el in drv.find_elements(AppiumBy.CSS_SELECTOR,
                                        "button, [role=button], input[type=submit]"):
                if (el.text or "").strip().lower() in (
                        "continue", "allow", "agree", "accept", "confirm"):
                    el.click()
                    ok = True
                    break
        except Exception:
            pass
        finally:
            try:
                drv.switch_to.context("NATIVE_APP")
            except Exception:
                pass
        return ok

    # ---- native email/password -----------------------------------------

    def _login_native(self, drv) -> str:
        user = self.credentials.get("username", "")
        pw = self.credentials.get("password", "")
        if not (user and pw):
            return "none"
        fields = self._find(drv, "XCUIElementTypeTextField")
        secure = self._find(drv, "XCUIElementTypeSecureTextField")
        if not (fields and secure):
            return "none"
        try:
            fields[0].send_keys(user)
            secure[0].send_keys(pw)
            self._tap_label(drv, ("Log In", "Sign In", "Login", "Continue", "Sign in", "Next"))
            return "attempted"
        except Exception:
            return "attempted"

    # ---- Sign in with Google -------------------------------------------

    def _login_google(self, drv) -> str:
        """Best-effort 'Sign in with Google'. Works reliably only when the test
        Google account is already signed into the device's Safari (shared cookies
        via ASWebAuthenticationSession) or when the app uses an embedded WKWebView.
        Google's bot detection may still block a re-signed/instrumented app."""
        import time as _t
        email = self.credentials.get("google_email") or self.credentials.get("username", "")
        pw = self.credentials.get("google_password") or self.credentials.get("password", "")
        # 1. Tap the Google entry button.
        if not self._tap_label(drv, ("Continue with Google", "Sign in with Google",
                                     "Sign up with Google", "Log in with Google", "Google")):
            return "none"
        _t.sleep(2)
        # 2. Accept the iOS web-auth consent alert.
        self._accept_native_alert(drv)
        _t.sleep(3)
        # 3a. Safari SSO: an account chooser may show the account by email; tap it.
        if email and self._tap_label(drv, (email, email.split("@")[0])):
            _t.sleep(2)
            self._confirm_oauth(drv)
            return "success"
        # 3b. Full Google web login: try the webview context, else the native tree.
        if email and pw and self._drive_google_web(drv, email, pw):
            return "success"
        # 4. Warm session / no chooser: poll for the final consent and confirm it.
        if self._confirm_oauth(drv):
            return "success"
        return "attempted"

    def _drive_google_web(self, drv, email: str, pw: str) -> bool:
        """Fill Google's email/password page. Prefers a WEBVIEW context (embedded
        WKWebView); falls back to the accessibility tree for the web-auth view."""
        import time as _t
        from appium.webdriver.common.appiumby import AppiumBy
        # Try switching into a web context.
        try:
            contexts = drv.contexts
            web = next((c for c in contexts if "WEBVIEW" in c), None)
            if web:
                drv.switch_to.context(web)
                try:
                    e = drv.find_element(AppiumBy.CSS_SELECTOR, "input[type=email], #identifierId")
                    e.send_keys(email)
                    drv.find_element(AppiumBy.ID, "identifierNext").click(); _t.sleep(2)
                    p = drv.find_element(AppiumBy.CSS_SELECTOR, "input[type=password], input[name=Passwd]")
                    p.send_keys(pw)
                    drv.find_element(AppiumBy.ID, "passwordNext").click(); _t.sleep(3)
                    return True
                finally:
                    drv.switch_to.context("NATIVE_APP")
        except Exception:
            try:
                drv.switch_to.context("NATIVE_APP")
            except Exception:
                pass
        # Fallback: the web-auth view sometimes exposes fields in the native tree.
        try:
            tf = self._find(drv, "XCUIElementTypeTextField")
            if tf:
                tf[0].send_keys(email)
                self._tap_label(drv, ("Next", "Weiter")); _t.sleep(2)
            sf = self._find(drv, "XCUIElementTypeSecureTextField")
            if sf:
                sf[0].send_keys(pw)
                self._tap_label(drv, ("Next", "Weiter", "Sign in")); _t.sleep(3)
                return True
        except Exception:
            return False
        return False

    def _exercise(self, drv, deadline: float, bundle_id: str | None = None,
                  stop_check=None) -> bool:
        """Tap through a few controls to trigger network, while watching liveness.
        Returns True if the app exited on its own (crash / anti-tamper) mid-window."""
        from appium.webdriver.common.appiumby import AppiumBy
        start = time.time()
        misses = 0  # consecutive informative "not running" polls (None is ignored)
        while time.time() < deadline:
            if stop_check is not None and stop_check():
                return False  # user hit Stop
            if bundle_id and (time.time() - start) > 8:
                state = is_app_running(bundle_id)
                if state is False:
                    misses += 1
                    if misses >= 2:
                        return True  # app died on its own
                elif state is True:
                    misses = 0
            try:
                buttons = drv.find_elements(AppiumBy.CLASS_NAME, "XCUIElementTypeButton")
                for b in buttons[:3]:
                    try:
                        b.click()
                        time.sleep(1)
                    except Exception:
                        continue
            except Exception:
                pass
            time.sleep(2)
        return False


def default_driver(credentials: dict[str, str] | None = None) -> UIDriver:
    """Cold launch by default (launch / wait / uninstall). Only use Appium when
    it is both explicitly enabled (APPIUM_ENABLED=1) and importable."""
    if CONFIG.appium.enabled:
        try:
            import appium  # noqa: F401
            return AppiumDriver(credentials=credentials)
        except ImportError:
            log.warning("APPIUM_ENABLED set but appium not installed; cold launch")
    return ColdLaunchDriver()
