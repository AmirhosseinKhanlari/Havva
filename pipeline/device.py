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
    crashed: bool = False
    crash_report: str = ""


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


def _pmd3() -> str:
    return CONFIG.test_device.pmd3_bin


def pmd3_available() -> bool:
    return bool(_pmd3()) and Path(_pmd3()).exists()


def ensure_tunnel(timeout: int = 30) -> "tuple[str, str] | None":
    """Start (once per process) a rootless native tunnel and return its RSD
    (host, port). Cached for the session; restarted if the process died."""
    global _tunnel_proc, _tunnel_rsd
    if _tunnel_proc is not None and _tunnel_proc.poll() is None and _tunnel_rsd:
        return _tunnel_rsd
    log_path = CONFIG.paths.work_dir / "pmd3_tunnel.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    f = log_path.open("w")
    try:
        _tunnel_proc = subprocess.Popen(
            [_pmd3(), "remote", "start-tunnel", "--native", "--udid", _udid()],
            stdout=f, stderr=subprocess.STDOUT, env=_xcrun_env())
    except FileNotFoundError:
        log.error("pymobiledevice3 not found at %s", _pmd3())
        return None
    atexit.register(stop_tunnel)
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
    global _tunnel_proc, _tunnel_rsd
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
    # is denied for the same ad-hoc apps its launch is.
    if pmd3_available() and _tunnel_rsd:
        run_cmd([_pmd3(), "developer", "dvt", "kill", str(pid),
                 "--rsd", _tunnel_rsd[0], _tunnel_rsd[1]], timeout=30, env=_xcrun_env())
        return
    run_cmd(["xcrun", "devicectl", "device", "process", "terminate",
             "--device", _udid(), "--pid", str(pid)], timeout=60, env=_xcrun_env())


def pull_container(bundle_id: str, remote: str, local: "str | Path") -> bool:
    """Pull `remote` (a path inside the app's data container) to `local` via
    house_arrest/AFC. Works over plain lockdown (no tunnel). Full-container
    access needs a dev-signed (get-task-allow) app; ad-hoc vends Documents only."""
    if not pmd3_available():
        return False
    local = Path(local)
    local.mkdir(parents=True, exist_ok=True)
    before = sum(1 for _ in local.rglob("*"))
    run_cmd([_pmd3(), "apps", "pull", bundle_id, remote, str(local), "--udid", _udid()],
            timeout=180, env=_xcrun_env())
    return sum(1 for _ in local.rglob("*")) > before


def is_app_running(bundle_id: str) -> bool:
    """True if an app with this bundle id is in the device's running-process
    list. Used by sideload detection: an app that detects re-signing often just
    exits (no crash log), so liveness is a better signal than crash reports."""
    if pmd3_available():
        rsd = ensure_tunnel()
        if rsd:
            p = run_cmd([_pmd3(), "developer", "dvt", "proclist", "--rsd", rsd[0], rsd[1]],
                        timeout=30, env=_xcrun_env())
            try:
                return any(e.get("bundleIdentifier") == bundle_id
                           for e in json.loads(p.stdout))
            except (ValueError, TypeError):
                return bundle_id in (p.stdout + p.stderr)
    out = CONFIG.paths.work_dir / "procs.json"
    run_cmd(["xcrun", "devicectl", "device", "info", "processes", "--device", _udid(),
             "--json-output", str(out)], timeout=60, env=_xcrun_env())
    try:
        data = json.loads(out.read_text())
        procs = data.get("result", {}).get("runningProcesses", [])
        return any(bundle_id in (pr.get("executable", "") or "") for pr in procs)
    except (OSError, ValueError):
        return False


def capture_syslog(seconds: int | None = None, during=None, grep: str = "OBSERVER",
                   on_line=None, stop_check=None) -> str:
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
            log.error("idevicesyslog not found (install libimobiledevice)")
            return ""
        _t.sleep(1)  # let the stream attach before the app runs
        try:
            if during is not None:
                during()
            elif on_line is not None:
                deadline = _t.time() + (seconds or CONFIG.runtime.monitor_seconds)
                with open(out, "r", errors="replace") as rf:
                    while _t.time() < deadline:
                        if stop_check is not None and stop_check():
                            break  # user hit Stop
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


def fetch_crash_report(bundle_id: str) -> str:
    """Copy crash reports off the device and return any matching this bundle."""
    dest = CONFIG.paths.work_dir / "crash"
    dest.mkdir(parents=True, exist_ok=True)
    run_cmd(["idevicecrashreport", "-u", _udid(), "-k", str(dest)], timeout=120)
    hits = []
    app_name = bundle_id.split(".")[-1].lower()
    for f in dest.rglob("*.ips"):
        try:
            txt = f.read_text(errors="replace")
        except OSError:
            continue
        if app_name in txt.lower() or bundle_id.lower() in txt.lower():
            hits.append(txt)
    for f in dest.rglob("*.crash"):
        try:
            txt = f.read_text(errors="replace")
        except OSError:
            continue
        if app_name in txt.lower() or bundle_id.lower() in txt.lower():
            hits.append(txt)
    return "\n\n".join(hits)


# ---- UI drivers -------------------------------------------------------------

class UIDriver(Protocol):
    def drive(self, bundle_id: str, duration: int, login: bool,
              prefer: str = "auto") -> DriveResult: ...


class ColdLaunchDriver:
    """Launch, wait, terminate. No UI interaction (paper-1 behavior)."""

    def drive(self, bundle_id: str, duration: int, login: bool,
              prefer: str = "auto") -> DriveResult:
        pid = launch(bundle_id, prefer=prefer)
        if pid is None:
            report = fetch_crash_report(bundle_id)
            return DriveResult(launched=False, crashed=bool(report), crash_report=report)
        time.sleep(duration)
        report = fetch_crash_report(bundle_id)
        terminate(pid, bundle_id)
        return DriveResult(launched=True, crashed=bool(report), crash_report=report)


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

    def _make_driver(self, bundle_id: str):
        from appium import webdriver
        from appium.options.ios import XCUITestOptions
        a = CONFIG.appium
        opts = XCUITestOptions()
        opts.udid = _udid()
        opts.bundle_id = bundle_id
        opts.platform_name = "iOS"
        opts.automation_name = "XCUITest"
        # WDA signing for a real (non-jailbroken) device.
        if a.xcode_org_id:
            opts.set_capability("appium:xcodeOrgId", a.xcode_org_id)
            opts.set_capability("appium:xcodeSigningId", a.xcode_signing_id)
        if a.wda_bundle_id:
            opts.set_capability("appium:updatedWDABundleId", a.wda_bundle_id)
        # Do not reinstall/relaunch the target; we manage install ourselves.
        opts.set_capability("appium:noReset", True)
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
              prefer: str = "auto") -> DriveResult:
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
                    return ColdLaunchDriver().drive(bundle_id, duration, login, prefer=prefer)
            else:
                log.warning("appium connect failed (%s); cold-launch fallback", e)
                return ColdLaunchDriver().drive(bundle_id, duration, login, prefer=prefer)

        login_status = "none"
        try:
            deadline = time.time() + duration
            if login and self.credentials:
                login_status = self._attempt_login(drv)
            if login_status == "success":
                # Logged in: stop driving the UI (further random taps could leave
                # the authenticated screen or hit 'log out'). Hold the session so
                # the app's post-login/gated requests still fire and get captured.
                log.info("login success; holding session (no further UI exercise)")
                time.sleep(max(0, deadline - time.time()))
            else:
                # Not logged in: tap through a few tabs / buttons to trigger network.
                self._exercise(drv, deadline)
        except Exception as e:
            log.info("appium drive note: %s", e)
        finally:
            try:
                drv.quit()
            except Exception:
                pass

        report = fetch_crash_report(bundle_id)
        return DriveResult(launched=True, login_status=login_status,
                           crashed=bool(report), crash_report=report)

    # ---- login orchestration -------------------------------------------

    def _attempt_login(self, drv) -> str:
        """Attempt login, polling while the UI settles (apps show a splash before
        the welcome/login screen). Each round: try the method; if nothing is there,
        try navigating a welcome screen into the login screen (Fitbod's 'Log In'
        next to 'START') and retry. Gives up after ~20s."""
        import time as _t
        _t.sleep(5)  # let the launch splash clear before the first attempt
        for _ in range(10):
            status = self._run_method(drv)
            if status != "none":
                return status
            if self._goto_login(drv):
                status = self._run_method(drv)
                if status != "none":
                    return status
            _t.sleep(2)
        return "none"

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
        Gmail (GV forwards texts there) and enter it. Returns attempted|none."""
        import time as _t
        from . import otp
        phone = self.credentials.get("phone", "")
        if not phone:
            return "none"
        fields = self._find(drv, "XCUIElementTypeTextField")
        if not fields:
            return "none"
        t0 = _t.time()
        try:
            fields[0].send_keys(phone)
        except Exception:
            return "attempted"
        self._tap_label(drv, ("Continue", "Next", "Send code", "Get code", "Send",
                              "Submit", "Verify", "Log In", "Sign In"))
        code = otp.fetch(after=t0, timeout=int(self.credentials.get("otp_timeout", 90)))
        if not code:
            return "attempted"
        _t.sleep(1)
        # Code entry: either one field, or N single-digit boxes.
        cfields = (self._find(drv, "XCUIElementTypeTextField")
                   + self._find(drv, "XCUIElementTypeSecureTextField"))
        try:
            if len(cfields) >= len(code):
                for i, ch in enumerate(code):
                    cfields[i].send_keys(ch)
            elif cfields:
                cfields[0].send_keys(code)
            else:
                return "attempted"
        except Exception:
            return "attempted"
        self._tap_label(drv, ("Continue", "Next", "Verify", "Submit", "Confirm",
                              "Log In", "Sign In"))
        return "attempted"

    # ---- helpers --------------------------------------------------------

    def _find(self, drv, class_name: str) -> list:
        from appium.webdriver.common.appiumby import AppiumBy
        try:
            return drv.find_elements(AppiumBy.CLASS_NAME, class_name)
        except Exception:
            return []

    def _tap_label(self, drv, labels: tuple[str, ...]) -> bool:
        """Tap the first button/element whose label or name matches any of labels
        (exact accessibility id, then a CONTAINS predicate for robustness)."""
        from appium.webdriver.common.appiumby import AppiumBy
        for label in labels:
            try:
                els = drv.find_elements(AppiumBy.ACCESSIBILITY_ID, label)
                if els:
                    els[0].click()
                    return True
            except Exception:
                pass
        for label in labels:
            try:
                pred = (f"(type == 'XCUIElementTypeButton' OR type == 'XCUIElementTypeStaticText' "
                        f"OR type == 'XCUIElementTypeOther') AND (label CONTAINS[c] '{label}' "
                        f"OR name CONTAINS[c] '{label}')")
                els = drv.find_elements(AppiumBy.IOS_PREDICATE, pred)
                if els:
                    els[0].click()
                    return True
            except Exception:
                pass
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

    def _exercise(self, drv, deadline: float) -> None:
        from appium.webdriver.common.appiumby import AppiumBy
        while time.time() < deadline:
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
