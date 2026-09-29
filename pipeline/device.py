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

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .config import CONFIG
from .util import get_logger, run_cmd

log = get_logger("device", CONFIG.paths.log_dir)


@dataclass
class DriveResult:
    launched: bool
    login_status: str = "none"   # none | attempted | success | not_needed
    crashed: bool = False
    crash_report: str = ""


# ---- Low-level device ops ---------------------------------------------------

def _udid() -> str:
    return CONFIG.test_device.udid


def install_ipa(signed_ipa: str | Path) -> tuple[bool, str]:
    p = run_cmd(["ideviceinstaller", "-u", _udid(), "-i", str(signed_ipa)], timeout=300)
    ok = p.ok and "Complete" in (p.stdout + p.stderr)
    return ok, (p.stderr or p.stdout)[:300]


def uninstall(bundle_id: str) -> None:
    run_cmd(["ideviceinstaller", "-u", _udid(), "-U", bundle_id], timeout=120)


def launch(bundle_id: str) -> int | None:
    """Launch via devicectl; return the pid or None."""
    out = CONFIG.paths.work_dir / f"launch_{bundle_id}.json"
    p = run_cmd(["xcrun", "devicectl", "device", "process", "launch",
                 "--device", _udid(), bundle_id, "--json-output", str(out)], timeout=120)
    try:
        data = json.loads(out.read_text())
        pid = data.get("result", {}).get("process", {}).get("processIdentifier")
        return int(pid) if pid else None
    except (OSError, ValueError, TypeError):
        if "running" in (p.stdout + p.stderr).lower():
            return -1  # launched but pid not parsed
        return None


def terminate(pid: int, bundle_id: str = "") -> None:
    if pid and pid > 0:
        run_cmd(["xcrun", "devicectl", "device", "process", "terminate",
                 "--device", _udid(), "--pid", str(pid)], timeout=60)


def capture_syslog(seconds: int | None = None, during=None, grep: str = "OBSERVER") -> str:
    """Stream the device syslog over USB (no jailbreak) while either sleeping
    `seconds` or running the `during` callable, returning lines matching `grep`.
    Used to read the AttestObserver marker trail while the app is exercised."""
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
    def drive(self, bundle_id: str, duration: int, login: bool) -> DriveResult: ...


class ColdLaunchDriver:
    """Launch, wait, terminate. No UI interaction (paper-1 behavior)."""

    def drive(self, bundle_id: str, duration: int, login: bool) -> DriveResult:
        pid = launch(bundle_id)
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

    def drive(self, bundle_id: str, duration: int, login: bool) -> DriveResult:
        try:
            drv = self._make_driver(bundle_id)
        except Exception as e:
            log.warning("appium connect failed (%s); cold-launch fallback", e)
            return ColdLaunchDriver().drive(bundle_id, duration, login)

        login_status = "none"
        try:
            deadline = time.time() + duration
            if login and self.credentials:
                login_status = self._attempt_login(drv)
            # Exercise: tap through a few tabs / buttons to trigger network.
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
        """Try native email/password first; if there is no form, try the
        'Sign in with Google' flow. Returns none|attempted|success."""
        method = self.credentials.get("method", "auto")
        if method in ("auto", "native"):
            status = self._login_native(drv)
            if status != "none":
                return status
        if method in ("auto", "google"):
            return self._login_google(drv)
        return "none"

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
            self._tap_label(drv, ("Continue", "Allow", "Weiter"))
            return "success"
        # 3b. Full Google web login: try the webview context, else the native tree.
        if email and pw and self._drive_google_web(drv, email, pw):
            return "success"
        # 4. Final consent if a session already existed.
        self._tap_label(drv, ("Continue", "Allow"))
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
    """Use Appium if importable, else cold launch."""
    try:
        import appium  # noqa: F401
        return AppiumDriver(credentials=credentials)
    except ImportError:
        return ColdLaunchDriver()
