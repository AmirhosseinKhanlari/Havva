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

    def _attempt_login(self, drv) -> str:
        from appium.webdriver.common.appiumby import AppiumBy
        user = self.credentials.get("username", "")
        pw = self.credentials.get("password", "")
        if not (user and pw):
            return "none"
        try:
            fields = drv.find_elements(AppiumBy.CLASS_NAME, "XCUIElementTypeTextField")
            secure = drv.find_elements(AppiumBy.CLASS_NAME, "XCUIElementTypeSecureTextField")
            if fields and secure:
                fields[0].send_keys(user)
                secure[0].send_keys(pw)
                for label in ("Log In", "Sign In", "Login", "Continue", "Sign in"):
                    btns = drv.find_elements(AppiumBy.ACCESSIBILITY_ID, label)
                    if btns:
                        btns[0].click()
                        return "attempted"
                return "attempted"
        except Exception:
            return "attempted"
        return "none"

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
