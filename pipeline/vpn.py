"""OpenVPN IP rotation for scans that Apple rate-limits (idea from paper 1).

Cycles through the NordVPN .ovpn configs in the openvpn dir, tracking position in
rotate.progress. Requires `openvpn` and sudo (it sets routes). Used by the IAP
scan: when a chunk shows heavy throttling, rotate to a fresh exit IP and continue.

Because this needs sudo and changes the host's network, the pipeline never calls
it silently; it is opt-in via --rotate-vpn, and the caller runs with privileges.
"""

from __future__ import annotations

import glob
import os
import time
from pathlib import Path

import requests

from .config import CONFIG
from .util import get_logger, run_cmd

log = get_logger("vpn", CONFIG.paths.log_dir)

OPENVPN_DIR = Path(os.environ.get("OPENVPN_DIR", str(CONFIG.paths.root.parent / "openvpn")))
OPENVPN_AUTH = Path(os.environ.get("OPENVPN_AUTH", str(OPENVPN_DIR / "auth.txt")))
STATE_FILE = OPENVPN_DIR / "rotate.progress"


def configs() -> list[str]:
    return sorted(glob.glob(str(OPENVPN_DIR / "*.ovpn")))


def public_ip() -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            return requests.get(url, timeout=10).text.strip()
        except requests.RequestException:
            continue
    return ""


def disconnect() -> None:
    run_cmd(["sudo", "pkill", "-f", "openvpn"], timeout=15)
    time.sleep(2)


def _next_index() -> int:
    try:
        return int(STATE_FILE.read_text().strip())
    except (OSError, ValueError):
        return -1


def _save_index(i: int) -> None:
    try:
        STATE_FILE.write_text(str(i))
    except OSError:
        pass


def connect(config: str, timeout: int = 45) -> str:
    """Bring up a tunnel; return the new public IP (empty on failure)."""
    if not OPENVPN_AUTH.exists():
        log.error("openvpn auth file missing: %s", OPENVPN_AUTH)
        return ""
    before = public_ip()
    disconnect()
    logf = CONFIG.paths.log_dir / "openvpn.log"
    run_cmd(["sudo", "openvpn", "--config", config, "--auth-user-pass", str(OPENVPN_AUTH),
             "--daemon", "--log", str(logf)], timeout=20)
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(3)
        ip = public_ip()
        if ip and ip != before:
            log.info("vpn up: %s via %s", ip, Path(config).name)
            return ip
    log.warning("vpn did not come up for %s", Path(config).name)
    return ""


def rotate() -> str:
    """Advance to the next config and connect. Returns the new IP (empty on fail)."""
    cfgs = configs()
    if not cfgs:
        log.error("no .ovpn configs in %s", OPENVPN_DIR)
        return ""
    idx = (_next_index() + 1) % len(cfgs)
    for _ in range(len(cfgs)):
        ip = connect(cfgs[idx])
        if ip:
            _save_index(idx)
            return ip
        idx = (idx + 1) % len(cfgs)
    return ""


def available() -> bool:
    return bool(configs()) and OPENVPN_AUTH.exists()
