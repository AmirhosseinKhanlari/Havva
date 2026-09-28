"""Stage E/6: MITM capture via Proxyman + HAR parsing.

Proxyman is driven by its CLI (clear-session, export-log -f har), the same
control pattern as paper 1. The parsing half is pure and tested: it turns a HAR
into the set of non-excluded hosts the app talked to, which is exactly what the
success oracle compares across configs.
"""

from __future__ import annotations

import base64
import gzip
import json
import time
import zlib
from pathlib import Path
from urllib.parse import urlparse

from .config import CONFIG
from .models import Flow
from .util import get_logger, run_cmd

log = get_logger("capture", CONFIG.paths.log_dir)


# ---- Pure parsing (tested) --------------------------------------------------

def host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_excluded(host: str, excluded: list[str] | None = None) -> bool:
    excluded = excluded if excluded is not None else CONFIG.runtime.excluded_hosts
    host = host.lower()
    return any(host == e or host.endswith("." + e) for e in excluded)


def _decode_body(content: dict) -> str:
    text = content.get("text", "") or ""
    if not text:
        return ""
    if content.get("encoding") == "base64":
        try:
            raw = base64.b64decode(text)
            for dec in (lambda b: gzip.decompress(b),
                        lambda b: zlib.decompress(b),
                        lambda b: b):
                try:
                    return dec(raw).decode("utf-8", "replace")
                except Exception:
                    continue
        except Exception:
            return ""
    return text


def _headers_to_dict(headers: list) -> dict[str, str]:
    return {h.get("name", "").lower(): h.get("value", "") for h in headers or []}


def har_to_flows(har: dict, device_ip: str = "") -> list[Flow]:
    """Convert a parsed HAR into Flow objects, optionally filtered to the device."""
    flows: list[Flow] = []
    for entry in har.get("log", {}).get("entries", []):
        client = (entry.get("_clientAddress") or entry.get("clientAddress")
                  or entry.get("serverIPAddress") or "")
        if device_ip and client and device_ip not in client:
            # Keep only device traffic when we know its IP.
            continue
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = req.get("url", "")
        flows.append(Flow(
            url=url, method=req.get("method", ""), status=resp.get("status", 0),
            host=host_from_url(url),
            request_headers=_headers_to_dict(req.get("headers")),
            response_headers=_headers_to_dict(resp.get("headers")),
            request_body=(req.get("postData", {}) or {}).get("text", "") or "",
            response_body=_decode_body(resp.get("content", {}) or {}),
        ))
    return flows


def app_hosts(flows: list[Flow], excluded: list[str] | None = None) -> set[str]:
    """Non-excluded hosts the app actually reached (the oracle's comparison set)."""
    return {f.host for f in flows if f.host and not is_excluded(f.host, excluded)}


def reached_any_network(flows: list[Flow]) -> bool:
    return any(f.host for f in flows)


# ---- Proxyman control (I/O) -------------------------------------------------

def _cli() -> str:
    return CONFIG.proxyman.cli


def clear_session() -> None:
    run_cmd([_cli(), "clear-session"], timeout=30)


def export_har(path: Path, retries: int = 3) -> bool:
    """Export the current session to HAR. Proxyman's CLI sometimes reports a
    timeout but writes the file anyway, so we check the file, not the exit code."""
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(retries):
        run_cmd([_cli(), "export-log", "-f", "har", "-o", str(path)], timeout=30)
        if path.exists() and path.stat().st_size > 0:
            return True
        time.sleep(1)
    return path.exists() and path.stat().st_size > 0


def check_connection() -> bool:
    """Verify Proxyman is listening; try to recover it once if not."""
    port = CONFIG.proxyman.port
    if run_cmd(["lsof", "-i", f":{port}"], timeout=10).stdout.strip():
        return True
    run_cmd(["open", "-a", "Proxyman"], timeout=15)
    time.sleep(5)
    return bool(run_cmd(["lsof", "-i", f":{port}"], timeout=10).stdout.strip())


def load_har(path: str | Path) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}
