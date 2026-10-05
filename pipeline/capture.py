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
import zipfile
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


# ---- Native session (ConnectionTraces) --------------------------------------
# HAR/raw only hold DECRYPTED transactions. Proxyman's native .proxymansession
# is a zip whose ConnectionTraces/trace_* record every connection's TLS
# handshake -- including ones that never decrypted (tunneled / client-aborted).
# That is the only export that reveals a host the app reached but whose pinning
# defeated our MITM, so it is how we catch pinning that a bypass can't break.


def export_session(path: Path, retries: int = 3) -> Path | None:
    """Export the current session in native (.proxymansession) format. Proxyman
    appends a version suffix (e.g. 'v2'), so return the file it actually wrote."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def _written() -> Path | None:
        if path.exists() and path.stat().st_size > 0:
            return path
        hits = sorted(path.parent.glob(path.name + "*"))
        hits = [h for h in hits if h.stat().st_size > 0]
        return hits[-1] if hits else None

    for _ in range(retries):
        run_cmd([_cli(), "export-log", "-f", "proxymansession", "-o", str(path)], timeout=30)
        got = _written()
        if got:
            return got
        time.sleep(1)
    return _written()


def _classify_trace(trace: dict) -> tuple[str, str]:
    """Classify one ConnectionTrace -> (host, outcome). Outcomes:
      decrypted  : TLS MITM handshake completed -> we saw plaintext.
      pinned     : TCP connected + TLS started, but the client aborted the
                   handshake before completion (no DNS/connect failure) ->
                   the app rejected our CA (pinning our MITM couldn't break).
      unresolved : DNS could not resolve the host (dead / sinkholed endpoint).
      connect_failed : reached DNS but never established a TCP connection.
      unknown    : none of the above.
    """
    host = (trace.get("resolvedHost") or trace.get("host") or "").lower()
    events = trace.get("events", []) or []
    kinds = [e.get("kind") for e in events]
    details = " ".join(str(e.get("detail", "")) for e in events).lower()

    tls_complete = "tlsComplete" in kinds
    tls_started = "tlsMessage" in kinds
    connected = "connected" in kinds
    had_error = "error" in kinds
    dns_failed = ("resolve" in details or "dns error" in details) and not connected

    if not host:
        return "", "unknown"
    if tls_complete:
        return host, "decrypted"
    if dns_failed:
        return host, "unresolved"
    if connected and tls_started and not tls_complete:
        # TLS negotiation began against our cert and was torn down first.
        return host, "pinned"
    if not connected and had_error:
        return host, "connect_failed"
    return host, "unknown"


def parse_session(path: str | Path) -> list[tuple[str, str]]:
    """Read a .proxymansession zip -> [(host, outcome), ...] per connection."""
    out: list[tuple[str, str]] = []
    try:
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if "ConnectionTraces/trace_" in n]
            for n in names:
                try:
                    trace = json.loads(z.read(n))
                except (ValueError, OSError):
                    continue
                host, outcome = _classify_trace(trace)
                if host:
                    out.append((host, outcome))
    except (zipfile.BadZipFile, OSError):
        return []
    return out


def session_host_outcomes(path: str | Path,
                          excluded: list[str] | None = None) -> dict[str, str]:
    """Aggregate per-host outcome across a session's connections. A host with
    any decrypted connection is 'decrypted'; else 'pinned' if any connection was
    a pinning abort; else 'unresolved'/'connect_failed'/'unknown'. Excluded
    (Apple/CDN) hosts are dropped -- they are tunneled by our exclude list, not
    pinned by the app."""
    priority = {"decrypted": 4, "pinned": 3, "connect_failed": 2,
                "unresolved": 1, "unknown": 0}
    best: dict[str, str] = {}
    for host, outcome in parse_session(path):
        if is_excluded(host, excluded):
            continue
        if host not in best or priority[outcome] > priority[best[host]]:
            best[host] = outcome
    return best
