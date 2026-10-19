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
import re
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


_ADDR_TOKEN_RE = re.compile(r"[0-9A-Fa-f:.]+")


def _client_matches(client: str, device_ip: str) -> bool:
    """Exact address match: '192.168.1.17' must not accept '192.168.1.170'.
    The HAR field may carry a port or brackets, so compare address tokens."""
    for tok in _ADDR_TOKEN_RE.findall(client or ""):
        if "." in tok and ":" in tok:          # IPv4:port
            tok = tok.split(":", 1)[0]
        if tok == device_ip:
            return True
    return False


def har_to_flows(har: dict, device_ip: str = "") -> list[Flow]:
    """Convert a parsed HAR into Flow objects, optionally filtered to the device.
    Proxyman writes the client as `_clientAddress`; an entry that carries NO
    client field is kept (unknown is not 'another client'), never judged by
    its server address."""
    flows: list[Flow] = []
    for entry in har.get("log", {}).get("entries", []):
        client = entry.get("_clientAddress") or entry.get("clientAddress") or ""
        if device_ip and client and not _client_matches(client, device_ip):
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
            started=str(entry.get("startedDateTime") or ""),
        ))
    return flows


def _scheme(url: str) -> str:
    try:
        return (urlparse(url).scheme or "").lower()
    except ValueError:
        return ""


def app_hosts(flows: list[Flow], excluded: list[str] | None = None,
              schemes: tuple[str, ...] = ("https", "wss")) -> set[str]:
    """Non-excluded TLS hosts the app actually reached (the oracle's comparison
    set). Cleartext flows are excluded by default: a plain-HTTP beacon, an ATS
    exception or an OCSP fetch says nothing about certificate pinning, so it
    must not make an app 'not pinned'. See cleartext_hosts()."""
    return {f.host for f in flows
            if f.host and not is_excluded(f.host, excluded) and _scheme(f.url) in schemes}


def cleartext_hosts(flows: list[Flow], excluded: list[str] | None = None) -> set[str]:
    """Non-excluded hosts reached over plain HTTP (reported, never a pinning verdict)."""
    return app_hosts(flows, excluded, schemes=("http", "ws"))


def reached_any_network(flows: list[Flow], excluded: list[str] | None = None) -> bool:
    """Did the app reach any NON-excluded host? Apple/iCloud/CDN background
    traffic is always present on the device, so counting every host would make
    this trivially True and let a tamper exit masquerade as 'ran'."""
    return any(f.host and not is_excluded(f.host, excluded) for f in flows)


# ---- Device-side TLS rejection signal (pure parsing) -----------------------
# When an app rejects the proxy's certificate, nothing reaches the HAR (no
# flow) and Proxyman's trace is just an early-closed upstream. The one place
# the rejection IS recorded, with the process that did it, is the device
# syslog: CFNetwork logs the task failure code and libboringssl logs the
# handshake error, both under the app's process name. Codes:
#   -1202  NSURLErrorServerCertificateUntrusted   (default handling rejected us)
#   -1200  NSURLErrorSecureConnectionFailed        (TLS failed, e.g. fatal alert)
#   -1012  NSURLErrorUserCancelledAuthentication   (challenge rejected)
#    -999  NSURLErrorCancelled: what TrustKit / Alamofire / a delegate produce
#          when they cancel the challenge on a pin mismatch, but also plain
#          user navigation, so it is tallied separately as 'cancelled'.
_SYSLOG_PROC_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d\s+\S+\s+([^\s\[(]+)(?:\(([^)]*)\))?\[\d+\]")
_CF_CODE_RE = re.compile(r"error code:\s*(-\d+)")
_NSERR_CODE_RE = re.compile(r"NSURLErrorDomain Code=(-\d+)")
_FAIL_URL_RE = re.compile(r"NSErrorFailingURL(?:String)?Key=(https?://[^\s,}>]+)")
_PRETEND_RE = re.compile(r"pretending to be [\u201c\"']([A-Za-z0-9.-]+)")
_TLS_REJECT_CODES = frozenset({"-1202", "-1200", "-1012"})
_CANCEL_CODES = frozenset({"-999"})
_BORINGSSL_MARKERS = ("certificate_verify_failed", "certificate verify failed",
                      "bad_certificate", "bad certificate", "unknown_ca", "unknown ca",
                      "errsslxcertchaininvalid")


def tls_rejections(syslog_text: str, process_names=None) -> dict:
    """Tally TLS rejections in a syslog capture, attributed to `process_names`
    (the app's CFBundleExecutable; no filter when empty). Returns
      rejected  : lines with a definite certificate / handshake rejection
      cancelled : -999 challenge cancellations (weak; pin libraries use it)
      codes     : per-code counts
      hosts     : hosts named in the error (often <private>-redacted on iOS)
      samples   : up to 5 matching lines
    Positive evidence only: zero rejections never proves 'not pinned'."""
    procs = {p.lower() for p in (process_names or []) if p}
    res = {"rejected": 0, "cancelled": 0, "codes": {}, "hosts": [], "samples": []}
    hosts: set[str] = set()
    for line in (syslog_text or "").splitlines():
        m = _SYSLOG_PROC_RE.match(line)
        if procs and (not m or m.group(1).lower() not in procs):
            continue
        low = line.lower()
        cm = _CF_CODE_RE.search(line) or _NSERR_CODE_RE.search(line)
        code = cm.group(1) if cm else None
        is_reject = code in _TLS_REJECT_CODES or any(k in low for k in _BORINGSSL_MARKERS)
        is_cancel = code in _CANCEL_CODES
        if not (is_reject or is_cancel):
            continue
        key = code or "boringssl"
        res["codes"][key] = res["codes"].get(key, 0) + 1
        if is_reject:
            res["rejected"] += 1
        else:
            res["cancelled"] += 1
        hm = _FAIL_URL_RE.search(line) or _PRETEND_RE.search(line)
        if hm:
            val = hm.group(1)
            h = host_from_url(val) if val.startswith("http") else val.lower()
            if h and not is_excluded(h):
                hosts.add(h)
        if len(res["samples"]) < 5:
            res["samples"].append(line.strip()[:200])
    res["hosts"] = sorted(hosts)
    return res


# ---- Proxyman control (I/O) -------------------------------------------------

def _cli() -> str:
    return CONFIG.proxyman.cli


def clear_session() -> None:
    run_cmd([_cli(), "clear-session"], timeout=30)


def export_har(path: Path, retries: int = 3) -> bool:
    """Export the current session to HAR. Proxyman's CLI sometimes reports a
    timeout but writes the file anyway, so we check the file, not the exit code."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never let a failed export silently hand back the PREVIOUS run's file.
    path.unlink(missing_ok=True)
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
    # Remove the previous run's file(s) first, and only accept a file whose
    # mtime is at/after the export started, so a failed export can never hand
    # back a stale session. int() floors the timestamp for 1s-resolution FSs.
    started = int(time.time())
    for stale in list(path.parent.glob(path.name + "*")) + [path]:
        try:
            if stale.is_file():
                stale.unlink()
        except OSError:
            pass

    def _fresh(p: Path) -> bool:
        try:
            st = p.stat()
        except OSError:
            return False
        return st.st_size > 0 and st.st_mtime >= started

    def _written() -> Path | None:
        if _fresh(path):
            return path
        hits = sorted(h for h in path.parent.glob(path.name + "*") if _fresh(h))
        return hits[-1] if hits else None

    for _ in range(retries):
        run_cmd([_cli(), "export-log", "-f", "proxymansession", "-o", str(path)], timeout=30)
        got = _written()
        if got:
            return got
        time.sleep(1)
    return _written()


_TLS_FAILURE_MARKERS = ("tls", "handshake", "certificate", "ssl")
_DNS_FAILURE_MARKERS = ("dns", "resolve")
# Orderly TLS close alerts are not handshake failures.
_BENIGN_TLS_MARKERS = ("close_notify", "close notify")


def _classify_trace(trace: dict) -> tuple[str, str]:
    """Classify one ConnectionTrace -> (host, outcome). Outcomes:
      decrypted  : upstream TLS completed and the connection did not fail.
      pinned     : state is 'failed' AND the failure reason (error-event detail)
                   names TLS / handshake / certificate / SSL and is not a DNS
                   error or an orderly close_notify. Weak signal, see below.
      unresolved : the trace has no 'resolved' DNS event at all.
      connect_failed : resolved, but failed before a TCP connection existed.
      unknown    : none of the above (incl. failed-after-TLS-complete, e.g. the
                   ubiquitous 'uncleanShutdown').

    LIMITATION: ConnectionTraces describe Proxyman's UPSTREAM leg (Mac -> origin
    server), not the client leg (app -> Proxyman), and carry no client
    attribution. An app that rejects our CA aborts its own handshake with
    Proxyman; upstream that merely looks like a connection Proxyman closed
    early ('uncleanShutdown' / 'closed'), which is indistinguishable from a
    normal short-lived connection or another app's traffic on the same device
    IP. So classification is deliberately conservative: a trace is never
    'decrypted' when its state is 'failed', and 'pinned' requires an explicit
    TLS-flavoured failure reason. Treat 'pinned' as a lead, not a verdict.
    """
    host = (trace.get("resolvedHost") or trace.get("host") or "").lower()
    events = trace.get("events", []) or []
    kinds = [e.get("kind") for e in events]
    state = str(trace.get("state") or "").lower()
    failed = state == "failed"
    # Only the failure reason(s), NOT every tlsMessage's "handshake" detail.
    err_text = " ".join(str(e.get("detail", "")) for e in events
                        if e.get("kind") == "error").lower()

    if not host:
        return "", "unknown"
    if not events:
        return host, "unknown"
    if "resolved" not in kinds:
        return host, "unresolved"

    tls_complete = "tlsComplete" in kinds
    connected = "connected" in kinds
    had_error = "error" in kinds

    if tls_complete and not failed:
        return host, "decrypted"

    dns_err = any(m in err_text for m in _DNS_FAILURE_MARKERS)
    tls_err = (any(m in err_text for m in _TLS_FAILURE_MARKERS)
               and not any(m in err_text for m in _BENIGN_TLS_MARKERS))
    if failed and tls_err and not dns_err:
        return host, "pinned"
    if not connected and (had_error or failed):
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
    a TLS-flavoured failure; else 'connect_failed'/'unresolved'/'unknown'.
    Excluded (Apple/CDN) hosts are dropped -- they are tunneled by our exclude
    list, not pinned by the app.

    See _classify_trace for the big caveat: traces are the upstream leg with no
    client attribution, so 'pinned' here is a lead to confirm, not proof."""
    priority = {"decrypted": 4, "pinned": 3, "connect_failed": 2,
                "unresolved": 1, "unknown": 0}
    best: dict[str, str] = {}
    for host, outcome in parse_session(path):
        if is_excluded(host, excluded):
            continue
        if host not in best or priority[outcome] > priority[best[host]]:
            best[host] = outcome
    return best
