"""Shared utilities: subprocess runner and logging."""

from __future__ import annotations

import logging
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path


# Helper threads spawned on behalf of a caller (e.g. the output pump below)
# register their parent here, so a per-job log filter (web/jobs.py) can accept
# records from a job's own helper threads and still reject other jobs' lines.
_THREAD_PARENT: dict[int, int] = {}
_THREAD_PARENT_LOCK = threading.Lock()


def register_child_thread(parent_ident: int) -> None:
    """Call from inside a helper thread to mark `parent_ident` as its parent."""
    with _THREAD_PARENT_LOCK:
        _THREAD_PARENT[threading.get_ident()] = parent_ident


def unregister_child_thread() -> None:
    with _THREAD_PARENT_LOCK:
        _THREAD_PARENT.pop(threading.get_ident(), None)


def is_thread_descendant(ident: int, ancestor: int) -> bool:
    """True if `ident` is `ancestor` or a registered descendant of it."""
    seen = set()
    while ident is not None and ident not in seen:
        if ident == ancestor:
            return True
        seen.add(ident)
        with _THREAD_PARENT_LOCK:
            ident = _THREAD_PARENT.get(ident)
    return False


@dataclass
class Proc:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _as_text(data) -> str:
    """Normalize subprocess output (bytes, str, or None) to str."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data)


def run_cmd(cmd: list[str] | str, timeout: int = 120, cwd: Path | None = None,
            env: dict | None = None) -> Proc:
    """Run a command with a hard timeout; never raises on nonzero or timeout."""
    shell = isinstance(cmd, str)
    try:
        r = subprocess.run(
            cmd, shell=shell, cwd=str(cwd) if cwd else None, env=env,
            capture_output=True, text=True, timeout=timeout,
        )
        return Proc(r.returncode, r.stdout or "", r.stderr or "")
    except subprocess.TimeoutExpired as e:
        # TimeoutExpired.stdout is bytes even with text=True; decode it so the
        # partial output is returned instead of being discarded.
        return Proc(124, _as_text(e.stdout), f"timeout after {timeout}s")
    except FileNotFoundError as e:
        return Proc(127, "", str(e))


def run_cmd_streamed(cmd: list[str] | str, timeout: int = 900,
                     cwd: Path | None = None, env: dict | None = None,
                     echo: bool = True, line_cb=None) -> Proc:
    """Like run_cmd, but streams the child's output live to the terminal (so a
    tool's own progress bar / carriage-return updates are visible) while still
    capturing it for parsing. stderr is merged into stdout. Never raises.

    If `line_cb` is given, it is called with each complete output line (newline
    terminated) as it arrives, so a caller can forward the child's live output
    somewhere else (e.g. a logger that a web job console tails). Carriage-return
    progress updates are collapsed to the final state of the line, so a progress
    bar does not flood the callback."""
    shell = isinstance(cmd, str)
    try:
        p = subprocess.Popen(
            cmd, shell=shell, cwd=str(cwd) if cwd else None, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
    except FileNotFoundError as e:
        return Proc(127, "", str(e))

    chunks: list[bytes] = []
    caller_ident = threading.get_ident()

    def _pump():
        register_child_thread(caller_ident)   # line_cb logs count as the caller's
        try:
            _pump_inner()
        finally:
            unregister_child_thread()

    def _pump_inner():
        assert p.stdout is not None
        buf = ""
        for chunk in iter(lambda: p.stdout.read(4096), b""):
            chunks.append(chunk)
            if echo:
                try:
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.flush()
                except Exception:
                    pass
            if line_cb is not None:
                buf += chunk.decode("utf-8", "replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    _emit_line(line, line_cb)
        # Flush the final, unterminated line (e.g. a prompt or a tool that
        # exits without a trailing newline) so it is not silently dropped.
        if line_cb is not None and buf:
            _emit_line(buf, line_cb)

    t = threading.Thread(target=_pump, daemon=True)
    t.start()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            p.wait(timeout=5)       # reap; never leave a zombie behind
        except Exception:
            pass
        t.join(timeout=2)
        return Proc(124, b"".join(chunks).decode("utf-8", "replace"),
                    f"timeout after {timeout}s")
    t.join(timeout=2)
    if echo:
        try:
            sys.stderr.write("\n")
            sys.stderr.flush()
        except Exception:
            pass
    return Proc(p.returncode, b"".join(chunks).decode("utf-8", "replace"), "")


def _emit_line(line: str, line_cb) -> None:
    """Deliver one output line to `line_cb`: strip a CRLF's trailing "\\r" first
    (so "foo\\r\\n" yields "foo", not ""), then collapse carriage-return progress
    updates to the final state of the line."""
    if line.endswith("\r"):
        line = line[:-1]
    if "\r" in line:          # keep only the final progress state
        line = line.rsplit("\r", 1)[-1]
    line = line.rstrip()
    if line:
        try:
            line_cb(line)
        except Exception:
            pass


def get_logger(name: str, log_dir: Path | None = None) -> logging.Logger:
    """Module logger at INFO with a stderr handler (+ file handler under
    `log_dir`). Initialized once per name; the marker (not "has handlers") is
    checked so a foreign handler attached earlier, e.g. a web job's log tee,
    cannot prevent the level/handlers from being set up."""
    logger = logging.getLogger(name)
    if getattr(logger, "_havva_initialized", False):
        return logger
    logger._havva_initialized = True  # type: ignore[attr-defined]
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / f"{name}.log")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger
