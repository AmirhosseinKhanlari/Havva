"""Shared utilities: subprocess runner and logging."""

from __future__ import annotations

import logging
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Proc:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


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
        return Proc(124, e.stdout or "" if isinstance(e.stdout, str) else "",
                    f"timeout after {timeout}s")
    except FileNotFoundError as e:
        return Proc(127, "", str(e))


def run_cmd_streamed(cmd: list[str] | str, timeout: int = 900,
                     cwd: Path | None = None, env: dict | None = None,
                     echo: bool = True) -> Proc:
    """Like run_cmd, but streams the child's output live to the terminal (so a
    tool's own progress bar / carriage-return updates are visible) while still
    capturing it for parsing. stderr is merged into stdout. Never raises."""
    shell = isinstance(cmd, str)
    try:
        p = subprocess.Popen(
            cmd, shell=shell, cwd=str(cwd) if cwd else None, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
        )
    except FileNotFoundError as e:
        return Proc(127, "", str(e))

    chunks: list[bytes] = []

    def _pump():
        assert p.stdout is not None
        for chunk in iter(lambda: p.stdout.read(4096), b""):
            chunks.append(chunk)
            if echo:
                try:
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.flush()
                except Exception:
                    pass

    t = threading.Thread(target=_pump, daemon=True)
    t.start()
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
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


def get_logger(name: str, log_dir: Path | None = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
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
