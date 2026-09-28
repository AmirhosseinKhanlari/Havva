"""Shared utilities: subprocess runner and logging."""

from __future__ import annotations

import logging
import subprocess
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
