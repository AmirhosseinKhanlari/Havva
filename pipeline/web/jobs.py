"""In-process job manager: thread pool for non-device work + a single lock for
device-bound stages. Backed by the DB jobs table; streams logs for SSE."""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Callable, Iterator

from ..db import Database

# Long-running device helpers that a device-bound job blocks inside and that do
# NOT poll the cancel flag (they are external processes). On cancel we terminate
# these so the blocking phase unwinds promptly. Only the job that currently
# holds the device lock (`_device_job_id`) triggers this, and the patterns are
# scoped to the configured test device's udid when it is known, so a manual
# `idevicesyslog` for another device or an unrelated xcodebuild is left alone.
# The shared Appium server and usbmuxd are NOT in this list on purpose.
_DEVICE_HELPER_PATTERNS = (
    "xcodebuild build-for-testing.*WebDriverAgent",
    "idevicesyslog",
)

_TERMINAL = ("done", "failed", "cancelled")


def _device_udid() -> str:
    """The test device udid from CONFIG (env TEST_DEVICE_UDID), '' if unknown."""
    try:
        from ..config import CONFIG
        udid = CONFIG.test_device.udid or ""
    except Exception:  # noqa: BLE001
        udid = ""
    udid = udid or os.environ.get("TEST_DEVICE_UDID", "")
    return udid if _UDID_RE.fullmatch(udid or "") else ""


_UDID_RE = re.compile(r"[A-Za-z0-9-]{8,64}")


def device_helper_patterns(udid: str | None = None) -> tuple[str, ...]:
    """pkill -f patterns, scoped to `udid` when known. A udid is only letters,
    digits and '-', none of which is special to pkill's regex, so it is embedded
    verbatim; anything else falls back to the unscoped patterns."""
    udid = _device_udid() if udid is None else udid
    if not udid or not _UDID_RE.fullmatch(udid):
        return _DEVICE_HELPER_PATTERNS
    return (f"xcodebuild build-for-testing.*WebDriverAgent.*-destination id={udid}",
            f"xcodebuild.*-destination id={udid}.*WebDriverAgent",
            f"idevicesyslog.*-u {udid}")


class JobCancelled(Exception):
    pass


class JobContext:
    def __init__(self, mgr: "JobManager", job_id: int):
        self._mgr = mgr
        self.job_id = job_id

    @property
    def cancelled(self) -> bool:
        return self._mgr._is_cancelled(self.job_id)

    def log(self, text: str) -> None:
        if not text:
            return
        self._mgr._append_log(self.job_id, text)

    def progress(self, pct: int) -> None:
        self._mgr.db.set_job_progress(self.job_id, pct)


class JobManager:
    def __init__(self, db: Database, max_workers: int = 3):
        self.db = db
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._device_lock = threading.Lock()
        self._device_job_id: int | None = None   # job currently holding the device
        self._cancelled: set[int] = set()
        self._buffers: dict[int, list[str]] = {}
        self._lock = threading.Lock()

    # ---- internal ----
    def _is_cancelled(self, job_id: int) -> bool:
        with self._lock:
            return job_id in self._cancelled

    def _append_log(self, job_id: int, text: str) -> None:
        self.db.append_job_log(job_id, text)
        with self._lock:
            self._buffers.setdefault(job_id, []).append(text)

    def _finish(self, job_id: int, state: str, error: str | None = None) -> None:
        """Record a terminal state and release per-job resources. The in-memory
        log buffer is dropped a moment later so a stream that is mid-read can
        still drain its tail (the DB keeps the full log)."""
        self.db.set_job_state(job_id, state, error=error)
        with self._lock:
            self._cancelled.discard(job_id)

        def _drop():
            with self._lock:
                self._buffers.pop(job_id, None)
        t = threading.Timer(2.0, _drop)
        t.daemon = True
        t.start()

    def is_device_busy(self) -> bool:
        return self._device_lock.locked()

    def _run(self, job_id: int, fn: Callable[[JobContext], None],
             device_bound: bool) -> None:
        ctx = JobContext(self, job_id)
        if self._is_cancelled(job_id):
            self._finish(job_id, "cancelled")
            return
        lock = self._device_lock if device_bound else None
        if lock:
            lock.acquire()
            with self._lock:
                self._device_job_id = job_id
        try:
            if self._is_cancelled(job_id):
                self._finish(job_id, "cancelled")
                return
            self.db.set_job_state(job_id, "running")
            fn(ctx)
            # fn returned normally: the job's work is complete. A cancel that
            # raced in after completion must not relabel finished work.
            self.db.set_job_progress(job_id, 100)
            if self._is_cancelled(job_id):
                self.db.append_job_log(job_id, "\ncancel arrived after completion\n")
            self._finish(job_id, "done")
        except JobCancelled:
            self._finish(job_id, "cancelled")
        except (SystemExit, KeyboardInterrupt) as e:
            # A job must never take the server down, and must not be left
            # "running" forever either.
            msg = f"{type(e).__name__}: {e}"
            self.db.append_job_log(job_id, f"\nERROR: {msg}\n")
            self._finish(job_id, "failed", error=msg[:500])
        except Exception as e:  # noqa: BLE001 - a job failure must never crash the server
            # A cancel that unblocked the job by killing a device helper surfaces as
            # an exception here; report it as cancelled, not failed.
            if self._is_cancelled(job_id):
                self._finish(job_id, "cancelled")
            else:
                self.db.append_job_log(job_id, f"\nERROR: {e}\n")
                self._finish(job_id, "failed", error=str(e)[:500])
        finally:
            if lock:
                with self._lock:
                    if self._device_job_id == job_id:
                        self._device_job_id = None
                lock.release()

    # ---- public ----
    def submit(self, kind: str, target: str, fn: Callable[[JobContext], None],
               *, device_bound: bool = False, params: dict | None = None) -> int:
        job_id = self.db.create_job(kind, target, params)
        self._pool.submit(self._run, job_id, fn, device_bound)
        return job_id

    def _terminate_device_helpers(self) -> None:
        """Kill the external device helpers the device-holding job blocks inside,
        so a cancel actually unwinds the current phase (WDA build, syslog
        capture) instead of waiting for it to finish on its own."""
        for pat in device_helper_patterns():
            try:
                subprocess.run(["pkill", "-TERM", "-f", pat],
                               timeout=5, capture_output=True)
            except Exception:  # noqa: BLE001 - best effort
                pass

    def cancel(self, job_id: int) -> bool:
        row = self.db.get_job(job_id)
        if not row or row["state"] in _TERMINAL:
            return False
        with self._lock:
            self._cancelled.add(job_id)
            holds_device = self._device_job_id == job_id
        # Only the job that currently holds the device gets its helpers killed.
        # Queued jobs (not yet holding the device) and non-device jobs just get
        # the flag; killing helpers for them would hit someone else's run.
        if holds_device:
            self._terminate_device_helpers()
        return True

    def stream(self, job_id: int) -> Iterator[str]:
        sent = 0
        while True:
            with self._lock:
                buf = self._buffers.get(job_id)
                chunk = "".join(buf[sent:]) if buf else ""
                sent = len(buf) if buf else sent
            if chunk:
                yield chunk
            row = self.db.get_job(job_id)
            if row is None or row["state"] in _TERMINAL:
                with self._lock:
                    buf = self._buffers.get(job_id)
                    tail = "".join(buf[sent:]) if buf else ""
                if tail:
                    yield tail
                elif buf is None and sent == 0 and row is not None and row["log"]:
                    # Finished and its live buffer already released: replay the
                    # persisted log once for a late subscriber.
                    yield row["log"]
                return
            time.sleep(0.25)


_ACTIVE_TEES: set["_CtxLogHandler"] = set()
_ACTIVE_TEES_LOCK = threading.Lock()


class _CtxLogHandler(logging.Handler):
    """Forwards pipeline log records to ONE job's console.

    A record is accepted when it was emitted by the thread that created the
    handler (the job's worker) or by a helper thread that registered that
    worker as its parent (util.run_cmd_streamed's output pump does). Records
    from any other thread are dropped, so two concurrent jobs tee-ing the same
    module loggers never see each other's lines. One exception keeps unregistered
    helper threads (e.g. a device syslog reader) visible: when this is the ONLY
    active tee, no cross-talk is possible and such records are accepted."""

    def __init__(self, ctx: JobContext, thread_ident: int | None = None):
        super().__init__()
        self.ctx = ctx
        self.thread_ident = threading.get_ident() if thread_ident is None else thread_ident

    def accepts(self, record_thread: int | None) -> bool:
        from ..util import is_thread_descendant
        if record_thread is None:
            return False
        if is_thread_descendant(record_thread, self.thread_ident):
            return True
        with _ACTIVE_TEES_LOCK:
            others = [h for h in _ACTIVE_TEES if h is not self]
        if not others:
            return True
        # claimed by nobody and more than one job is live: drop (no guessing)
        return False

    def emit(self, record: logging.LogRecord) -> None:
        if not self.accepts(record.thread):
            return
        try:
            self.ctx.log(self.format(record) + "\n")
        except Exception:
            pass


_PIPELINE_LOGGERS = ("acquire", "analysis", "dynamic", "attestation", "appstore",
                     "static", "iap", "crawl", "aggregate", "attest_detect",
                     "instrument", "device", "capture", "otp", "llm_driver")


@contextmanager
def tee_pipeline_logs(ctx: JobContext):
    """Stream pipeline module logs emitted by THIS thread into the job's live log
    for the duration."""
    handler = _CtxLogHandler(ctx)
    handler.setFormatter(logging.Formatter("%(message)s"))
    loggers = [logging.getLogger(n) for n in _PIPELINE_LOGGERS]
    with _ACTIVE_TEES_LOCK:
        _ACTIVE_TEES.add(handler)
    for lg in loggers:
        lg.addHandler(handler)
    try:
        yield
    finally:
        for lg in loggers:
            lg.removeHandler(handler)
        with _ACTIVE_TEES_LOCK:
            _ACTIVE_TEES.discard(handler)


_MANAGER: JobManager | None = None


def get_manager(db: Database) -> JobManager:
    global _MANAGER
    if _MANAGER is None:
        from ..config import _env
        try:
            workers = max(1, int(_env("WEB_MAX_WORKERS", "3")))
        except ValueError:
            workers = 3
        _MANAGER = JobManager(db, max_workers=workers)
    return _MANAGER
