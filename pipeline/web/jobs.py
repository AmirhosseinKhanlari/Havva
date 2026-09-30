"""In-process job manager: thread pool for non-device work + a single lock for
device-bound stages. Backed by the DB jobs table; streams logs for SSE."""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Callable, Iterator

from ..db import Database


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

    def is_device_busy(self) -> bool:
        return self._device_lock.locked()

    def _run(self, job_id: int, fn: Callable[[JobContext], None],
             device_bound: bool) -> None:
        ctx = JobContext(self, job_id)
        if self._is_cancelled(job_id):
            self.db.set_job_state(job_id, "cancelled")
            return
        lock = self._device_lock if device_bound else None
        if lock:
            lock.acquire()
        try:
            if self._is_cancelled(job_id):
                self.db.set_job_state(job_id, "cancelled")
                return
            self.db.set_job_state(job_id, "running")
            fn(ctx)
            if self._is_cancelled(job_id):
                self.db.set_job_state(job_id, "cancelled")
            else:
                self.db.set_job_progress(job_id, 100)
                self.db.set_job_state(job_id, "done")
        except JobCancelled:
            self.db.set_job_state(job_id, "cancelled")
        except Exception as e:  # noqa: BLE001 - a job failure must never crash the server
            self.db.append_job_log(job_id, f"\nERROR: {e}\n")
            self.db.set_job_state(job_id, "failed", error=str(e)[:500])
        finally:
            if lock:
                lock.release()

    # ---- public ----
    def submit(self, kind: str, target: str, fn: Callable[[JobContext], None],
               *, device_bound: bool = False, params: dict | None = None) -> int:
        job_id = self.db.create_job(kind, target, params)
        self._pool.submit(self._run, job_id, fn, device_bound)
        return job_id

    def cancel(self, job_id: int) -> bool:
        row = self.db.get_job(job_id)
        if not row or row["state"] in ("done", "failed", "cancelled"):
            return False
        with self._lock:
            self._cancelled.add(job_id)
        return True

    def stream(self, job_id: int) -> Iterator[str]:
        sent = 0
        while True:
            with self._lock:
                buf = self._buffers.get(job_id, [])
                chunk = "".join(buf[sent:])
                sent = len(buf)
            if chunk:
                yield chunk
            row = self.db.get_job(job_id)
            if row is None or row["state"] in ("done", "failed", "cancelled"):
                with self._lock:
                    buf = self._buffers.get(job_id, [])
                    tail = "".join(buf[sent:])
                if tail:
                    yield tail
                return
            time.sleep(0.25)


class _CtxLogHandler(logging.Handler):
    def __init__(self, ctx: JobContext):
        super().__init__()
        self.ctx = ctx

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.ctx.log(self.format(record) + "\n")
        except Exception:
            pass


_PIPELINE_LOGGERS = ("acquire", "analysis", "dynamic", "attestation", "appstore",
                     "static", "iap", "crawl", "aggregate", "attest_detect",
                     "instrument", "device", "capture")


@contextmanager
def tee_pipeline_logs(ctx: JobContext):
    """Stream pipeline module logs into the job's live log for the duration."""
    handler = _CtxLogHandler(ctx)
    handler.setFormatter(logging.Formatter("%(message)s"))
    loggers = [logging.getLogger(n) for n in _PIPELINE_LOGGERS]
    for lg in loggers:
        lg.addHandler(handler)
    try:
        yield
    finally:
        for lg in loggers:
            lg.removeHandler(handler)


_MANAGER: JobManager | None = None


def get_manager(db: Database) -> JobManager:
    global _MANAGER
    if _MANAGER is None:
        from ..config import _env
        _MANAGER = JobManager(db, max_workers=int(_env("WEB_MAX_WORKERS", "3")))
    return _MANAGER
