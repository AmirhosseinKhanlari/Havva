import tempfile
import threading
import time
from pathlib import Path

from pipeline.db import Database
from pipeline.web.jobs import JobManager


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def _wait(db, jid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if db.get_job(jid)["state"] in ("done", "failed", "cancelled"):
            return db.get_job(jid)
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_runs_and_logs():
    db = _db(); mgr = JobManager(db, max_workers=2)

    def fn(ctx):
        ctx.log("hello\n"); ctx.progress(100)

    jid = mgr.submit("static", "x", fn)
    row = _wait(db, jid)
    assert row["state"] == "done"
    assert "hello" in row["log"]
    assert row["progress_pct"] == 100


def test_job_failure_recorded():
    db = _db(); mgr = JobManager(db, max_workers=2)

    def fn(ctx):
        raise RuntimeError("boom")

    jid = mgr.submit("static", "x", fn)
    row = _wait(db, jid)
    assert row["state"] == "failed"
    assert "boom" in row["error"]


def test_device_jobs_serialize():
    db = _db(); mgr = JobManager(db, max_workers=4)
    order = []

    def fn(ctx):
        order.append(("start", time.time()))
        time.sleep(0.2)
        order.append(("end", time.time()))

    a = mgr.submit("dynamic", "1", fn, device_bound=True)
    b = mgr.submit("dynamic", "2", fn, device_bound=True)
    _wait(db, a); _wait(db, b)
    starts = [t for k, t in order if k == "start"]
    ends = [t for k, t in order if k == "end"]
    assert min(ends) <= max(starts) + 0.05


def test_cancel_before_run():
    db = _db(); mgr = JobManager(db, max_workers=1)
    gate = threading.Event()

    def blocker(ctx):
        gate.wait(2)

    def fn(ctx):
        for _ in range(50):
            if ctx.cancelled:
                return
            time.sleep(0.02)

    mgr.submit("static", "block", blocker)   # occupies the single worker
    jid = mgr.submit("static", "x", fn)      # queued behind it
    assert mgr.cancel(jid) is True
    gate.set()
    row = _wait(db, jid)
    assert row["state"] == "cancelled"
