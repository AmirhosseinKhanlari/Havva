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


# ---- audit 2026-10-18: device-job tracking, scoped cancel, log isolation ----

def test_cancel_kills_helpers_only_for_device_holding_job(monkeypatch):
    db = _db(); mgr = JobManager(db, max_workers=3)
    killed = []
    monkeypatch.setattr(mgr, "_terminate_device_helpers", lambda: killed.append(1))
    started, release = threading.Event(), threading.Event()

    def device_fn(ctx):
        started.set()
        release.wait(3)

    def plain_fn(ctx):
        started.wait(3)
        time.sleep(0.3)

    dev = mgr.submit("dynamic", "d", device_fn, device_bound=True)
    other = mgr.submit("static", "s", plain_fn)
    assert started.wait(3)
    assert mgr._device_job_id == dev
    assert mgr.cancel(other) is True
    assert killed == []                      # a non-device job never pkills helpers
    assert mgr.cancel(dev) is True
    assert killed == [1]                     # the device holder does
    release.set()
    _wait(db, dev); _wait(db, other)
    assert mgr._device_job_id is None        # cleared in finally


def test_cancel_after_completion_is_done_not_cancelled():
    db = _db(); mgr = JobManager(db, max_workers=1)
    hold = threading.Event()

    def fn(ctx):
        ctx.log("work\n")
        hold.wait(3)       # body finishes only once the test has issued the cancel

    jid = mgr.submit("static", "x", fn)
    # wait until running, then cancel while fn is about to return normally
    end = time.time() + 3
    while time.time() < end and db.get_job(jid)["state"] != "running":
        time.sleep(0.01)
    with mgr._lock:
        mgr._cancelled.add(jid)   # cancel flag lands as fn completes
    hold.set()
    row = _wait(db, jid)
    assert row["state"] == "done"
    assert "cancel arrived after completion" in row["log"]


def test_system_exit_in_job_marks_failed():
    db = _db(); mgr = JobManager(db, max_workers=1)

    def fn(ctx):
        raise SystemExit(3)

    jid = mgr.submit("static", "x", fn)
    row = _wait(db, jid)
    assert row["state"] == "failed" and "SystemExit" in row["error"]
    # the worker is still alive afterwards
    jid2 = mgr.submit("static", "y", lambda ctx: None)
    assert _wait(db, jid2)["state"] == "done"


def test_log_buffer_released_after_terminal_state():
    db = _db(); mgr = JobManager(db, max_workers=1)
    jid = mgr.submit("static", "x", lambda ctx: ctx.log("hi\n"))
    _wait(db, jid)
    end = time.time() + 5
    while time.time() < end and jid in mgr._buffers:
        time.sleep(0.05)
    assert jid not in mgr._buffers
    assert jid not in mgr._cancelled


def test_tee_logs_isolated_per_thread():
    import logging
    from pipeline.web.jobs import tee_pipeline_logs
    db = _db(); mgr = JobManager(db, max_workers=2)
    both_in = threading.Barrier(2, timeout=5)
    lg = logging.getLogger("acquire")
    lg.setLevel(logging.INFO)

    def make(tag):
        def fn(ctx):
            with tee_pipeline_logs(ctx):
                both_in.wait()              # both handlers attached to the logger
                lg.info("from-%s", tag)
                both_in.wait()              # keep both attached until both logged
        return fn

    a = mgr.submit("acquire", "a", make("A"))
    b = mgr.submit("acquire", "b", make("B"))
    ra, rb = _wait(db, a), _wait(db, b)
    assert "from-A" in ra["log"] and "from-B" not in ra["log"]
    assert "from-B" in rb["log"] and "from-A" not in rb["log"]


def test_device_helper_patterns_scoped_to_udid(monkeypatch):
    from pipeline.web import jobs as jm
    pats = jm.device_helper_patterns("00008020-000A1B2C3D4E5F60")
    assert all("00008020-000A1B2C3D4E5F60" in p for p in pats)
    assert any("idevicesyslog" in p and "-u " in p for p in pats)
    assert any("WebDriverAgent" in p and "-destination id=" in p for p in pats)
    assert jm.device_helper_patterns("") == jm._DEVICE_HELPER_PATTERNS


def test_get_logger_initializes_even_if_tee_attached_first():
    """A web job tees the 'acquire' logger BEFORE importing pipeline.acquire;
    get_logger must still set the INFO level (it used to bail out as soon as any
    handler was present, so every log.info() from the module was dropped)."""
    import logging
    from pipeline.util import get_logger
    name = "havva_test_logger_order"
    lg = logging.getLogger(name)
    lg.addHandler(logging.NullHandler())
    assert get_logger(name).level == logging.INFO


def test_tee_logs_accept_streamed_child_thread_lines():
    """acquire logs ipadecrypt's live output from run_cmd_streamed's pump thread;
    those lines belong to the job and must reach its console even while another
    job is tee-ing the same loggers."""
    import logging
    import sys
    from pipeline.util import run_cmd_streamed
    from pipeline.web.jobs import tee_pipeline_logs
    db = _db(); mgr = JobManager(db, max_workers=2)
    lg = logging.getLogger("acquire")
    lg.setLevel(logging.INFO)
    gate = threading.Barrier(2, timeout=5)

    def streamer(ctx):
        with tee_pipeline_logs(ctx):
            gate.wait()
            run_cmd_streamed([sys.executable, "-c", "print('child-line')"], timeout=30,
                             echo=False, line_cb=lambda ln: lg.info("ipadecrypt | %s", ln))
            gate.wait()

    def other(ctx):
        with tee_pipeline_logs(ctx):
            gate.wait()
            gate.wait()

    a = mgr.submit("acquire", "a", streamer)
    b = mgr.submit("acquire", "b", other)
    ra, rb = _wait(db, a), _wait(db, b)
    assert "ipadecrypt | child-line" in ra["log"]
    assert "child-line" not in rb["log"]


def test_tee_logs_sole_job_accepts_unregistered_threads():
    import logging
    from pipeline.web.jobs import tee_pipeline_logs
    db = _db(); mgr = JobManager(db, max_workers=1)
    lg = logging.getLogger("device")
    lg.setLevel(logging.INFO)

    def fn(ctx):
        with tee_pipeline_logs(ctx):
            t = threading.Thread(target=lambda: lg.info("syslog-helper-line"))
            t.start(); t.join()

    row = _wait(db, mgr.submit("dynamic", "x", fn))
    assert "syslog-helper-line" in row["log"]


def test_stream_replays_db_log_after_buffer_released():
    db = _db(); mgr = JobManager(db, max_workers=1)
    jid = mgr.submit("static", "x", lambda ctx: ctx.log("persisted\n"))
    _wait(db, jid)
    with mgr._lock:
        mgr._buffers.pop(jid, None)        # simulate the delayed release
    assert "persisted" in "".join(mgr.stream(jid))
