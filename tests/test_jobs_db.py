import tempfile
from pathlib import Path

from pipeline.db import Database


def _db():
    return Database(Path(tempfile.mkdtemp()) / "t.db")


def test_job_lifecycle():
    db = _db()
    jid = db.create_job("acquire", "475772902", {"country": "us"})
    assert isinstance(jid, int)
    row = db.get_job(jid)
    assert row["state"] == "queued"
    assert row["kind"] == "acquire"
    assert row["target"] == "475772902"

    db.set_job_state(jid, "running")
    assert db.get_job(jid)["started_at"] is not None

    db.append_job_log(jid, "line 1\n")
    db.append_job_log(jid, "line 2\n")
    assert db.get_job(jid)["log"] == "line 1\nline 2\n"

    db.set_job_progress(jid, 42)
    assert db.get_job(jid)["progress_pct"] == 42

    db.set_job_state(jid, "done")
    r = db.get_job(jid)
    assert r["state"] == "done"
    assert r["finished_at"] is not None


def test_list_jobs_newest_first():
    db = _db()
    a = db.create_job("acquire", "1")
    b = db.create_job("static", "2")
    jobs = db.list_jobs()
    assert [j["id"] for j in jobs][:2] == [b, a]


def test_mark_interrupted():
    db = _db()
    jid = db.create_job("acquire", "1")
    db.set_job_state(jid, "running")
    n = db.mark_interrupted_jobs()
    assert n == 1
    assert db.get_job(jid)["state"] == "failed"
    assert "interrupted" in db.get_job(jid)["error"]
