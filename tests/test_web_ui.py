"""Auth, jobs routes, and dashboard tests. Uses direct DB injection into the app
module (no module reloads) so each test gets an isolated SQLite DB."""
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from pipeline.db import Database


def _client(token="t"):
    os.environ["WEB_AUTH_TOKEN"] = token
    import pipeline.web.app as appmod
    import pipeline.web.jobs as jobsmod
    appmod._DB = Database(Path(tempfile.mkdtemp()) / "pinning.db")
    appmod._JOBS = None
    jobsmod._MANAGER = None
    client = TestClient(appmod.create_app())
    return client, appmod


def _login(client, token="t"):
    client.post("/login", data={"token": token})


# ---- auth ----

def test_protected_root_redirects_without_cookie():
    client, _ = _client()
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "/login" in r.headers["location"]


def test_login_with_token_grants_access():
    client, _ = _client()
    r = client.post("/login", data={"token": "t"}, follow_redirects=False)
    assert r.status_code in (302, 307)
    assert client.get("/").status_code == 200


def test_login_wrong_token_rejected():
    client, _ = _client()
    r = client.post("/login", data={"token": "nope"}, follow_redirects=False)
    assert r.status_code == 401
    r2 = client.get("/", follow_redirects=False)
    assert "/login" in r2.headers.get("location", "/login")


def test_healthz_open():
    client, _ = _client()
    assert client.get("/healthz").status_code == 200


# ---- jobs routes ----

def test_jobs_page_ok():
    client, _ = _client(); _login(client)
    assert client.get("/jobs").status_code == 200


def test_job_stream_emits_logs():
    client, appmod = _client(); _login(client)
    mgr = appmod.get_jobs_manager()

    def fn(ctx):
        ctx.log("streamed-line\n")
        time.sleep(0.1)

    jid = mgr.submit("static", "x", fn)
    body = ""
    with client.stream("GET", f"/jobs/{jid}/stream") as r:
        for chunk in r.iter_text():
            body += chunk
            if "streamed-line" in body:
                break
    assert "streamed-line" in body


# ---- dashboard ----

def test_dashboard_renders():
    client, _ = _client(); _login(client)
    r = client.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text


def test_run_static_creates_job():
    client, appmod = _client(); _login(client)
    r = client.post("/run/static", follow_redirects=False)
    assert r.status_code == 200
    assert len(appmod.get_db().list_jobs()) >= 1


def test_run_unknown_kind_rejected():
    client, _ = _client(); _login(client)
    r = client.post("/run/bogus")
    assert r.status_code == 400
