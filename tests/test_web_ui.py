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


# ---- audit 2026-10-18: auth hardening ----

def test_unset_token_refuses_everything(monkeypatch):
    client, _ = _client()
    monkeypatch.setenv("WEB_AUTH_TOKEN", "")
    # no session can be minted ...
    r = client.post("/login", data={"token": ""}, follow_redirects=False)
    assert r.status_code == 503
    assert "not configured" in r.text
    assert "havva_session" not in r.cookies
    # ... a forged cookie signed with the old fallback secret is rejected ...
    from itsdangerous import URLSafeSerializer
    client.cookies.set("havva_session", URLSafeSerializer("insecure-dev-secret", salt="havva").dumps("ok"))
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307) and "/login" in r.headers["location"]
    # ... and the login page explains it
    assert "not configured" in client.get("/login").text


def test_session_cookie_is_httponly_with_max_age():
    client, _ = _client()
    r = client.post("/login", data={"token": "t"}, follow_redirects=False)
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "max-age=604800" in sc and "samesite=lax" in sc


def test_token_check_is_constant_time_compare(monkeypatch):
    import pipeline.web.auth as auth
    calls = []
    real = auth.secrets.compare_digest
    monkeypatch.setattr(auth.secrets, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    client, _ = _client()
    client.post("/login", data={"token": "nope"}, follow_redirects=False)
    assert calls


# ---- jobs watch: reload must be a same-origin path, rendered as JSON ----

def test_jobs_watch_reload_validation():
    client, appmod = _client(); _login(client)
    jid = appmod.get_db().create_job("static", "x")
    appmod.get_db().set_job_state(jid, "done")
    r = client.get(f"/jobs/{jid}/watch", params={"reload": "/app/1/tab/static"})
    assert r.status_code == 200 and '"/app/1/tab/static"' in r.text
    for bad in ("https://evil.example/x", "//evil.example/x", "javascript:alert(1)"):
        r = client.get(f"/jobs/{jid}/watch", params={"reload": bad})
        assert r.status_code == 200 and "evil" not in r.text and "javascript:" not in r.text
    # a reflected payload inside a valid path is JSON-escaped, never raw
    r = client.get(f"/jobs/{jid}/watch", params={"reload": "/x');alert(1)//</script>"})
    assert "');alert(1)//</script>" not in r.text
    assert "\\u003c/script" in r.text or "\\/script" in r.text


def test_job_watch_closes_previous_event_source():
    import pipeline.web.app as appmod
    from pathlib import Path
    html = (Path(appmod.__file__).parent / "templates" / "_job_watch.html").read_text()
    assert "window.__havvaES" in html and "htmx:beforeSwap" in html
    assert "'{{ reload }}'" not in html and "{{ reload|tojson }}" in html


# ---- settings: no .env injection, ints validated ----

def test_settings_rejects_newlines_and_bad_ints(tmp_path, monkeypatch):
    import pipeline.web.routers.settings as st
    monkeypatch.setattr(st, "PROJECT_ROOT", tmp_path)
    client, _ = _client(); _login(client)
    r = client.post("/settings/save", data={"ACQUIRE_MODE": "ipatool\nWEB_AUTH_TOKEN=pwned"})
    assert r.status_code == 400
    assert not (tmp_path / ".env").exists()
    r = client.post("/settings/save", data={"WEB_MAX_WORKERS": "lots"})
    assert r.status_code == 400
    r = client.post("/settings/save", data={"WEB_MAX_WORKERS": "0"})
    assert r.status_code == 400
    r = client.post("/settings/save", data={"WEB_MAX_WORKERS": " 4 "})
    assert r.status_code == 200
    assert "WEB_MAX_WORKERS=4" in (tmp_path / ".env").read_text()
    from pipeline.web.routers.settings import validate_updates
    import pytest
    with pytest.raises(ValueError):
        validate_updates({"DECRYPT_SSH_PORT": "70000"})
    with pytest.raises(ValueError):
        validate_updates({"X": "a\rb"})
    assert validate_updates({"WEB_PORT": "8080"}) == {"WEB_PORT": "8080"}
