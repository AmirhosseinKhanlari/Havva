"""Smoke tests for corpus, app detail, analyze, and settings routes."""
import os
import plistlib
import tempfile
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from pipeline.db import Database
from pipeline.models import WorkState


def _seed_ipa(path: Path):
    info = {"CFBundleIdentifier": "com.test.app", "CFBundleExecutable": "Test",
            "CFBundleShortVersionString": "1.0"}
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(info))
        z.writestr("Payload/Test.app/Test", b"https://api.example.com TrustKit SecTrustEvaluate")


def _client(tmp):
    os.environ["WEB_AUTH_TOKEN"] = "t"
    import pipeline.web.app as appmod
    import pipeline.web.jobs as jobsmod
    db = Database(Path(tmp) / "pinning.db")
    ipa = Path(tmp) / "999.decrypted.ipa"
    _seed_ipa(ipa)
    db.upsert_app("999", "us", bundle_id="com.test.app", name="Test App",
                  primary_category="Finance")
    db.save_acquisition("999", WorkState.POSITIVE, ipa_path=str(ipa))
    appmod._DB = db
    appmod._JOBS = None
    jobsmod._MANAGER = None
    c = TestClient(appmod.create_app())
    c.post("/login", data={"token": "t"})
    return c, appmod


def test_corpus_lists_and_filters():
    c, _ = _client(tempfile.mkdtemp())
    r = c.get("/corpus")
    assert r.status_code == 200
    assert "Test App" in r.text
    # filter to acquired only still shows it
    r2 = c.get("/corpus?acquired=1", headers={"HX-Request": "true"})
    assert "Test App" in r2.text
    # filter to not-acquired hides it
    r3 = c.get("/corpus?acquired=0", headers={"HX-Request": "true"})
    assert "Test App" not in r3.text


def test_app_detail_and_tabs():
    c, _ = _client(tempfile.mkdtemp())
    r = c.get("/app/999")
    assert r.status_code == 200
    assert "com.test.app" in r.text
    for tab in ("overview", "acquire", "static", "dynamic", "attest"):
        rt = c.get(f"/app/999/tab/{tab}")
        assert rt.status_code == 200


def test_app_detail_404():
    c, _ = _client(tempfile.mkdtemp())
    assert c.get("/app/does-not-exist").status_code == 404


def test_analyze_action_creates_job_and_persists():
    import time
    c, appmod = _client(tempfile.mkdtemp())
    r = c.post("/app/999/analyze")
    assert r.status_code == 200
    # the deep_analyze job should run and persist analysis
    end = time.time() + 5
    while time.time() < end:
        if appmod.get_db().get_analysis("999"):
            break
        time.sleep(0.05)
    assert appmod.get_db().get_analysis("999") is not None


def test_download_missing_is_404():
    c, appmod = _client(tempfile.mkdtemp())
    # point acquisition at a nonexistent path
    appmod.get_db().save_acquisition("999", WorkState.POSITIVE, ipa_path="/nope/x.ipa")
    assert c.get("/app/999/download").status_code == 404


def test_acquire_action_keys_by_corpus_app_id(monkeypatch):
    """Regression: acquiring from app detail must record the acquisition under the
    same (numeric) app_id as the corpus row, not under the bundle id."""
    import time

    import pipeline.acquire as acq
    from pipeline.models import WorkState
    c, appmod = _client(tempfile.mkdtemp())
    db = appmod.get_db()
    db.upsert_app("555", "us", bundle_id="com.example.app", name="Ex")

    captured = {}

    def fake_acquire_one(database, bundle_id=None, app_id=None, **kw):
        captured["bundle_id"] = bundle_id
        captured["app_id"] = app_id
        return WorkState.POSITIVE, "ipas/555.decrypted.ipa", ""

    monkeypatch.setattr(acq, "acquire_one", fake_acquire_one)
    # The acquire route gates on the decrypt device being online; this test isn't
    # about connectivity, so pretend the iPhone 8 is reachable.
    from pipeline.config import CONFIG
    monkeypatch.setattr(type(CONFIG.decrypt_device), "online", lambda self, timeout=2.5: True)
    r = c.post("/app/555/acquire", data={"version": ""})
    assert r.status_code == 200
    end = time.time() + 5
    while time.time() < end and "app_id" not in captured:
        time.sleep(0.02)
    assert captured.get("app_id") == "555"
    assert captured.get("bundle_id") is None


def test_add_app_redirects_to_detail(monkeypatch):
    import pipeline.crawl as crawl
    c, _ = _client(tempfile.mkdtemp())
    monkeypatch.setattr(crawl, "add_app", lambda db, ident, country="us": "310633997")
    r = c.post("/corpus/add", data={"identifier": "310633997", "country": "us"},
               headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 204
    assert r.headers.get("HX-Redirect") == "/app/310633997"


def test_add_app_not_found_shows_error(monkeypatch):
    import pipeline.crawl as crawl
    c, _ = _client(tempfile.mkdtemp())
    monkeypatch.setattr(crawl, "add_app", lambda db, ident, country="us": None)
    r = c.post("/corpus/add", data={"identifier": "nope", "country": "us"},
               headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "No App Store match" in r.text


def test_appstore_search_lists_results(monkeypatch):
    import pipeline.crawl as crawl
    c, _ = _client(tempfile.mkdtemp())
    monkeypatch.setattr(crawl, "search_appstore", lambda term, country="us", limit=15: [
        {"app_id": "1", "name": "Foo", "bundle_id": "com.foo", "artwork_url": "", "category": "Utilities"}])
    r = c.get("/corpus/search", params={"identifier": "foo"}, headers={"HX-Request": "true"})
    assert r.status_code == 200 and "Foo" in r.text and "com.foo" in r.text


def test_settings_page_and_doctor():
    c, _ = _client(tempfile.mkdtemp())
    assert c.get("/settings").status_code == 200
    assert c.get("/settings/doctor").status_code == 200


def test_settings_save_writes_env(tmp_path, monkeypatch):
    # redirect PROJECT_ROOT/.env writing into a temp dir
    import pipeline.web.routers.settings as st
    monkeypatch.setattr(st, "PROJECT_ROOT", tmp_path)
    c, _ = _client(tempfile.mkdtemp())
    r = c.post("/settings/save", data={"ACQUIRE_MODE": "ipatool"})
    assert r.status_code == 200
    assert "ACQUIRE_MODE=ipatool" in (tmp_path / ".env").read_text()
    assert os.environ["ACQUIRE_MODE"] == "ipatool"
