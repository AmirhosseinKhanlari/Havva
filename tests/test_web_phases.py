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


# ---- audit 2026-10-18 ----

def test_static_tab_renders_with_multiple_vulnerable_deps():
    """Regression: Jinja `sort(attribute='cves')` 500'd with >= 2 deps carrying
    CVE lists (lists of dicts are not orderable). The router now precomputes
    n_cves and the template sorts on that."""
    c, appmod = _client(tempfile.mkdtemp())
    db = appmod.get_db()
    db.save_analysis("999", {"info_plist": {"summary": {"CFBundleIdentifier": "com.test.app"}},
                             "dependencies": [
        {"name": "libA", "version": "1.0", "cves": [
            {"id": "CVE-2024-0001", "severity": "high", "summary": "a", "fixed": "1.1"},
            {"id": "CVE-2024-0002", "severity": "medium", "summary": "b", "fixed": ""}]},
        {"name": "libB", "version": "2.0", "cves": [
            {"id": "CVE-2023-0009", "severity": "high", "summary": "c", "fixed": "2.1"}]},
        {"name": "libC", "version": "3.0", "cves": []},
        {"name": "libD", "version": "4.0"},
    ]})
    r = c.get("/app/999/tab/static")
    assert r.status_code == 200
    assert r.text.index("libA") < r.text.index("libB") < r.text.index("libC")
    from pipeline.web.routers.app_detail import _decode_analysis
    deps = _decode_analysis(db.get_analysis("999"))["dependencies"]
    assert [d["n_cves"] for d in deps] == [2, 1, 0, 0]


def test_dynamic_custom_rejects_unknown_dylib_ids():
    c, appmod = _client(tempfile.mkdtemp())
    r = c.post("/app/999/dynamic/custom", data={"dylibs": ["ssks", "../../etc"]})
    assert r.status_code == 400 and "unknown dylib" in r.text
    r = c.post("/app/999/dynamic/custom", data={"dylibs": ["nope"]})
    assert r.status_code == 400
    r = c.post("/app/999/dynamic/custom", data={})
    assert r.status_code == 400
    assert appmod.get_db().list_jobs() == []      # nothing was submitted


def test_corpus_pagination_querystring_is_urlencoded():
    c, _ = _client(tempfile.mkdtemp())
    # page=2 so the Prev link (which carries the filter querystring) is rendered
    r = c.get("/corpus", params={"q": "a&b=c d", "category": "Finance", "page": 2})
    assert r.status_code == 200
    assert "q=a%26b%3Dc+d" in r.text and "category=Finance" in r.text
    assert "q=a&b=c d" not in r.text


def test_remove_and_download_resolve_relative_ipa_dir(monkeypatch):
    """The listing resolves IPA_DIR against the project root; remove/download
    must use the same resolution (previously they used the raw, possibly
    relative, CONFIG path and so depended on the server's cwd)."""
    import pipeline.web.routers.app_detail as ad
    tmp = tempfile.mkdtemp()
    c, appmod = _client(tmp)
    ipa_dir = Path(tmp) / "ipas"
    ipa_dir.mkdir()
    cur = ipa_dir / "999.decrypted.ipa"
    _seed_ipa(cur)
    old = ipa_dir / "999-v842.decrypted.ipa"
    _seed_ipa(old)
    monkeypatch.setattr(ad, "_ipa_dir", lambda: str(ipa_dir))
    db = appmod.get_db()
    db.save_acquisition("999", WorkState.POSITIVE, ipa_path=str(cur))
    db.save_acquisition_version("999", "842", WorkState.POSITIVE, ipa_path=str(old))
    assert c.get("/app/999/download", params={"file": old.name}).status_code == 200
    assert c.get("/app/999/download", params={"file": "../999.decrypted.ipa"}).status_code == 200
    assert c.get("/app/999/download", params={"file": "998.decrypted.ipa"}).status_code == 400
    assert c.get("/app/999/download", params={"file": "999-v842.ipa"}).status_code == 400
    # remove the old version: canonical row untouched, version row cleared
    r = c.post("/app/999/remove", data={"file": old.name})
    assert r.status_code == 200 and not old.exists() and cur.exists()
    assert db.get_acquisition("999")["ipa_path"] == str(cur)
    assert db.get_acquisition_versions("999")[0]["ipa_path"] == ""
    # remove the current build: acquisition row goes away
    r = c.post("/app/999/remove", data={"file": cur.name})
    assert r.status_code == 200 and not cur.exists()
    assert db.get_acquisition("999") is None
    assert c.get("/app/999/download").status_code == 404
