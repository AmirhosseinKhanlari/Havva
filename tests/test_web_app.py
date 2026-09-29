from fastapi.testclient import TestClient

from pipeline.web.app import create_app


def test_healthz_ok():
    client = TestClient(create_app())
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}
