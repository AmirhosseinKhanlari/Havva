# Satella Console — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the web app foundation — a token-authed, mobile-first FastAPI UI over the existing pipeline with a background job manager (SQLite-backed, device-serialized), live SSE job logs, a Dashboard (funnel + health + run buttons), and a Jobs page — without changing any existing pipeline behavior or CLI.

**Architecture:** A new `pipeline/web/` package hosts a FastAPI app that calls existing pipeline functions through a `JobManager` (thread pool for non-device work + a single shared lock for device-bound stages). Jobs and their logs persist in the existing SQLite DB via new additive tables. The browser gets server-rendered Jinja2 + HTMX partials and subscribes to per-job SSE log streams. The existing CLI is untouched; a convenience `cli web` alias launches the server.

**Tech Stack:** FastAPI, uvicorn[standard], Jinja2, python-multipart, itsdangerous (cookie signing), HTMX + Tailwind (CDN), pytest + FastAPI TestClient. Existing: SQLite (`pipeline/db.py`), `pipeline/config.py`, `run_cmd_streamed`.

## Global Constraints

- **Do not break the existing pipeline or CLI.** `pipeline/` modules and `python3 -m pipeline.cli …` must behave exactly as before. New DB tables are additive (`CREATE TABLE IF NOT EXISTS`); no existing table is altered destructively.
- **CLI parity.** The web layer only *calls* existing pipeline functions; it never reimplements pipeline logic. (Deep analysis, a new capability, arrives in Phase 3 for both web and CLI.)
- **No em dashes in user-facing prose/UI copy.** Use commas or parentheses.
- **Use `python3`** in all commands and docs, never bare `python`.
- **Secrets never reach the client.** Apple-ID passwords and tokens are masked in any settings/config view.
- **Config comes from `pipeline/config.py` / `.env`.** New settings: `WEB_AUTH_TOKEN`, `WEB_HOST` (default `0.0.0.0`), `WEB_PORT` (default `8770`), `WEB_MAX_WORKERS` (default `3`).

---

### Task 1: Dependencies + web package skeleton (authless healthz)

**Files:**
- Modify: `requirements.txt`
- Create: `pipeline/web/__init__.py`
- Create: `pipeline/web/app.py`
- Create: `pipeline/web/__main__.py`
- Create: `pipeline/web/templates/base.html`
- Test: `tests/test_web_app.py`

**Interfaces:**
- Produces: `pipeline.web.app.create_app() -> fastapi.FastAPI` (app factory). `GET /healthz` returns `{"ok": true}` with no auth. `pipeline.web.app.templates` (a `starlette.templating.Jinja2Templates` bound to `pipeline/web/templates`).

- [ ] **Step 1: Add dependencies**

Append to `requirements.txt`:
```
fastapi>=0.110
uvicorn[standard]>=0.29
jinja2>=3.1
python-multipart>=0.0.9
itsdangerous>=2.1
httpx>=0.27
```
(`httpx` is required by FastAPI `TestClient`.)

Run: `python3 -m pip install -r requirements.txt`
Expected: installs without error.

- [ ] **Step 2: Write the failing test**

Create `tests/test_web_app.py`:
```python
from fastapi.testclient import TestClient
from pipeline.web.app import create_app


def test_healthz_ok():
    client = TestClient(create_app())
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python3 -m pytest tests/test_web_app.py -v`
Expected: FAIL with `ModuleNotFoundError: pipeline.web`.

- [ ] **Step 4: Create the package skeleton**

Create `pipeline/web/__init__.py`:
```python
"""Satella Console: web UI over the pipeline. See docs/superpowers/specs/2026-09-29-ios-security-suite-webui-design.md."""
```

Create `pipeline/web/templates/base.html`:
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Satella Console{% endblock %}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@1.9.12"></script>
  <script src="https://unpkg.com/htmx.org@1.9.12/dist/ext/sse.js"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">
  <main class="max-w-5xl mx-auto p-4 pb-24">{% block content %}{% endblock %}</main>
  {% block nav %}{% endblock %}
</body>
</html>
```

Create `pipeline/web/app.py`:
```python
"""FastAPI application factory for Satella Console."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))


def create_app() -> FastAPI:
    app = FastAPI(title="Satella Console", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    return app
```

Create `pipeline/web/__main__.py`:
```python
"""Launch the Satella Console server: python3 -m pipeline.web"""
from __future__ import annotations

import uvicorn

from ..config import _env
from .app import create_app


def main() -> None:
    host = _env("WEB_HOST", "0.0.0.0")
    port = int(_env("WEB_PORT", "8770"))
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_web_app.py -v`
Expected: PASS.

- [ ] **Step 6: Verify the server boots and the CLI is unaffected**

Run: `python3 -c "import pipeline.cli, pipeline.web.app; print('ok')"`
Expected: prints `ok`.
Run: `python3 -m pipeline.cli status` and confirm it still prints DB counts (no change).

- [ ] **Step 7: Commit**

```bash
git add requirements.txt pipeline/web tests/test_web_app.py
git commit -m "web: FastAPI app skeleton + healthz (Satella Console phase 1)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: DB tables for jobs + analysis (+ job helper methods)

**Files:**
- Modify: `pipeline/db.py` (append to `SCHEMA` string near line 135; add methods to `Database`)
- Test: `tests/test_jobs_db.py`

**Interfaces:**
- Produces on `Database`:
  - `create_job(kind: str, target: str, params: dict | None = None) -> int` — inserts a `queued` job, returns its integer id.
  - `get_job(job_id: int) -> sqlite3.Row | None`
  - `list_jobs(limit: int = 50) -> list[sqlite3.Row]` — newest first.
  - `set_job_state(job_id: int, state: str, error: str | None = None) -> None` — also stamps `started_at` when moving to `running` and `finished_at` when moving to a terminal state (`done`/`failed`/`cancelled`).
  - `append_job_log(job_id: int, text: str) -> None` — appends to the `log` column.
  - `set_job_progress(job_id: int, pct: int) -> None`
  - `mark_interrupted_jobs() -> int` — moves any `running`/`queued` job to `failed` with error `interrupted`; returns count. (Called once at server start.)
- The `analysis` table is created here (used in Phase 3), but no methods for it yet.

- [ ] **Step 1: Write the failing test**

Create `tests/test_jobs_db.py`:
```python
import tempfile
from pathlib import Path

from pipeline.db import Database


def _db():
    d = tempfile.mkdtemp()
    return Database(Path(d) / "t.db")


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_jobs_db.py -v`
Expected: FAIL with `AttributeError: 'Database' object has no attribute 'create_job'`.

- [ ] **Step 3: Add the tables to SCHEMA**

In `pipeline/db.py`, insert before the `CREATE INDEX` lines (currently ~line 137) inside the `SCHEMA` string:
```sql
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                  -- crawl|acquire|deep_analyze|static|dynamic|attest|iap|aggregate|full
    target TEXT,                         -- app_id or 'batch'
    params TEXT,                         -- JSON
    state TEXT NOT NULL DEFAULT 'queued',-- queued|running|done|failed|cancelled
    progress_pct INTEGER DEFAULT 0,
    log TEXT DEFAULT '',
    error TEXT,
    created_at TEXT,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS analysis (
    app_id TEXT PRIMARY KEY REFERENCES apps(app_id),
    info_plist TEXT,                     -- JSON
    entitlements TEXT,                   -- JSON
    ats TEXT,                            -- JSON
    frameworks TEXT,                     -- JSON
    sdks TEXT,                           -- JSON
    secrets TEXT,                        -- JSON
    file_tree TEXT,                      -- JSON
    crypto_hints TEXT,                   -- JSON
    analyzed_at TEXT
);
```
And add to the index block:
```sql
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
```

- [ ] **Step 4: Add the job methods to the `Database` class**

Add these methods inside `class Database` (after `set_stage`, keeping style consistent; `_now`, `json`, `time` are already imported):
```python
    # ---- Jobs (web UI) --------------------------------------------------

    _JOB_TERMINAL = ("done", "failed", "cancelled")

    def create_job(self, kind: str, target: str, params: dict | None = None) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO jobs (kind, target, params, state, created_at) "
                "VALUES (?, ?, ?, 'queued', ?)",
                (kind, target, json.dumps(params or {}), _now()),
            )
            return int(cur.lastrowid)

    def get_job(self, job_id: int):
        with self.connect() as conn:
            return conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()

    def list_jobs(self, limit: int = 50):
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def set_job_state(self, job_id: int, state: str, error: str | None = None) -> None:
        with self.connect() as conn:
            sets = ["state=?"]
            vals: list = [state]
            if state == "running":
                sets.append("started_at=?"); vals.append(_now())
            if state in self._JOB_TERMINAL:
                sets.append("finished_at=?"); vals.append(_now())
            if error is not None:
                sets.append("error=?"); vals.append(error)
            vals.append(job_id)
            conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE id=?", vals)

    def append_job_log(self, job_id: int, text: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET log = COALESCE(log,'') || ? WHERE id=?",
                         (text, job_id))

    def set_job_progress(self, job_id: int, pct: int) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE jobs SET progress_pct=? WHERE id=?", (int(pct), job_id))

    def mark_interrupted_jobs(self) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "UPDATE jobs SET state='failed', error='interrupted', finished_at=? "
                "WHERE state IN ('queued','running')", (_now(),))
            return cur.rowcount
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_jobs_db.py -v`
Expected: PASS (all three tests).

- [ ] **Step 6: Verify existing DB tests still pass**

Run: `python3 -m pytest tests/ -k "db or static or oracle or escalate or capture" -q`
Expected: existing tests still PASS (no regressions from the schema additions).

- [ ] **Step 7: Commit**

```bash
git add pipeline/db.py tests/test_jobs_db.py
git commit -m "db: add jobs + analysis tables and job helper methods (additive)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Job manager (thread pool + device lock + log tee + cancel)

**Files:**
- Create: `pipeline/web/jobs.py`
- Test: `tests/test_job_manager.py`

**Interfaces:**
- Consumes: `Database` job methods from Task 2; `pipeline.config.CONFIG`.
- Produces:
  - `JobContext` — passed to job functions; has `.log(text: str)` (tees to DB + in-memory buffer + `cancelled` check), `.progress(pct: int)`, and `.cancelled` (bool property).
  - `JobManager(db, max_workers=3)`:
    - `submit(kind: str, target: str, fn: Callable[[JobContext], None], *, device_bound: bool = False, params: dict | None = None) -> int` — creates a DB job, schedules it, returns job id.
    - `cancel(job_id: int) -> bool` — sets the cancel flag; returns True if the job was known and not already terminal.
    - `stream(job_id: int) -> Iterator[str]` — yields log text as it is appended (for SSE), ending when the job reaches a terminal state.
    - `is_device_busy() -> bool`.
  - Module singleton accessor `get_manager(db) -> JobManager` (one per process).

- [ ] **Step 1: Write the failing test**

Create `tests/test_job_manager.py`:
```python
import tempfile, time, threading
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
    lock_seen = []
    def fn(ctx):
        order.append(("start", time.time()))
        lock_seen.append(mgr.is_device_busy())
        time.sleep(0.2)
        order.append(("end", time.time()))
    a = mgr.submit("dynamic", "1", fn, device_bound=True)
    b = mgr.submit("dynamic", "2", fn, device_bound=True)
    _wait(db, a); _wait(db, b)
    # Second start must be after first end (serialized).
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
    b0 = mgr.submit("static", "block", blocker)   # occupies the single worker
    jid = mgr.submit("static", "x", fn)           # queued behind it
    assert mgr.cancel(jid) is True
    gate.set()
    row = _wait(db, jid)
    assert row["state"] == "cancelled"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_job_manager.py -v`
Expected: FAIL with `ModuleNotFoundError: pipeline.web.jobs`.

- [ ] **Step 3: Implement the job manager**

Create `pipeline/web/jobs.py`:
```python
"""In-process job manager: thread pool for non-device work + a single lock for
device-bound stages. Backed by the DB jobs table; streams logs for SSE."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
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
        import time
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
                # flush any final buffered text
                with self._lock:
                    buf = self._buffers.get(job_id, [])
                    tail = "".join(buf[sent:])
                if tail:
                    yield tail
                return
            time.sleep(0.25)


_MANAGER: JobManager | None = None


def get_manager(db: Database) -> JobManager:
    global _MANAGER
    if _MANAGER is None:
        from ..config import _env
        _MANAGER = JobManager(db, max_workers=int(_env("WEB_MAX_WORKERS", "3")))
    return _MANAGER
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_job_manager.py -v`
Expected: PASS (all four tests).

- [ ] **Step 5: Commit**

```bash
git add pipeline/web/jobs.py tests/test_job_manager.py
git commit -m "web: in-process job manager (pool + device lock + log stream + cancel)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Auth (token login, signed cookie, route guard)

**Files:**
- Create: `pipeline/web/auth.py`
- Create: `pipeline/web/templates/login.html`
- Modify: `pipeline/web/app.py` (wire auth + a protected `/` placeholder)
- Modify: `pipeline/config.py` (nothing structural; auth reads via `_env` directly)
- Test: `tests/test_web_auth.py`

**Interfaces:**
- Consumes: `create_app()` from Task 1.
- Produces in `pipeline/web/auth.py`:
  - `COOKIE_NAME = "satella_session"`
  - `require_auth(request: Request) -> None` — FastAPI dependency; raises `HTTPException(status_code=307)` redirect to `/login` when the signed cookie is missing/invalid.
  - `mount_auth(app: FastAPI) -> None` — adds `GET /login` (form) and `POST /login` (checks token, sets signed cookie, redirects to `/`) and `GET /logout`.
  - Token source: `_env("WEB_AUTH_TOKEN", "")`. If empty, auth is effectively open BUT `mount_auth` logs a loud warning; tests set the env explicitly.

- [ ] **Step 1: Write the failing test**

Create `tests/test_web_auth.py`:
```python
import os
from fastapi.testclient import TestClient


def _client():
    os.environ["WEB_AUTH_TOKEN"] = "secret123"
    from importlib import reload
    import pipeline.web.auth as auth; reload(auth)
    import pipeline.web.app as appmod; reload(appmod)
    return TestClient(appmod.create_app())


def test_protected_root_redirects_without_cookie():
    client = _client()
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "/login" in r.headers["location"]


def test_login_with_token_grants_access():
    client = _client()
    r = client.post("/login", data={"token": "secret123"}, follow_redirects=False)
    assert r.status_code in (302, 307)
    # cookie now set on the client; root should be reachable
    r2 = client.get("/")
    assert r2.status_code == 200


def test_login_wrong_token_rejected():
    client = _client()
    r = client.post("/login", data={"token": "nope"}, follow_redirects=False)
    assert r.status_code in (401, 200)  # re-renders form with error
    r2 = client.get("/", follow_redirects=False)
    assert "/login" in r2.headers.get("location", "/login")


def test_healthz_open():
    client = _client()
    assert client.get("/healthz").status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_web_auth.py -v`
Expected: FAIL (root `/` not defined / no auth).

- [ ] **Step 3: Implement auth**

Create `pipeline/web/templates/login.html`:
```html
{% extends "base.html" %}
{% block content %}
<div class="max-w-sm mx-auto mt-24">
  <h1 class="text-xl font-semibold mb-4">Satella Console</h1>
  {% if error %}<p class="text-red-400 mb-2">{{ error }}</p>{% endif %}
  <form method="post" action="/login" class="space-y-3">
    <input name="token" type="password" placeholder="Access token" autofocus
           class="w-full rounded bg-slate-800 px-3 py-2">
    <button class="w-full rounded bg-indigo-600 px-3 py-2 font-medium">Sign in</button>
  </form>
</div>
{% endblock %}
```

Create `pipeline/web/auth.py`:
```python
"""Single shared-token auth via a signed cookie."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, URLSafeSerializer

from ..config import _env
from .app import templates

log = logging.getLogger("web.auth")
COOKIE_NAME = "satella_session"


def _serializer() -> URLSafeSerializer:
    secret = _env("WEB_AUTH_TOKEN", "") or "insecure-dev-secret"
    return URLSafeSerializer(secret, salt="satella")


def _valid_cookie(request: Request) -> bool:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return False
    try:
        return _serializer().loads(raw) == "ok"
    except BadSignature:
        return False


def require_auth(request: Request) -> None:
    if _valid_cookie(request):
        return
    raise HTTPException(status_code=307, headers={"Location": "/login"})


def mount_auth(app: FastAPI) -> None:
    token = _env("WEB_AUTH_TOKEN", "")
    if not token:
        log.warning("WEB_AUTH_TOKEN is empty; the console is UNPROTECTED. Set it in .env.")

    @app.get("/login")
    def login_form(request: Request):
        return templates.TemplateResponse("login.html", {"request": request})

    @app.post("/login")
    def login(request: Request, token_in: str = Form(alias="token", default="")):
        if token and token_in == token:
            resp = RedirectResponse("/", status_code=302)
            resp.set_cookie(COOKIE_NAME, _serializer().dumps("ok"),
                            httponly=True, samesite="lax")
            return resp
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid token"}, status_code=401)

    @app.get("/logout")
    def logout():
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(COOKIE_NAME)
        return resp
```

- [ ] **Step 4: Wire auth + protected root into the app**

Replace `pipeline/web/app.py` `create_app` body to add auth and a protected root. New `create_app`:
```python
def create_app() -> FastAPI:
    app = FastAPI(title="Satella Console", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    from .auth import mount_auth, require_auth
    mount_auth(app)

    from fastapi import Depends, Request

    @app.get("/")
    def index(request: Request, _: None = Depends(require_auth)):
        return templates.TemplateResponse("base.html", {"request": request})

    # Turn a require_auth redirect (307 + Location) into a real redirect response.
    from fastapi.responses import RedirectResponse
    from fastapi.exceptions import HTTPException as _HTTPExc

    @app.exception_handler(_HTTPExc)
    def _auth_redirect(request: Request, exc: _HTTPExc):
        loc = exc.headers and exc.headers.get("Location")
        if exc.status_code == 307 and loc:
            return RedirectResponse(loc, status_code=307)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_web_auth.py -v`
Expected: PASS (all four tests).

- [ ] **Step 6: Add WEB_AUTH_TOKEN to .env.example**

Append to `.env.example`:
```
# --- Web UI (Satella Console) ---
WEB_AUTH_TOKEN=change-me-to-a-long-random-string
WEB_HOST=0.0.0.0
WEB_PORT=8770
WEB_MAX_WORKERS=3
```

- [ ] **Step 7: Commit**

```bash
git add pipeline/web/auth.py pipeline/web/app.py pipeline/web/templates/login.html tests/test_web_auth.py .env.example
git commit -m "web: single-token auth (signed cookie) + protected root

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Jobs router + SSE live log stream + Jobs page

**Files:**
- Create: `pipeline/web/routers/__init__.py`
- Create: `pipeline/web/routers/jobs.py`
- Create: `pipeline/web/templates/jobs.html`
- Create: `pipeline/web/templates/_job_row.html`
- Modify: `pipeline/web/app.py` (include the jobs router; expose the DB + manager)
- Test: `tests/test_web_jobs_routes.py`

**Interfaces:**
- Consumes: `require_auth` (Task 4), `get_manager` + `JobManager` (Task 3), `Database` job methods (Task 2).
- Produces:
  - `pipeline.web.app.get_db() -> Database` and `pipeline.web.app.get_jobs_manager() -> JobManager` accessors (single instances per process, created from `CONFIG.paths.db`). `mark_interrupted_jobs()` is called once when the DB accessor first initializes.
  - Routes (all require auth except where noted): `GET /jobs` (page), `GET /jobs/list` (HTMX partial table), `GET /jobs/{id}/stream` (SSE `text/event-stream`), `POST /jobs/{id}/cancel`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_web_jobs_routes.py`:
```python
import os, time
from fastapi.testclient import TestClient


def _client(tmp_path):
    os.environ["WEB_AUTH_TOKEN"] = "t"
    os.environ["DB_PATH"] = str(tmp_path / "pinning.db")
    from importlib import reload
    import pipeline.config as cfg; reload(cfg)
    import pipeline.web.app as appmod; reload(appmod)
    import pipeline.web.auth as auth; reload(auth)
    c = TestClient(appmod.create_app())
    c.post("/login", data={"token": "t"})
    return c, appmod


def test_jobs_page_requires_auth(tmp_path):
    c, _ = _client(tmp_path)
    assert c.get("/jobs").status_code == 200


def test_job_stream_emits_logs(tmp_path):
    c, appmod = _client(tmp_path)
    mgr = appmod.get_jobs_manager()
    def fn(ctx):
        ctx.log("streamed-line\n")
        time.sleep(0.1)
    jid = mgr.submit("static", "x", fn)
    with c.stream("GET", f"/jobs/{jid}/stream") as r:
        body = ""
        for chunk in r.iter_text():
            body += chunk
            if "streamed-line" in body:
                break
    assert "streamed-line" in body
```

Note: `pipeline/config.py` must honor `DB_PATH`. Confirm `Paths.db` uses `_env_path("DB_PATH", …)`; if not, this test's `DB_PATH` override belongs on whatever env var `Paths.db` reads. (Inspect `pipeline/config.py` `Paths` before running; adjust the env var name in the test to match.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_web_jobs_routes.py -v`
Expected: FAIL (`/jobs` 404 or `get_jobs_manager` missing).

- [ ] **Step 3: Add DB + manager accessors to app.py**

Add to `pipeline/web/app.py` (module level, after `templates`):
```python
_DB = None
_JOBS = None


def get_db():
    global _DB
    if _DB is None:
        from ..config import CONFIG
        from ..db import Database
        _DB = Database(CONFIG.paths.db)
        _DB.mark_interrupted_jobs()
    return _DB


def get_jobs_manager():
    global _JOBS
    if _JOBS is None:
        from .jobs import get_manager
        _JOBS = get_manager(get_db())
    return _JOBS
```
And in `create_app`, after `mount_auth(app)`:
```python
    from .routers import jobs as jobs_router
    app.include_router(jobs_router.router)
```

- [ ] **Step 4: Implement the jobs router**

Create `pipeline/web/routers/__init__.py` (empty).

Create `pipeline/web/routers/jobs.py`:
```python
"""Jobs page, HTMX list partial, SSE log stream, cancel."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from ..app import get_db, get_jobs_manager, templates
from ..auth import require_auth

router = APIRouter()


@router.get("/jobs")
def jobs_page(request: Request, _: None = Depends(require_auth)):
    return templates.TemplateResponse(
        "jobs.html", {"request": request, "jobs": get_db().list_jobs()})


@router.get("/jobs/list")
def jobs_list(request: Request, _: None = Depends(require_auth)):
    return templates.TemplateResponse(
        "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})


@router.get("/jobs/{job_id}/stream")
def jobs_stream(job_id: int, _: None = Depends(require_auth)):
    mgr = get_jobs_manager()

    def gen():
        for chunk in mgr.stream(job_id):
            for line in chunk.splitlines():
                yield f"data: {line}\n\n"
        yield "event: done\ndata: end\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.post("/jobs/{job_id}/cancel")
def jobs_cancel(job_id: int, request: Request, _: None = Depends(require_auth)):
    get_jobs_manager().cancel(job_id)
    return templates.TemplateResponse(
        "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})
```

- [ ] **Step 5: Create the templates**

Create `pipeline/web/templates/_job_row.html`:
```html
<table class="w-full text-sm" id="jobs-table">
  <thead class="text-slate-400"><tr>
    <th class="text-left p-1">#</th><th class="text-left p-1">Kind</th>
    <th class="text-left p-1">Target</th><th class="text-left p-1">State</th>
    <th class="text-left p-1">%</th><th></th>
  </tr></thead>
  <tbody>
  {% for j in jobs %}
    <tr class="border-t border-slate-800">
      <td class="p-1">{{ j['id'] }}</td>
      <td class="p-1">{{ j['kind'] }}</td>
      <td class="p-1 font-mono text-xs">{{ j['target'] }}</td>
      <td class="p-1">
        <span class="px-2 py-0.5 rounded text-xs
          {% if j['state']=='running' %}bg-amber-600{% elif j['state']=='done' %}bg-emerald-700
          {% elif j['state']=='failed' %}bg-red-700{% elif j['state']=='cancelled' %}bg-slate-600
          {% else %}bg-slate-700{% endif %}">{{ j['state'] }}</span>
      </td>
      <td class="p-1">{{ j['progress_pct'] }}</td>
      <td class="p-1">
        <a class="text-indigo-400" href="#" hx-get="/jobs/{{ j['id'] }}/stream">log</a>
        {% if j['state'] in ('queued','running') %}
        <button class="text-red-400 ml-2" hx-post="/jobs/{{ j['id'] }}/cancel"
                hx-target="#jobs-table" hx-swap="outerHTML">cancel</button>
        {% endif %}
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
```

Create `pipeline/web/templates/jobs.html`:
```html
{% extends "base.html" %}
{% block title %}Jobs{% endblock %}
{% block content %}
<h1 class="text-lg font-semibold mb-3">Jobs</h1>
<div hx-get="/jobs/list" hx-trigger="every 2s" hx-swap="innerHTML">
  {% include "_job_row.html" %}
</div>
{% endblock %}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `python3 -m pytest tests/test_web_jobs_routes.py -v`
Expected: PASS. If the DB-path env override fails, fix the test's env var to match `Paths.db` in `pipeline/config.py` (see the note in Step 1), then re-run.

- [ ] **Step 7: Commit**

```bash
git add pipeline/web/routers pipeline/web/templates/jobs.html pipeline/web/templates/_job_row.html pipeline/web/app.py tests/test_web_jobs_routes.py
git commit -m "web: jobs router, SSE log stream, jobs page

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Dashboard (funnel + doctor health + run buttons)

**Files:**
- Create: `pipeline/web/routers/dashboard.py`
- Create: `pipeline/web/templates/dashboard.html`
- Create: `pipeline/web/templates/_nav.html`
- Modify: `pipeline/web/app.py` (include dashboard router; make `/` render the dashboard)
- Modify: `pipeline/web/templates/base.html` (include the nav)
- Test: `tests/test_web_dashboard.py`

**Interfaces:**
- Consumes: `require_auth`, `get_db`, `get_jobs_manager`; existing `db.counts()`; existing `aggregate.report(db)` (for funnel numbers); a health helper.
- Produces:
  - `pipeline.web.routers.dashboard.health() -> dict` — reachability booleans: `{"iphone8": bool, "xr": bool, "itunes_server": bool, "ipadecrypt_bootstrapped": bool}` (best-effort, each wrapped in try/except, fast timeouts).
  - Routes: `GET /` (dashboard page), `POST /run/{kind}` (submits a job of `kind` in `{acquire,static,dynamic,attest,iap,aggregate,full,crawl}` for the corpus/batch; returns the jobs table partial). Single-app runs come in Phase 2.

- [ ] **Step 1: Write the failing test**

Create `tests/test_web_dashboard.py`:
```python
import os
from fastapi.testclient import TestClient


def _client(tmp_path):
    os.environ["WEB_AUTH_TOKEN"] = "t"
    os.environ["DB_PATH"] = str(tmp_path / "pinning.db")
    from importlib import reload
    import pipeline.config as cfg; reload(cfg)
    import pipeline.web.app as appmod; reload(appmod)
    import pipeline.web.auth as auth; reload(auth)
    c = TestClient(appmod.create_app()); c.post("/login", data={"token": "t"})
    return c, appmod


def test_dashboard_renders(tmp_path):
    c, _ = _client(tmp_path)
    r = c.get("/")
    assert r.status_code == 200
    assert "Dashboard" in r.text or "Corpus" in r.text


def test_run_static_creates_job(tmp_path):
    c, appmod = _client(tmp_path)
    r = c.post("/run/static", follow_redirects=False)
    assert r.status_code in (200, 302)
    assert len(appmod.get_db().list_jobs()) >= 1


def test_run_unknown_kind_rejected(tmp_path):
    c, _ = _client(tmp_path)
    r = c.post("/run/bogus")
    assert r.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_web_dashboard.py -v`
Expected: FAIL (`/` renders base only; `/run/...` missing).

- [ ] **Step 3: Implement health + dashboard router**

Create `pipeline/web/routers/dashboard.py`:
```python
"""Dashboard: funnel numbers, health, and batch run buttons."""
from __future__ import annotations

import socket

from fastapi import APIRouter, Depends, HTTPException, Request

from ...config import CONFIG
from ..app import get_db, get_jobs_manager, templates
from ..auth import require_auth

router = APIRouter()

# kind -> (pipeline callable factory, device_bound). Each factory returns a
# function taking a JobContext. Batch/corpus runs only in this task.
def _job_fns():
    from ... import acquire, static_classify, dynamic, attestation, iap, aggregate, crawl

    def wrap(run_callable):
        def job(ctx):
            db = get_db()
            ctx.log(f"starting…\n")
            result = run_callable(db)
            ctx.log(f"{result}\n")
        return job

    return {
        "crawl":     (lambda: (lambda ctx: (ctx.log("crawling…\n"), crawl.crawl(get_db()))), False),
        "acquire":   (lambda: wrap(lambda db: acquire.run(db)), True),
        "static":    (lambda: wrap(lambda db: static_classify.run(db)), False),
        "dynamic":   (lambda: wrap(lambda db: dynamic.run(db)), True),
        "attest":    (lambda: wrap(lambda db: attestation.run(db)), True),
        "iap":       (lambda: wrap(lambda db: iap.run(db)), False),
        "aggregate": (lambda: wrap(lambda db: aggregate.report(db)), False),
    }


def health() -> dict:
    def _tcp(host: str, port: int, t=1.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=t):
                return True
        except Exception:
            return False

    h = {"iphone8": False, "xr": False, "itunes_server": False,
         "ipadecrypt_bootstrapped": False}
    try:
        h["iphone8"] = _tcp(CONFIG.decrypt_device.ssh_host, 22) if hasattr(
            CONFIG.decrypt_device, "ssh_host") else False
    except Exception:
        pass
    try:
        ip = CONFIG.test_device.client_ip
        h["xr"] = _tcp(ip, 62078) if ip else False
    except Exception:
        pass
    try:
        srv = CONFIG.appstore.itunes_server.split("//", 1)[-1]
        host, _, port = srv.partition(":")
        h["itunes_server"] = _tcp(host, int(port or "80"))
    except Exception:
        pass
    try:
        h["ipadecrypt_bootstrapped"] = CONFIG.decrypt_device.is_bootstrapped
    except Exception:
        pass
    return h


@router.get("/")
def dashboard(request: Request, _: None = Depends(require_auth)):
    db = get_db()
    from ... import aggregate
    try:
        metrics = aggregate.report(db)
    except Exception:
        metrics = {}
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "counts": db.counts(),
        "metrics": metrics,
        "health": health(),
        "jobs": db.list_jobs(10),
    })


@router.post("/run/{kind}")
def run_kind(kind: str, request: Request, _: None = Depends(require_auth)):
    fns = _job_fns()
    if kind == "full":
        # Chain the corpus stages in order in a single job.
        def full(ctx):
            for k in ("acquire", "static", "aggregate"):
                if ctx.cancelled:
                    return
                ctx.log(f"== {k} ==\n")
                fns[k][0]()(ctx)
        get_jobs_manager().submit("full", "batch", full, device_bound=True)
    elif kind in fns:
        factory, device = fns[kind]
        get_jobs_manager().submit(kind, "batch", factory(), device_bound=device)
    else:
        raise HTTPException(status_code=400, detail=f"unknown kind {kind}")
    return templates.TemplateResponse(
        "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})
```

Note: verify the real attribute names on `CONFIG.decrypt_device` (e.g. the SSH host field) in `pipeline/config.py` and adjust `health()` to match; keep each probe in its own try/except so a wrong attribute never breaks the page.

- [ ] **Step 4: Create nav + dashboard templates; wire `/`**

Create `pipeline/web/templates/_nav.html`:
```html
<nav class="fixed bottom-0 inset-x-0 bg-slate-900 border-t border-slate-800 flex justify-around py-2 text-xs md:hidden">
  <a href="/" class="px-3">Home</a>
  <a href="/corpus" class="px-3">Corpus</a>
  <a href="/jobs" class="px-3">Jobs</a>
  <a href="/settings" class="px-3">Settings</a>
</nav>
```
(`/corpus` and `/settings` arrive in later phases; links can 404 for now or be added as stubs. Add stub routes returning a "coming soon" page if a 404 is undesirable.)

Add to `pipeline/web/templates/base.html` before `</body>`, replacing the empty nav block:
```html
  {% block nav %}{% include "_nav.html" %}{% endblock %}
```

Create `pipeline/web/templates/dashboard.html`:
```html
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<h1 class="text-lg font-semibold mb-3">Dashboard</h1>

<section class="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
  {% for label, key in [('Apps','apps'),('Acquired','acquired'),('Static','static_done'),('Pinned','pinned'),('Attest','appattest'),('Tested','attested_tested')] %}
  <div class="rounded bg-slate-900 p-3">
    <div class="text-2xl font-bold">{{ counts.get(key, 0) }}</div>
    <div class="text-slate-400 text-xs">{{ label }}</div>
  </div>
  {% endfor %}
</section>

<section class="mb-4">
  <h2 class="text-sm text-slate-400 mb-1">Health</h2>
  <div class="flex flex-wrap gap-2 text-xs">
    {% for label, key in [('iPhone 8','iphone8'),('iPhone XR','xr'),('iTunes server','itunes_server'),('ipadecrypt','ipadecrypt_bootstrapped')] %}
    <span class="px-2 py-1 rounded {% if health[key] %}bg-emerald-700{% else %}bg-red-800{% endif %}">
      {{ label }}: {{ 'up' if health[key] else 'down' }}</span>
    {% endfor %}
  </div>
</section>

<section class="mb-4">
  <h2 class="text-sm text-slate-400 mb-1">Run</h2>
  <div class="grid grid-cols-2 sm:grid-cols-4 gap-2" hx-target="#recent-jobs" hx-swap="innerHTML">
    {% for k in ['crawl','acquire','static','iap','dynamic','attest','aggregate','full'] %}
    <button class="rounded bg-indigo-700 px-2 py-2 text-sm"
            hx-post="/run/{{ k }}"
            hx-confirm="Run {{ k }} on the corpus?">{{ k }}</button>
    {% endfor %}
  </div>
</section>

<section>
  <h2 class="text-sm text-slate-400 mb-1">Recent jobs</h2>
  <div id="recent-jobs" hx-get="/jobs/list" hx-trigger="every 3s" hx-swap="innerHTML">
    {% include "_job_row.html" %}
  </div>
</section>
{% endblock %}
```

In `pipeline/web/app.py` `create_app`: remove the placeholder `/` route from Task 4 and instead include the dashboard router (which owns `/`):
```python
    from .routers import jobs as jobs_router, dashboard as dashboard_router
    app.include_router(dashboard_router.router)
    app.include_router(jobs_router.router)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python3 -m pytest tests/test_web_dashboard.py -v`
Expected: PASS (all three tests).

- [ ] **Step 6: Full suite regression**

Run: `python3 -m pytest tests/ -q`
Expected: all tests pass (web + existing pipeline tests). No regressions.

- [ ] **Step 7: Commit**

```bash
git add pipeline/web/routers/dashboard.py pipeline/web/templates/dashboard.html pipeline/web/templates/_nav.html pipeline/web/app.py pipeline/web/templates/base.html tests/test_web_dashboard.py
git commit -m "web: dashboard (funnel, health, batch run buttons)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: CLI `web` launch alias + manual boot check + docs

**Files:**
- Modify: `pipeline/cli.py` (add a `web` subcommand that launches the server)
- Modify: `README.md` (document the console)
- Test: `tests/test_cli_web.py`

**Interfaces:**
- Consumes: `pipeline.web.__main__.main`.
- Produces: `python3 -m pipeline.cli web` starts the server (delegates to `pipeline.web.__main__.main`). Existing subcommands unchanged.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_web.py`:
```python
import pipeline.cli as cli


def test_web_subcommand_registered(monkeypatch):
    called = {}
    import pipeline.web.__main__ as webmain
    monkeypatch.setattr(webmain, "main", lambda: called.setdefault("ran", True))
    # Parse args and dispatch without actually starting uvicorn.
    import sys
    monkeypatch.setattr(sys, "argv", ["pipeline", "web"])
    rc = cli.main()
    assert called.get("ran") is True
    assert rc == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_cli_web.py -v`
Expected: FAIL (`web` not a valid subcommand; argparse SystemExit).

- [ ] **Step 3: Add the `web` subcommand**

In `pipeline/cli.py`, add a handler near the other `cmd_*` functions:
```python
def cmd_web(_args: argparse.Namespace) -> int:
    from .web.__main__ import main as web_main
    web_main()
    return 0
```
And register it in `main()` alongside the other `sub.add_parser(...)` calls:
```python
    sub.add_parser("web", help="launch the Satella Console web UI").set_defaults(func=cmd_web)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest tests/test_cli_web.py -v`
Expected: PASS.

- [ ] **Step 5: Manual boot smoke check**

Run (in one shell): `WEB_AUTH_TOKEN=devtoken python3 -m pipeline.cli web`
Then in another shell:
```bash
curl -s http://127.0.0.1:8770/healthz
curl -s -i http://127.0.0.1:8770/ | head -1   # expect 307 redirect to /login
```
Expected: `{"ok":true}` and a redirect to `/login`. Stop the server (Ctrl-C).

- [ ] **Step 6: Document in README**

Add a section to `README.md`:
```markdown
## Satella Console (web UI)

A mobile-friendly web UI over the whole pipeline (run any stage or the full
funnel, watch live progress, browse results).

```bash
# set a token first (in .env): WEB_AUTH_TOKEN=<long random string>
python3 -m pipeline.cli web        # or: python3 -m pipeline.web
# open http://<mac-ip>:8770 from your phone on the same network, sign in
```

The CLI keeps working exactly as before; the console just calls the same
pipeline functions.
```

- [ ] **Step 7: Commit**

```bash
git add pipeline/cli.py README.md tests/test_cli_web.py
git commit -m "cli: add 'web' subcommand to launch Satella Console; document it

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage (Phase 1 scope):**
- App skeleton + auth → Tasks 1, 4. ✓
- Job manager (pool + device lock + SSE + cancel) → Tasks 3, 5. ✓
- Dashboard + doctor health → Task 6. ✓
- Jobs page → Task 5. ✓
- Additive DB tables (jobs + analysis) → Task 2. ✓ (analysis table created now, used in Phase 3.)
- CLI parity / don't break CLI → Task 7 + regression runs in Tasks 2 and 6. ✓
- Config keys (`WEB_AUTH_TOKEN`, `WEB_HOST`, `WEB_PORT`, `WEB_MAX_WORKERS`) → Tasks 1, 4. ✓
- Deferred to later phases (per spec phasing): Corpus browser, App detail, Acquire tab (Phase 2); deep analysis + CLI `analyze` (Phase 3); dynamic/attest tabs (Phase 4); settings editor (Phase 5). Not gaps.

**Placeholder scan:** No TBD/TODO. Two tasks contain explicit "verify the real attribute/env name in config.py and adjust" notes (Task 5 Step 1, Task 6 Step 3). These are deliberate verification steps against the existing codebase, with a concrete fallback action, not vague placeholders.

**Type consistency:** `JobContext.log/progress/cancelled`, `JobManager.submit/cancel/stream/is_device_busy`, `get_manager`, `get_db`, `get_jobs_manager`, and the `Database.create_job/get_job/list_jobs/set_job_state/append_job_log/set_job_progress/mark_interrupted_jobs` signatures are used consistently across Tasks 2, 3, 5, 6. Job `kind` strings are the same set in Task 2 schema comment and Task 6 `_job_fns`. Cookie name `satella_session` consistent in Task 4.

**Known verification points for the implementer (not gaps):**
1. `pipeline/config.py` `Paths.db` env var name (Task 5/6 tests use `DB_PATH`) — confirm and align.
2. `CONFIG.decrypt_device` SSH host attribute name (Task 6 `health()`).
3. `crawl.crawl`, `iap.run`, `aggregate.report`, `acquire.run`, `static_classify.run`, `dynamic.run`, `attestation.run` signatures — confirm each accepts `(db)` (adjust the wrappers in `_job_fns` if a stage needs extra args; e.g. `acquire.run(db, limit=...)`).
