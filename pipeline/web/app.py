"""FastAPI application factory for Havva."""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import HTTPException as _HTTPExc
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

_HERE = Path(__file__).parent
templates = Jinja2Templates(directory=str(_HERE / "templates"))

# Cache-bust static assets: version = css mtime, so a changed stylesheet always
# reloads in the browser after a server restart.
try:
    templates.env.globals["asset_ver"] = int((_HERE / "static" / "console.css").stat().st_mtime)
except OSError:
    templates.env.globals["asset_ver"] = 0

_DB = None
_JOBS = None


def get_db():
    """One Database instance per process. Marks interrupted jobs on first use."""
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


def create_app() -> FastAPI:
    app = FastAPI(title="Havva", docs_url=None, redoc_url=None)

    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    from .auth import mount_auth
    mount_auth(app)

    from .routers import app_detail as app_detail_router
    from .routers import corpus as corpus_router
    from .routers import dashboard as dashboard_router
    from .routers import jobs as jobs_router
    from .routers import settings as settings_router
    app.include_router(dashboard_router.router)
    app.include_router(corpus_router.router)
    app.include_router(app_detail_router.router)
    app.include_router(jobs_router.router)
    app.include_router(settings_router.router)

    # Turn a require_auth redirect (307 + Location) into a real redirect.
    @app.exception_handler(_HTTPExc)
    def _auth_redirect(request: Request, exc: _HTTPExc):
        loc = exc.headers.get("Location") if exc.headers else None
        if exc.status_code == 307 and loc:
            return RedirectResponse(loc, status_code=307)
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
