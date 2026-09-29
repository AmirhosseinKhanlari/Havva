"""Dashboard: funnel numbers, health, and batch run buttons."""
from __future__ import annotations

import socket

from fastapi import APIRouter, Depends, HTTPException, Request

from ...config import CONFIG
from ..app import get_db, get_jobs_manager, templates
from ..auth import require_auth

router = APIRouter()


def _job_fns():
    """kind -> (factory returning a JobContext-taking fn, device_bound)."""
    from ... import (acquire, aggregate, analysis, attestation, crawl, dynamic,
                     iap, static_classify)

    def wrap(run_callable):
        def job(ctx):
            ctx.log("starting\n")
            result = run_callable(get_db())
            ctx.log(f"{result}\n")
        return job

    return {
        "crawl":     (lambda: wrap(lambda db: crawl.crawl(db)), False),
        "acquire":   (lambda: wrap(lambda db: acquire.run(db)), True),
        "static":    (lambda: wrap(lambda db: static_classify.run(db)), False),
        "analyze":   (lambda: wrap(lambda db: analysis.run(db)), False),
        "dynamic":   (lambda: wrap(lambda db: dynamic.run(db)), True),
        "attest":    (lambda: wrap(lambda db: attestation.run(db)), True),
        "iap":       (lambda: wrap(lambda db: iap.run(db)), False),
        "aggregate": (lambda: wrap(lambda db: aggregate.report(db)), False),
    }


def health() -> dict:
    def _tcp(host: str, port: int, t: float = 1.5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=t):
                return True
        except Exception:
            return False

    h = {"iphone8": False, "xr": False, "itunes_server": False,
         "ipadecrypt_bootstrapped": False}
    try:
        host = CONFIG.decrypt_device.ssh_host
        h["iphone8"] = _tcp(host, CONFIG.decrypt_device.ssh_port) if host else False
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
    return templates.TemplateResponse(request, "dashboard.html", {
        "request": request,
        "counts": db.counts(),
        "metrics": metrics,
        "health": health(),
        "jobs": db.list_jobs(10),
        "nav": "dash",
    })


@router.post("/run/{kind}")
def run_kind(kind: str, request: Request, _: None = Depends(require_auth)):
    fns = _job_fns()
    if kind == "full":
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
    return templates.TemplateResponse(request, "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})
