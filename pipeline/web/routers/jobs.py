"""Jobs page, HTMX list partial, SSE log stream, cancel."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from ..app import get_db, get_jobs_manager, templates
from ..auth import require_auth

router = APIRouter()


@router.get("/jobs")
def jobs_page(request: Request, _: None = Depends(require_auth)):
    return templates.TemplateResponse(request, "jobs.html", {"request": request, "jobs": get_db().list_jobs(), "nav": "jobs"})


@router.get("/jobs/list")
def jobs_list(request: Request, _: None = Depends(require_auth)):
    return templates.TemplateResponse(request, "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})


@router.get("/jobs/{job_id}/stream")
def jobs_stream(job_id: int, _: None = Depends(require_auth)):
    mgr = get_jobs_manager()

    def gen():
        for chunk in mgr.stream(job_id):
            for line in chunk.splitlines():
                yield f"data: {line}\n\n"
        yield "event: done\ndata: end\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.get("/jobs/{job_id}/watch")
def jobs_watch(job_id: int, request: Request, reload: str = "",
               _: None = Depends(require_auth)):
    """Self-polling job widget. Renders progress; when the job is terminal it
    stops polling and (client-side) reloads `reload` into #tab-content + notifies."""
    job = get_db().get_job(job_id)
    if not job:
        return templates.TemplateResponse(request, "_job_watch.html",
                                          {"request": request,
                                           "job": {"id": job_id, "kind": "job",
                                                   "target": "", "state": "failed",
                                                   "progress_pct": 0}, "reload": reload})
    return templates.TemplateResponse(request, "_job_watch.html",
                                      {"request": request, "job": job, "reload": reload})


@router.post("/jobs/{job_id}/cancel")
def jobs_cancel(job_id: int, request: Request, _: None = Depends(require_auth)):
    get_jobs_manager().cancel(job_id)
    return templates.TemplateResponse(request, "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})
