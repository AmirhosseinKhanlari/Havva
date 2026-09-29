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


@router.post("/jobs/{job_id}/cancel")
def jobs_cancel(job_id: int, request: Request, _: None = Depends(require_auth)):
    get_jobs_manager().cancel(job_id)
    return templates.TemplateResponse(request, "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})
