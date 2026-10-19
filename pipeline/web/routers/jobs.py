"""Jobs page, HTMX list partial, SSE log stream, cancel."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from ..app import get_db, get_jobs_manager, templates
from ..auth import require_auth

router = APIRouter()


def _job_phase(job) -> str:
    """A friendly current-phase label derived from the job's log tail, so the
    watch widget shows e.g. Downloading vs Decrypting while a job runs."""
    if job["state"] == "queued":
        return "Queued"
    log = job["log"] or ""
    # last non-empty token (handle tqdm '\r' progress lines)
    lines = [seg.strip() for line in log.splitlines() for seg in line.split("\r") if seg.strip()]
    last = lines[-1] if lines else ""
    low = last.lower()
    if low.startswith("==") or "acquire id" in low or "starting" in low:
        return "Preparing"
    if "download" in low:
        return "Downloading from iTunes"
    if "decrypting on device" in low or "ipadecrypt" in low or "spawned" in low or "running target" in low:
        return "Decrypting on device"
    if "installed" in low or "installing" in low:
        return "Installing on device"
    if "verifying" in low or "verified" in low or "decrypted" in low:
        return "Finalizing"
    if "classif" in low or "pinned=" in low:
        return "Classifying"
    if "analyz" in low:
        return "Analyzing"
    return (last[:70] if last else "Working")


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
        job = {"id": job_id, "kind": "job", "target": "", "state": "failed",
               "progress_pct": 0, "log": ""}
    # Only a same-origin path may be reloaded into the tab (no "//evil", no
    # "javascript:", no absolute URLs).
    if not (reload.startswith("/") and not reload.startswith("//")):
        reload = ""
    # The poll updates only the status bar; the log console (in _job_watch) persists.
    return templates.TemplateResponse(request, "_job_status.html",
                                      {"request": request, "job": job, "reload": reload,
                                       "phase": _job_phase(job)})


@router.post("/jobs/{job_id}/cancel")
def jobs_cancel(job_id: int, request: Request, _: None = Depends(require_auth)):
    get_jobs_manager().cancel(job_id)
    return templates.TemplateResponse(request, "_job_row.html", {"request": request, "jobs": get_db().list_jobs()})


@router.post("/jobs/clear")
def jobs_clear(request: Request, _: None = Depends(require_auth)):
    """Remove all finished jobs (done/failed/cancelled); running/queued stay."""
    get_db().clear_jobs()
    return templates.TemplateResponse(request, "_job_row.html",
                                      {"request": request, "jobs": get_db().list_jobs()})
