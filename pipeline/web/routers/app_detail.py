"""Per-app detail page and its tabs + actions (acquire, analyze, dynamic, attest).

Every action submits a job through the shared JobManager; the tabs render whatever
is currently persisted for the app. All actions call existing pipeline functions.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse

from ..app import get_db, get_jobs_manager, templates
from ..auth import require_auth
from ..jobs import tee_pipeline_logs

router = APIRouter()

TABS = ("overview", "acquire", "static", "dynamic", "attest")


def _app_or_404(app_id: str):
    row = get_db().get_app(app_id)
    if not row:
        raise HTTPException(status_code=404, detail="app not found")
    return row


def _tab_context(request: Request, app_id: str, tab: str) -> dict:
    db = get_db()
    app = _app_or_404(app_id)
    ctx = {"request": request, "app": app, "app_id": app_id, "tab": tab, "tabs": TABS, "nav": "corpus"}
    if tab == "acquire":
        ctx["acq"] = db.get_acquisition(app_id)
    elif tab == "static":
        ctx["profile"] = db.get_static_profile(app_id)
        an = db.get_analysis(app_id)
        ctx["analysis"] = _decode_analysis(an) if an else None
    elif tab == "dynamic":
        ctx["runs"] = db.get_dynamic_runs(app_id)
        ctx["outcome"] = db.get_outcome(app_id)
    elif tab == "attest":
        ctx["attestation"] = db.get_attestation(app_id)
    return ctx


def _decode_analysis(row) -> dict:
    import json
    out = {}
    for k in ("info_plist", "entitlements", "ats", "frameworks", "sdks",
              "secrets", "file_tree", "crypto_hints"):
        try:
            out[k] = json.loads(row[k]) if row[k] else None
        except Exception:
            out[k] = None
    out["analyzed_at"] = row["analyzed_at"]
    return out


@router.get("/app/{app_id}")
def app_page(app_id: str, request: Request, _: None = Depends(require_auth)):
    return templates.TemplateResponse(request, "app_detail.html",
                                      _tab_context(request, app_id, "overview"))


@router.get("/app/{app_id}/tab/{tab}")
def app_tab(app_id: str, tab: str, request: Request, _: None = Depends(require_auth)):
    if tab not in TABS:
        raise HTTPException(status_code=404, detail="no such tab")
    return templates.TemplateResponse(request, f"_tab_{tab}.html",
                                      _tab_context(request, app_id, tab))


# ---- actions (each submits a job) ----

@router.post("/app/{app_id}/acquire")
def act_acquire(app_id: str, request: Request, version: str = Form(default=""),
                _: None = Depends(require_auth)):
    app = _app_or_404(app_id)
    # Key the acquisition by the SAME id as the corpus row (app_id), so the app
    # detail page finds it. acquire_one keys by bundle_id when one is passed, so
    # for a numeric corpus id we pass app_id only (numeric ids are App Store
    # store ids, which both backends accept); for a non-numeric corpus id we fall
    # back to the bundle.
    numeric = str(app_id).isdigit()
    bundle = None if numeric else app["bundle_id"]
    store_id = app_id if numeric else None

    def job(ctx):
        from ... import acquire
        with tee_pipeline_logs(ctx):
            state, path, err = acquire.acquire_one(
                get_db(), bundle_id=bundle, app_id=store_id,
                country=app["country"] or "us", app_ver_id=version or None)
        ctx.log(f"result: {state.name} {path or err}\n")

    get_jobs_manager().submit("acquire", app_id, job, device_bound=True,
                              params={"version": version})
    return templates.TemplateResponse(request, "_action_queued.html",
                                      {"request": request, "app_id": app_id, "what": "acquire"})


@router.get("/app/{app_id}/versions")
def act_versions(app_id: str, request: Request, _: None = Depends(require_auth)):
    from ... import appstore_dl
    from ...config import CONFIG
    numeric = app_id if str(app_id).isdigit() else None
    versions, error = [], ""
    try:
        if not numeric:
            app = _app_or_404(app_id)
            numeric = appstore_dl.lookup_app_id(app["bundle_id"], (app["country"] or "us").upper())
        versions = appstore_dl.list_versions(str(numeric), CONFIG.appstore.itunes_server, limit=40)
    except Exception as e:  # noqa: BLE001
        error = str(e)
    return templates.TemplateResponse(request, "_versions.html",
                                      {"request": request, "app_id": app_id,
                                       "versions": versions, "error": error})


@router.get("/app/{app_id}/download")
def act_download(app_id: str, _: None = Depends(require_auth)):
    ac = get_db().get_acquisition(app_id)
    if not ac or not ac["ipa_path"] or not os.path.exists(ac["ipa_path"]):
        raise HTTPException(status_code=404, detail="no decrypted IPA for this app")
    return FileResponse(ac["ipa_path"], filename=os.path.basename(ac["ipa_path"]),
                        media_type="application/octet-stream")


@router.post("/app/{app_id}/classify")
def act_classify(app_id: str, request: Request, _: None = Depends(require_auth)):
    _app_or_404(app_id)

    def job(ctx):
        from ... import static_classify
        with tee_pipeline_logs(ctx):
            prof = static_classify.classify_one(get_db(), app_id)
            ctx.log(f"pinned={prof.pins_flag} layer={prof.pin_layer} "
                    f"library={prof.pin_library} attest={prof.appattest_flag}\n")

    get_jobs_manager().submit("static", app_id, job, device_bound=False)
    return templates.TemplateResponse(request, "_action_queued.html",
                                      {"request": request, "app_id": app_id, "what": "classify"})


@router.post("/app/{app_id}/analyze")
def act_analyze(app_id: str, request: Request, _: None = Depends(require_auth)):
    _app_or_404(app_id)

    def job(ctx):
        from ... import analysis
        with tee_pipeline_logs(ctx):
            analysis.analyze_one(get_db(), app_id, log_fn=ctx.log)

    get_jobs_manager().submit("deep_analyze", app_id, job, device_bound=False)
    return templates.TemplateResponse(request, "_action_queued.html",
                                      {"request": request, "app_id": app_id, "what": "analyze"})


@router.post("/app/{app_id}/dynamic")
def act_dynamic(app_id: str, request: Request, _: None = Depends(require_auth)):
    row = _app_or_404(app_id)

    def job(ctx):
        from ... import device, dynamic
        with tee_pipeline_logs(ctx):
            driver = device.default_driver()
            label = dynamic.process_app(get_db(), row, driver)
            ctx.log(f"outcome: {getattr(label, 'value', label)}\n")

    get_jobs_manager().submit("dynamic", app_id, job, device_bound=True)
    return templates.TemplateResponse(request, "_action_queued.html",
                                      {"request": request, "app_id": app_id, "what": "dynamic"})


@router.post("/app/{app_id}/attest")
def act_attest(app_id: str, request: Request, _: None = Depends(require_auth)):
    row = _app_or_404(app_id)

    def job(ctx):
        from ... import attestation
        with tee_pipeline_logs(ctx):
            accounts = attestation.load_accounts()
            v = attestation.process_app(get_db(), row, accounts)
            ctx.log(f"verdict: {getattr(v, 'value', v)}\n")

    get_jobs_manager().submit("attest", app_id, job, device_bound=True)
    return templates.TemplateResponse(request, "_action_queued.html",
                                      {"request": request, "app_id": app_id, "what": "attest"})
