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


def _decrypted_files(app_id: str) -> list[dict]:
    """All decrypted IPAs on disk for this app (current + specific versions),
    since acquiring multiple versions writes multiple files (the acquisition row
    only records the latest)."""
    import glob
    from ...config import CONFIG
    d = str(CONFIG.paths.ipa_dir)
    out = []
    for p in sorted(glob.glob(os.path.join(d, f"{app_id}*.decrypted.ipa"))):
        name = os.path.basename(p)
        if name != f"{app_id}.decrypted.ipa" and not name.startswith(f"{app_id}-v"):
            continue  # avoid matching a different app whose id shares this prefix
        rest = name[len(app_id):]
        version = rest[2:].rsplit(".decrypted", 1)[0] if rest.startswith("-v") else "current"
        try:
            mb = round(os.path.getsize(p) / (1024 * 1024), 1)
        except OSError:
            mb = 0
        out.append({"name": name, "version": version, "size_mb": mb})
    return out


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
        ctx["decrypted_files"] = _decrypted_files(app_id)
    elif tab == "static":
        prof = db.get_static_profile(app_id)
        ctx["profile"] = prof
        ctx["matched"] = _decode_matched(prof)
        an = db.get_analysis(app_id)
        ctx["analysis"] = _decode_analysis(an) if an else None
    elif tab == "dynamic":
        ctx["runs"] = db.get_dynamic_runs(app_id)
        ctx["outcome"] = db.get_outcome(app_id)
    elif tab == "attest":
        ctx["attestation"] = db.get_attestation(app_id)
    return ctx


_MATCH_LABELS = {
    "pin": "Native pinning", "pinlib": "Pin library", "tls": "TLS stack",
    "anti_tamper": "Anti-tamper", "anti_debug": "Anti-debug",
    "jailbreak_detection": "Jailbreak detection", "appattest": "App Attest",
    "devicecheck": "DeviceCheck", "networkextension": "Network Extension",
}


def _decode_matched(profile) -> list[dict]:
    """Parse static_profile.matched_patterns JSON into [{label, tokens}] groups
    with human labels, for a clean UI instead of raw JSON."""
    import json
    if not profile:
        return []
    try:
        raw = json.loads(profile["matched_patterns"] or "{}")
    except Exception:
        return []
    groups = []
    for key, tokens in raw.items():
        base = key.split(":", 1)
        label = _MATCH_LABELS.get(base[0], base[0].replace("_", " ").title())
        if len(base) == 2:
            label = f"{label}: {base[1]}"
        toks = tokens if isinstance(tokens, list) else [tokens]
        groups.append({"label": label, "tokens": [str(t) for t in toks]})
    return groups


def _decode_analysis(row) -> dict:
    import json
    out = {}
    for k in ("info_plist", "entitlements", "ats", "frameworks", "sdks",
              "secrets", "file_tree", "crypto_hints", "binary_protections",
              "insecure_apis", "binary_type", "security_score"):
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

def _watch(request: Request, app_id: str, job_id: int, tab: str):
    """Render the live job-watch widget that self-polls and, on completion,
    reloads the given tab into #tab-content and fires a browser notification."""
    return templates.TemplateResponse(request, "_job_watch.html", {
        "request": request, "job": get_db().get_job(job_id),
        "reload": f"/app/{app_id}/tab/{tab}"})

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

    jid = get_jobs_manager().submit("acquire", app_id, job, device_bound=True,
                                    params={"version": version})
    return _watch(request, app_id, jid, "acquire")


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
def act_download(app_id: str, file: str = "", _: None = Depends(require_auth)):
    from ...config import CONFIG
    if file:
        # Serve a specific decrypted file (must belong to this app, no traversal).
        base = os.path.basename(file)
        if base != f"{app_id}.decrypted.ipa" and not base.startswith(f"{app_id}-v"):
            raise HTTPException(status_code=400, detail="bad file")
        path = os.path.join(str(CONFIG.paths.ipa_dir), base)
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="file not found")
        return FileResponse(path, filename=base, media_type="application/octet-stream")
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

    jid = get_jobs_manager().submit("static", app_id, job, device_bound=False)
    return _watch(request, app_id, jid, "static")


@router.post("/app/{app_id}/analyze")
def act_analyze(app_id: str, request: Request, _: None = Depends(require_auth)):
    _app_or_404(app_id)

    def job(ctx):
        from ... import analysis
        with tee_pipeline_logs(ctx):
            analysis.analyze_one(get_db(), app_id, log_fn=ctx.log)

    jid = get_jobs_manager().submit("deep_analyze", app_id, job, device_bound=False)
    return _watch(request, app_id, jid, "static")


@router.post("/app/{app_id}/dynamic")
def act_dynamic(app_id: str, request: Request, _: None = Depends(require_auth)):
    row = _app_or_404(app_id)

    def job(ctx):
        from ... import device, dynamic
        with tee_pipeline_logs(ctx):
            driver = device.default_driver()
            label = dynamic.process_app(get_db(), row, driver)
            ctx.log(f"outcome: {getattr(label, 'value', label)}\n")

    jid = get_jobs_manager().submit("dynamic", app_id, job, device_bound=True)
    return _watch(request, app_id, jid, "dynamic")


@router.post("/app/{app_id}/attest")
def act_attest(app_id: str, request: Request, _: None = Depends(require_auth)):
    row = _app_or_404(app_id)

    def job(ctx):
        from ... import attestation
        with tee_pipeline_logs(ctx):
            accounts = attestation.load_accounts()
            v = attestation.process_app(get_db(), row, accounts)
            ctx.log(f"verdict: {getattr(v, 'value', v)}\n")

    jid = get_jobs_manager().submit("attest", app_id, job, device_bound=True)
    return _watch(request, app_id, jid, "attest")
