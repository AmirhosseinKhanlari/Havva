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

TABS = ("overview", "acquire", "static", "dynamic", "iap", "attest")


def _parse_secs(val) -> int | None:
    """Clamp a user-supplied capture window to 3..300s; None => use config default."""
    try:
        n = int(val)
    except (TypeError, ValueError):
        return None
    return max(3, min(300, n))


def _ipa_dir() -> str:
    """Absolute IPA directory (IPA_DIR may be relative, e.g. './ipas'; resolve it
    against the project root so lookups don't depend on the server's CWD)."""
    from pathlib import Path
    from ...config import CONFIG
    d = CONFIG.paths.ipa_dir
    if not d.is_absolute():
        d = CONFIG.paths.root / d
    return str(d)


def _decode_json_field(row, key: str) -> dict:
    """JSON column -> dict ({} when absent / unparseable)."""
    try:
        if row is None or key not in row.keys() or not row[key]:
            return {}
        import json as _json
        v = _json.loads(row[key])
        return v if isinstance(v, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _decode_storage(row):
    """Decode the storage_probe row's JSON fields for the template."""
    if not row:
        return None
    import json
    def _j(v, default):
        try:
            return json.loads(v) if v else default
        except (ValueError, TypeError):
            return default
    return {"verdict": row["verdict"], "note": row["note"],
            "findings": _j(row["findings"], []), "stores": _j(row["stores"], {}),
            "probed_at": row["probed_at"]}


def _is_acquired(app_id: str) -> bool:
    """True if a usable decrypted IPA exists for this app -- the same thing the
    pipeline needs to run static/dynamic. Checks the on-disk files AND the
    acquisition record (resolved against the project root)."""
    from pathlib import Path
    from ...config import CONFIG
    if _decrypted_files(app_id):
        return True
    ac = get_db().get_acquisition(app_id)
    if ac and ac["ipa_path"]:
        p = Path(ac["ipa_path"])
        if not p.is_absolute():
            p = CONFIG.paths.root / p
        return p.exists()
    return False


def _decrypted_files(app_id: str) -> list[dict]:
    """All decrypted IPAs on disk for this app (current + specific versions),
    since acquiring multiple versions writes multiple files (the acquisition row
    only records the latest)."""
    import glob
    d = _ipa_dir()
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


_TAB_JOB_KINDS = {"acquire": ("acquire",),
                  "static": ("static", "deep_analyze"),
                  "dynamic": ("dynamic",),
                  "iap": ("iap",),
                  "attest": ("attest", "attest_detect")}


def _tab_context(request: Request, app_id: str, tab: str) -> dict:
    db = get_db()
    app = _app_or_404(app_id)
    ctx = {"request": request, "app": app, "app_id": app_id, "tab": tab, "tabs": TABS, "nav": "corpus"}
    # Re-attach to an in-progress job so switching tabs doesn't lose the live view.
    kinds = _TAB_JOB_KINDS.get(tab)
    if kinds:
        aj = db.active_job(app_id, kinds)
        if aj:
            from .jobs import _job_phase
            ctx["active_job"] = aj
            ctx["active_phase"] = _job_phase(aj)
            ctx["active_reload"] = f"/app/{app_id}/tab/{tab}"
    if tab == "acquire":
        ctx["acq"] = db.get_acquisition(app_id)
        ctx["acq_versions"] = db.get_acquisition_versions(app_id)
        ctx["decrypted_files"] = _decrypted_files(app_id)
    # (static branch below sets ctx["plist"] via _plist_view)
    elif tab == "static":
        ctx["acquired"] = _is_acquired(app_id)
        prof = db.get_static_profile(app_id)
        ctx["profile"] = prof
        ctx["matched"] = _decode_matched(prof)
        an = db.get_analysis(app_id)
        ctx["analysis"] = _decode_analysis(an) if an else None
        ctx["plist"] = _plist_view(ctx["analysis"]) if ctx["analysis"] else None
    elif tab == "dynamic":
        ctx["acquired"] = _is_acquired(app_id)
        ctx["runs"] = db.get_dynamic_runs(app_id)
        ctx["outcome"] = db.get_outcome(app_id)
        ctx["pinning"] = db.get_pinning_probe(app_id)
        ctx["sideload"] = db.get_sideload_probe(app_id)
        ctx["sideload_evidence"] = _decode_json_field(ctx["sideload"], "evidence")
        ctx["storage"] = _decode_storage(db.get_storage_probe(app_id))
        from ... import instrument
        from ...config import CONFIG
        ctx["dylibs"] = instrument.dylib_catalog()
        ctx["monitor_default"] = CONFIG.runtime.monitor_seconds
    elif tab == "iap":
        ctx["acquired"] = _is_acquired(app_id)
        ctx["iap"] = _decode_iap(db.get_iap_bypass(app_id))
        an = db.get_analysis(app_id)
        ctx["iap_static"] = (_decode_analysis(an).get("iap") if an else None)
        ctx["has_iap"] = bool(app["has_iap"]) if "has_iap" in app.keys() else None
        from ...config import CONFIG
        ctx["monitor_default"] = CONFIG.runtime.monitor_seconds
    elif tab == "attest":
        ctx["attestation"] = db.get_attestation(app_id)
        ctx["attest_probes"] = _decode_json_field(ctx["attestation"], "probe_results")
        ctx["attest_usage"] = _attest_usage(db, app_id)
    return ctx


_ATTEST_USAGE_SUMMARY = {
    "none": "No App Attest or DeviceCheck usage detected.",
    "capable": "Provisioned for App Attest (entitlement present), but runtime usage not confirmed.",
    "likely": "The app ships App Attest / DeviceCheck code, but it was not called during this run.",
    "confirmed_active": "The app actively calls App Attest / DeviceCheck at runtime.",
    "confirmed_located": "The app calls App Attest / DeviceCheck and sends a token to a server.",
}


def _attest_usage(db, app_id: str) -> dict | None:
    """Usage-detection results (attest_detect observer), translated to plain
    language. Columns may be absent until the observer has run once."""
    import json
    try:
        with db.connect() as c:
            row = c.execute("SELECT * FROM static_profile WHERE app_id=?", (app_id,)).fetchone()
    except Exception:
        return None
    if not row:
        return None
    d = dict(row)
    conf = d.get("attest_confidence")
    if not conf:
        return None
    try:
        methods = json.loads(d.get("attest_methods_seen") or "[]")
    except (ValueError, TypeError):
        methods = []
    try:
        trail = json.loads(d.get("attest_trail") or "{}")
    except (ValueError, TypeError):
        trail = {}
    try:
        requests = json.loads(d.get("attest_requests") or "[]")
    except (ValueError, TypeError):
        requests = []
    endpoint = d.get("attested_endpoint") or ""
    tooling_ok = bool(d.get("attest_tooling_ok"))

    # Detected-calls table: every hooked attestation method + whether it fired.
    _SEL = {
        "generateKeyWithCompletionHandler:": ("App Attest", "generateKey", "DCAppAttestService generateKey"),
        "attestKey:clientDataHash:completionHandler:": ("App Attest", "attestKey", "DCAppAttestService attestKey"),
        "generateAssertion:clientDataHash:completionHandler:": ("App Attest", "generateAssertion", "DCAppAttestService generateAssertion"),
        "generateTokenWithCompletionHandler:": ("DeviceCheck", "generateToken", "DCDevice generateToken"),
    }
    calls_set = set(trail.get("calls") or [])
    calls_table = []
    for sel in (trail.get("verified") or []):
        api, fn, callkey = _SEL.get(sel, ("?", sel, ""))
        calls_table.append({"api": api, "function": fn, "hooked": True,
                            "called": callkey in calls_set})

    def _status(api_name):
        rows = [c for c in calls_table if c["api"] == api_name]
        if any(c["called"] for c in rows):
            return "Called", "var(--accent)"
        if rows:
            return "Present", "var(--warn)"
        return "Not detected", "var(--ink3)"

    aa_status, aa_color = _status("App Attest")
    dc_status, dc_color = _status("DeviceCheck")
    used = aa_status == "Called" or dc_status == "Called"

    bits = ["Detector ran correctly, so this result is reliable." if tooling_ok
            else "Detector could not fully confirm, so treat this result as unreliable."]
    if methods:
        bits.append("Calls seen: " + ", ".join(methods) + ".")
    elif trail.get("class_present"):
        bits.append("Attestation code is present and was being watched, but nothing fired "
                    "during this session (it may run only after login or on a specific screen).")
    elif trail.get("class_absent"):
        bits.append("No attestation class was found in the running app.")
    if endpoint:
        bits.append("Token observed going to: " + endpoint + ".")

    launches = int(trail.get("launches") or 0)
    crashed = bool(trail.get("crashed"))  # crash report captured this run (not launch count)
    summary = _ATTEST_USAGE_SUMMARY.get(conf, conf)
    if crashed:
        summary = "App crashed on launch — possible anti-tamper or integrity enforcement."
        bits.append("A crash report was captured during the session, so the app likely refuses "
                    "to run re-signed; the 'not called' result is unreliable.")

    return {"confidence": conf,
            "summary": summary,
            "detail": " ".join(bits),
            "methods": methods, "endpoint": endpoint, "tooling_ok": tooling_ok,
            "calls_table": calls_table, "requests": requests,
            "aa_status": aa_status, "aa_color": aa_color,
            "dc_status": dc_status, "dc_color": dc_color, "used": used,
            "crashed": crashed, "launches": launches}


def _decode_iap(row) -> dict | None:
    if not row:
        return None
    import json
    def _j(v):
        try:
            return json.loads(v) if v else []
        except (ValueError, TypeError):
            return []
    return {"verdict": row["verdict"], "tamperable": row["tamperable"],
            "fields": _j(row["fields"]), "urls": _j(row["urls"]),
            "method": row["method"], "analysis": row["analysis"],
            "error": row["error"], "n_iap_flows": row["n_iap_flows"],
            "probed_at": row["probed_at"]}


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
              "insecure_apis", "binary_type", "security_score", "trackers",
              "dependencies", "privacy_manifest", "bundled_certs",
              "app_extensions", "ats_gap", "iap"):
        try:
            out[k] = json.loads(row[k]) if row[k] else None
        except Exception:
            out[k] = None
    # Dependencies: normalize `cves` to a list and precompute its length so the
    # template can sort on a scalar (sorting on the list itself 500s with >=2
    # vulnerable deps, since dicts are not orderable).
    deps = out.get("dependencies")
    if isinstance(deps, list):
        norm = []
        for d in deps:
            if not isinstance(d, dict):
                continue
            d = dict(d)
            cves = d.get("cves")
            d["cves"] = cves if isinstance(cves, list) else []
            d["n_cves"] = len(d["cves"])
            norm.append(d)
        out["dependencies"] = norm
    else:
        out["dependencies"] = None
    out["analyzed_at"] = row["analyzed_at"]
    return out


_PERM_META = {
    "NSCameraUsageDescription": ("Camera", "\U0001F4F7"),
    "NSMicrophoneUsageDescription": ("Microphone", "\U0001F3A4"),
    "NSLocationWhenInUseUsageDescription": ("Location — When in use", "\U0001F4CD"),
    "NSLocationAlwaysUsageDescription": ("Location — Always", "\U0001F4CD"),
    "NSLocationAlwaysAndWhenInUseUsageDescription": ("Location — Always", "\U0001F4CD"),
    "NSLocationUsageDescription": ("Location", "\U0001F4CD"),
    "NSPhotoLibraryUsageDescription": ("Photos", "\U0001F5BC️"),
    "NSPhotoLibraryAddUsageDescription": ("Photos — Add", "\U0001F5BC️"),
    "NSContactsUsageDescription": ("Contacts", "\U0001F465"),
    "NSCalendarsUsageDescription": ("Calendar", "\U0001F4C5"),
    "NSRemindersUsageDescription": ("Reminders", "✅"),
    "NSUserTrackingUsageDescription": ("Tracking (ATT)", "\U0001F3AF"),
    "NSNearbyInteractionUsageDescription": ("Nearby Interaction", "\U0001F4E1"),
    "NSUserDeclaredAgeRangeUsageDescription": ("Declared Age Range", "\U0001F51E"),
    "NSBluetoothAlwaysUsageDescription": ("Bluetooth", "\U0001F535"),
    "NSBluetoothPeripheralUsageDescription": ("Bluetooth", "\U0001F535"),
    "NSFaceIDUsageDescription": ("Face ID", "\U0001F642"),
    "NSMotionUsageDescription": ("Motion & Fitness", "\U0001F3C3"),
    "NSSpeechRecognitionUsageDescription": ("Speech Recognition", "\U0001F5E3️"),
    "NSHealthShareUsageDescription": ("Health — Read", "❤️"),
    "NSHealthUpdateUsageDescription": ("Health — Write", "❤️"),
    "NSAppleMusicUsageDescription": ("Media Library", "\U0001F3B5"),
    "NSSiriUsageDescription": ("Siri", "\U0001F399️"),
    "NSLocalNetworkUsageDescription": ("Local Network", "\U0001F6DC"),
}


def _friendly_perm(key: str) -> tuple[str, str]:
    import re
    if key in _PERM_META:
        return _PERM_META[key]
    base = key[:-len("UsageDescription")] if key.endswith("UsageDescription") else key
    if base.startswith("NS"):
        base = base[2:]
    nice = re.sub(r"(?<!^)(?=[A-Z])", " ", base).strip()
    return (nice or key, "\U0001F510")


def _plist_view(report: dict | None) -> dict | None:
    """Structured, display-ready view of Info.plist: identity, background modes,
    URL schemes, queryable apps, and friendly privacy permissions."""
    ip = (report or {}).get("info_plist") or {}
    summ = ip.get("summary") or {}
    perms = ip.get("permissions") or {}
    if not summ and not perms:
        return None
    identity = []
    for label, key in (("Bundle ID", "CFBundleIdentifier"), ("Name", "CFBundleName"),
                       ("Display name", "CFBundleDisplayName"),
                       ("Version", "CFBundleShortVersionString"), ("Build", "CFBundleVersion"),
                       ("Min iOS", "MinimumOSVersion"), ("Executable", "CFBundleExecutable")):
        if summ.get(key):
            identity.append((label, str(summ[key])))
    schemes: list[str] = []
    for t in (summ.get("CFBundleURLTypes") or []):
        if isinstance(t, dict):
            schemes.extend(t.get("CFBundleURLSchemes") or [])
    permissions = []
    for key in sorted(perms):
        name, icon = _friendly_perm(key)
        permissions.append({"key": key, "name": name, "icon": icon, "desc": perms[key]})
    return {
        "identity": identity,
        "bg_modes": list(summ.get("UIBackgroundModes") or []),
        "url_schemes": sorted({s for s in schemes if s}),
        "query_schemes": sorted({s for s in (summ.get("LSApplicationQueriesSchemes") or []) if s}),
        "permissions": permissions,
    }


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
    """Render the live job-watch widget (log console + polling status) that, on
    completion, reloads the given tab and fires a browser notification."""
    from .jobs import _job_phase
    job = get_db().get_job(job_id)
    return templates.TemplateResponse(request, "_job_watch.html", {
        "request": request, "job": job, "reload": f"/app/{app_id}/tab/{tab}",
        "phase": _job_phase(job) if job else ""})

@router.post("/app/{app_id}/acquire")
def act_acquire(app_id: str, request: Request, version: str = Form(default=""),
                _: None = Depends(require_auth)):
    app = _app_or_404(app_id)
    # Key the acquisition by the SAME id as the corpus row (app_id), so the app
    # detail page finds it. acquire_one keys by bundle_id when one is passed, so
    # for a numeric corpus id we pass app_id only (numeric ids are App Store
    # store ids, which both backends accept); for a non-numeric corpus id we fall
    # back to the bundle.
    # Acquire needs the jailbroken iPhone 8 for FairPlay decryption. If it's
    # offline, don't start the process (downloading would be wasted).
    from ...config import CONFIG
    dd = CONFIG.decrypt_device
    if not dd.online():
        from fastapi.responses import HTMLResponse
        where = f"{dd.ssh_host}:{dd.ssh_port}" if dd.ssh_host else "(DECRYPT_SSH_HOST not set)"
        return HTMLResponse(
            f'<div class="glass sm" style="padding:14px 16px;border:1px solid var(--bad)">'
            f'<div style="font-weight:700;color:var(--bad)">Decrypt device offline</div>'
            f'<div class="muted" style="font-size:12.5px;margin-top:4px">The jailbroken iPhone 8 '
            f'({where}) is not reachable. Acquire needs it for FairPlay decryption. '
            f'Connect it and try again.</div></div>')

    numeric = str(app_id).isdigit()
    bundle = None if numeric else app["bundle_id"]
    store_id = app_id if numeric else None

    def job(ctx):
        from ... import acquire
        with tee_pipeline_logs(ctx):
            state, path, err = acquire.acquire_one(
                get_db(), bundle_id=bundle, app_id=store_id,
                country=app["country"] or "us", app_ver_id=version or None,
                progress_cb=ctx.progress)
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
    if file:
        # Serve a specific decrypted file (must belong to this app, no traversal).
        base = _owned_ipa_name(app_id, file)
        path = os.path.join(_ipa_dir(), base)
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="file not found")
        return FileResponse(path, filename=base, media_type="application/octet-stream")
    ac = get_db().get_acquisition(app_id)
    path = _abs_ipa_path(ac["ipa_path"]) if ac and ac["ipa_path"] else ""
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="no decrypted IPA for this app")
    return FileResponse(path, filename=os.path.basename(path),
                        media_type="application/octet-stream")


def _owned_ipa_name(app_id: str, file: str) -> str:
    """The bare file name of a decrypted IPA that belongs to `app_id`
    ({app_id}.decrypted.ipa or {app_id}-v<ver>.decrypted.ipa); 400 otherwise."""
    base = os.path.basename(file or "")
    ok = (base == f"{app_id}.decrypted.ipa"
          or (base.startswith(f"{app_id}-v") and base.endswith(".decrypted.ipa")))
    if not ok or "/" in base or ".." in base:
        raise HTTPException(status_code=400, detail="bad file")
    return base


def _abs_ipa_path(p: str) -> str:
    """Resolve a stored ipa_path (possibly relative) against the project root,
    the same way the listing does."""
    from ...config import CONFIG
    if not p:
        return ""
    if os.path.isabs(p):
        return p
    return str(CONFIG.paths.root / p)


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


@router.post("/app/{app_id}/remove")
def act_remove(app_id: str, request: Request, file: str = Form(...),
               _: None = Depends(require_auth)):
    """Delete one decrypted IPA for this app, then re-render the Acquire tab."""
    from ...models import WorkState
    base = _owned_ipa_name(app_id, file)
    ipa_dir = _ipa_dir()
    path = os.path.join(ipa_dir, base)
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"could not remove: {e}")
    # Keep the acquisition rows consistent with what's left on disk.
    db = get_db()
    remaining = _decrypted_files(app_id)
    ac = db.get_acquisition(app_id)
    if ac and os.path.basename(ac["ipa_path"] or "") == base:
        current = [f for f in remaining if f["version"] == "current"]
        if current:
            db.save_acquisition(app_id, WorkState.POSITIVE,
                                ipa_path=os.path.join(ipa_dir, current[0]["name"]))
        else:
            db.delete_acquisition(app_id)
    for v in db.get_acquisition_versions(app_id):
        if v["ipa_path"] and os.path.basename(v["ipa_path"]) == base:
            db.save_acquisition_version(app_id, v["version_id"], WorkState.UNTESTED,
                                        ipa_path="", error="removed from disk")
    return templates.TemplateResponse(request, "_tab_acquire.html",
                                      _tab_context(request, app_id, "acquire"))


@router.post("/app/{app_id}/analyze")
def act_analyze(app_id: str, request: Request, _: None = Depends(require_auth)):
    _app_or_404(app_id)

    def job(ctx):
        from ... import analysis
        with tee_pipeline_logs(ctx):
            analysis.analyze_one(get_db(), app_id, log_fn=ctx.log)

    jid = get_jobs_manager().submit("deep_analyze", app_id, job, device_bound=False)
    return _watch(request, app_id, jid, "static")


@router.post("/app/{app_id}/ats-gap")
def act_ats_gap(app_id: str, request: Request, _: None = Depends(require_auth)):
    """ATS declared-vs-needed gap via nscurl (MASTG-TECH-0149)."""
    _app_or_404(app_id)

    def job(ctx):
        from ... import ats_runtime
        with tee_pipeline_logs(ctx):
            ctx.log("ATS declared-vs-needed gap (nscurl per endpoint) ...\n")
            res = ats_runtime.assess_and_store(get_db(), app_id)
            if res.get("checked"):
                ctx.log(f"verdict: {res['verdict']} | {res['n_pass_default']}/{res['n_tested']} "
                        f"pass default ATS | {res['n_unnecessary']} unnecessary weakening(s)\n")
            else:
                ctx.log(f"skipped: {res.get('reason')}\n")

    jid = get_jobs_manager().submit("deep_analyze", app_id, job, device_bound=False)
    return _watch(request, app_id, jid, "static")


@router.get("/app/{app_id}/sbom")
def act_sbom(app_id: str, _: None = Depends(require_auth)):
    """Download a CycloneDX SBOM for the app (MASTG-TECH-0132)."""
    import json
    from fastapi.responses import Response
    from ... import cve
    db = get_db()
    an = db.get_analysis(app_id)
    if not an:
        raise HTTPException(status_code=404, detail="not analyzed yet")
    deps = json.loads(an["dependencies"]) if an["dependencies"] else []
    row = db.get_app(app_id)
    meta = {"app_id": app_id, "name": row["name"] if row else app_id,
            "version": (row["current_version"] if row else "")}
    sbom = cve.build_sbom(meta, deps)
    return Response(content=json.dumps(sbom, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="sbom_{app_id}.json"'})


@router.post("/app/{app_id}/dynamic")
async def act_dynamic(app_id: str, request: Request, _: None = Depends(require_auth)):
    row = _app_or_404(app_id)
    form = await request.form()
    entshim = form.get("entshim") == "on"

    def job(ctx):
        from ... import device, dynamic
        with tee_pipeline_logs(ctx):
            if entshim:
                ctx.log("entitlement-shim injected (swallows re-sign entitlement-loss crashes)\n")
            driver = device.default_driver()
            label = dynamic.process_app(get_db(), row, driver, entshim=entshim,
                                        stop_check=lambda: ctx.cancelled)
            ctx.log(f"outcome: {getattr(label, 'value', label)}\n")

    jid = get_jobs_manager().submit("dynamic", app_id, job, device_bound=True)
    return _watch(request, app_id, jid, "dynamic")


@router.post("/app/{app_id}/dynamic/custom")
async def act_dynamic_custom(app_id: str, request: Request, _: None = Depends(require_auth)):
    """Run one dynamic pass injecting exactly the user-selected dylibs."""
    row = _app_or_404(app_id)
    form = await request.form()
    dylib_ids = form.getlist("dylibs")
    aliased = form.get("aliased") == "on"
    sign_env = form.get("sign_env") or "dist"
    monitor_seconds = _parse_secs(form.get("monitor_seconds"))
    swap_certs = form.get("swap_certs") == "on"
    if form.get("entshim") == "on" and "entshim" not in dylib_ids:
        dylib_ids = [*dylib_ids, "entshim"]
    if not dylib_ids:
        raise HTTPException(status_code=400, detail="select at least one dylib")
    # Only catalog ids are valid: the ids end up in the build label (a work-dir
    # name that gets rmtree'd), so anything else is rejected outright.
    from ... import instrument
    valid = {it["id"] for it in instrument.dylib_catalog()}
    unknown = [d for d in dylib_ids if d not in valid]
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown dylib id(s): {', '.join(map(str, unknown))}")
    dylib_ids = list(dict.fromkeys(dylib_ids))     # de-dup, keep order
    if sign_env not in ("dev", "dist"):
        raise HTTPException(status_code=400, detail="sign_env must be dev or dist")

    def job(ctx):
        from ... import device, dynamic
        with tee_pipeline_logs(ctx):
            ctx.log(f"injecting: {', '.join(dylib_ids)} (aliased={aliased}, signing={sign_env}, "
                    f"{monitor_seconds or 'default'}s window{', cert-swap' if swap_certs else ''})\n")
            driver = device.default_driver()
            run = dynamic.run_custom(get_db(), row, driver, list(dylib_ids),
                                     aliased=aliased, sign_env=sign_env,
                                     monitor_seconds=monitor_seconds, swap_certs=swap_certs,
                                     stop_check=lambda: ctx.cancelled)
            ctx.log(f"outcome: hosts={len(run.hosts)} crashed={run.crashed} "
                    f"reached_network={run.reached_network}\n")

    jid = get_jobs_manager().submit("dynamic", app_id, job, device_bound=True,
                                    params={"dylibs": list(dylib_ids), "aliased": aliased,
                                            "sign_env": sign_env})
    return _watch(request, app_id, jid, "dynamic")


@router.post("/app/{app_id}/dynamic/pinning")
async def act_dynamic_pinning(app_id: str, request: Request, _: None = Depends(require_auth)):
    """Differential SSL-pinning probe: two Proxyman MITM runs (clean vs SSL
    Kill Switch), report the endpoints that only decrypt once pinning is
    bypassed -> those endpoints enforce pinning."""
    row = _app_or_404(app_id)
    form = await request.form()
    aliased = form.get("aliased") == "on"
    sign_env = form.get("sign_env") or "dist"
    monitor_seconds = _parse_secs(form.get("monitor_seconds"))
    swap_certs = form.get("swap_certs") == "on"
    login = form.get("login") == "on"
    entshim = form.get("entshim") == "on"

    def job(ctx):
        from ... import device, dynamic
        with tee_pipeline_logs(ctx):
            ctx.log(f"SSL-pinning probe ({sign_env} signing, {monitor_seconds or 'default'}s window"
                    f"{', cert-swap' if swap_certs else ''}{', UI login' if login else ''}"
                    f"{', entitlement-shim' if entshim else ''}): "
                    "2 MITM runs (clean baseline, then SSL Kill Switch)\n")
            driver = device.default_driver()
            res = dynamic.detect_pinning(get_db(), row, driver, aliased=aliased,
                                         sign_env=sign_env, monitor_seconds=monitor_seconds,
                                         swap_certs=swap_certs, login=login, entshim=entshim,
                                         stop_check=lambda: ctx.cancelled)
            if res.get("crashed"):
                ctx.log("verdict: TAMPER_DETECTED — the app crashed/exited on launch when "
                        "re-signed (anti-tamper / integrity enforcement). Cannot MITM it to "
                        "test pinning; skipped the bypass run.\n")
                return
            tag = "" if res["reliable"] else " (open/bypassed split UNRELIABLE: clean run did not launch)"
            rj = res.get("rejections", {})
            ctx.log(f"bypassable-pinned: {len(res['pinned'])} | "
                    f"hard-pinned: {len(res['hard_pinned'])} | "
                    f"open: {len(res['not_pinned'])} | "
                    f"leads: {len(res.get('leads', []))} | unverified: {len(res.get('unverified', []))}"
                    f"{tag}\n")
            ctx.log(f"CA rejections in the device syslog (this app's process): "
                    f"clean={rj.get('clean', 0)} bypass={rj.get('bypass', 0)}\n")
            for h in res["pinned"]:
                ctx.log(f"  \N{LOCK} {h} (bypassed by SSL Kill Switch)\n")
            for h in res["hard_pinned"]:
                ctx.log(f"  \N{SHIELD} {h} (HARD-PINNED: rejected our CA even with the bypass)\n")
            for h in res.get("leads", []):
                ctx.log(f"  lead: {h} (upstream TLS failure, not attributed; confirm by hand)\n")
            for h in res.get("unverified", []):
                ctx.log(f"  unverified: {h} (seen only in the bypass window; not counted)\n")
            ctx.log(f"verdict: {res.get('outcome', '?').upper()}\n")

    jid = get_jobs_manager().submit("dynamic", app_id, job, device_bound=True,
                                    params={"mode": "pinning", "aliased": aliased})
    return _watch(request, app_id, jid, "dynamic")


@router.post("/app/{app_id}/dynamic/sideload")
async def act_dynamic_sideload(app_id: str, request: Request, _: None = Depends(require_auth)):
    """Sideload / anti-resign detection: launch a plain re-sign vs a SideloadFix
    build and compare whether each stays running."""
    row = _app_or_404(app_id)
    form = await request.form()
    sign_env = form.get("sign_env") or "dist"
    monitor_seconds = _parse_secs(form.get("monitor_seconds"))
    entshim = form.get("entshim") == "on"

    def job(ctx):
        from ... import dynamic
        with tee_pipeline_logs(ctx):
            ctx.log(f"sideload-detection probe ({sign_env} signing, {monitor_seconds or 'default'}s"
                    f"{', entitlement-shim' if entshim else ''}): "
                    "plain re-sign (control) vs SideloadFix\n")
            res = dynamic.detect_sideload(get_db(), row, sign_env=sign_env,
                                          monitor_seconds=monitor_seconds, entshim=entshim,
                                          stop_check=lambda: ctx.cancelled)
            ev = res.get("evidence", {})
            for arm in ("control", "fixed"):
                a = ev.get(arm, {})
                ctx.log(f"  {arm}: {a.get('status')}"
                        f"{' class=' + a['crash_class'] if a.get('crash_class') not in (None, 'none') else ''}"
                        f"{' intent=' + a['intent'] if a.get('intent') else ''}"
                        f"{' reason: ' + a['reason'][:160] if a.get('reason') else ''}\n")
            if ev.get("static_markers"):
                ctx.log(f"  static integrity markers: {', '.join(ev['static_markers'])}\n")
            ctx.log(f"verdict: {res['verdict']} — {res['note']}\n")

    jid = get_jobs_manager().submit("dynamic", app_id, job, device_bound=True,
                                    params={"mode": "sideload", "sign_env": sign_env})
    return _watch(request, app_id, jid, "dynamic")


@router.post("/app/{app_id}/dynamic/storage")
async def act_dynamic_storage(app_id: str, request: Request, _: None = Depends(require_auth)):
    """Dynamic insecure-data-storage inspection: run the app, pull its container,
    scan the unencrypted stores for secrets/sensitive values."""
    row = _app_or_404(app_id)
    form = await request.form()
    sign_env = form.get("sign_env") or "dev"
    monitor_seconds = _parse_secs(form.get("monitor_seconds"))
    entshim = form.get("entshim") == "on"
    login = form.get("login") == "on"

    def job(ctx):
        from ... import dynamic
        with tee_pipeline_logs(ctx):
            ctx.log(f"data-storage inspection ({sign_env} signing, {monitor_seconds or 'default'}s"
                    f"{', entitlement-shim' if entshim else ''}{', UI login' if login else ''}): "
                    "drive app with StorageObserver, pull container, scan stores + Keychain\n")
            res = dynamic.inspect_storage(get_db(), row, sign_env=sign_env,
                                          monitor_seconds=monitor_seconds, entshim=entshim,
                                          login=login, stop_check=lambda: ctx.cancelled)
            by = {}
            for f in res["findings"]:
                by[f["severity"]] = by.get(f["severity"], 0) + 1
            ctx.log(f"verdict: {res['verdict']} — {len(res['findings'])} finding(s) "
                    f"({', '.join(f'{k}: {v}' for k, v in sorted(by.items()))})\n")
            ctx.log(f"{res['note']}\n")

    jid = get_jobs_manager().submit("dynamic", app_id, job, device_bound=True,
                                    params={"mode": "storage", "sign_env": sign_env})
    return _watch(request, app_id, jid, "dynamic")


@router.post("/app/{app_id}/iap-bypass")
async def act_iap_bypass(app_id: str, request: Request, _: None = Depends(require_auth)):
    """IAP / subscription bypass detection: capture decrypted IAP traffic and ask
    the Llama API whether any field is client-tamperable."""
    row = _app_or_404(app_id)
    form = await request.form()
    sign_env = form.get("sign_env") or "dist"
    monitor_seconds = _parse_secs(form.get("monitor_seconds"))
    swap_certs = form.get("swap_certs") == "on"
    entshim = form.get("entshim") == "on"

    def job(ctx):
        from ... import device, dynamic
        with tee_pipeline_logs(ctx):
            ctx.log(f"IAP bypass probe ({sign_env} signing{', entitlement-shim' if entshim else ''}): "
                    "launch with pinning bypass, capture IAP traffic, ask Llama if tamperable\n")
            driver = device.default_driver()
            res = dynamic.detect_iap_bypass(get_db(), row, driver, sign_env=sign_env,
                                            monitor_seconds=monitor_seconds, swap_certs=swap_certs,
                                            entshim=entshim, stop_check=lambda: ctx.cancelled)
            ctx.log(f"verdict: {res['verdict']} ({res.get('n_iap_flows', 0)} IAP flows)"
                    f"{' - ' + res['method'] if res.get('method') else ''}\n")

    jid = get_jobs_manager().submit("iap", app_id, job, device_bound=True,
                                    params={"sign_env": sign_env})
    return _watch(request, app_id, jid, "iap")


@router.post("/app/{app_id}/dynamic/clear")
def act_dynamic_clear(app_id: str, request: Request, _: None = Depends(require_auth)):
    """Clear this app's dynamic run history, then re-render the Dynamic tab."""
    get_db().clear_dynamic_runs(app_id)
    return templates.TemplateResponse(request, "_tab_dynamic.html",
                                      _tab_context(request, app_id, "dynamic"))


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


@router.post("/app/{app_id}/attest-detect")
def act_attest_detect(app_id: str, request: Request, manual: str = Form(""),
                      seconds: int = Form(0), login: str = Form(""),
                      entshim: str = Form(""),
                      _: None = Depends(require_auth)):
    """Observe-only App Attest / DeviceCheck usage detection (no server test).
    Injects AttestObserver, runs the app, records which attestation APIs fire.

    manual=on: launch the app and keep capturing for `seconds` while the human
    drives it by hand, and leave the app installed afterwards (no window-gated
    uninstall). Otherwise Appium drives it and the app is uninstalled.

    entshim=on also injects the EntitlementShim dylib (swallows re-sign
    entitlement-loss crashes so they aren't mis-read as tamper detection)."""
    row = _app_or_404(app_id)
    is_manual = manual.lower() in ("1", "on", "true", "yes")
    is_login = login.lower() in ("1", "on", "true", "yes")
    is_entshim = entshim.lower() in ("1", "on", "true", "yes")
    secs = seconds if 30 <= seconds <= 1800 else 300

    def job(ctx):
        from ... import attest_detect, attestation
        with tee_pipeline_logs(ctx):
            accounts = attestation.load_accounts()

            # Stream each observer marker (HOOK_VERIFIED / CALL ...) to this console
            # live, in BOTH manual and UI-automation modes.
            def cb(line: str):
                ctx.log(line if line.endswith("\n") else line + "\n")

            if is_manual:
                ctx.log(f"MANUAL MODE: app stays installed. Interact with it now; "
                        f"the observer is streaming calls below for {secs}s.\n")
            if is_entshim:
                ctx.log("entitlement-shim injected (swallows re-sign entitlement-loss crashes)\n")
            conf = attest_detect.process_app(get_db(), row, accounts,
                                             manual=is_manual, manual_seconds=secs, log_cb=cb,
                                             stop_check=lambda: ctx.cancelled, login=is_login,
                                             entshim=is_entshim)
            ctx.log(f"usage: {getattr(conf, 'value', conf)}\n")

    jid = get_jobs_manager().submit("attest_detect", app_id, job, device_bound=True)
    return _watch(request, app_id, jid, "attest")
