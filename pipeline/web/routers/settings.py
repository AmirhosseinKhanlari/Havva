"""Settings: view config (secrets masked), edit selected .env keys, run doctor."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, Request

from ...config import CONFIG, PROJECT_ROOT
from ..app import templates
from ..auth import require_auth

router = APIRouter()

# Non-secret keys the UI may edit. Secrets are shown masked and not editable here.
EDITABLE = [
    ("ACQUIRE_MODE", "appstore | ipatool | ipadecrypt"),
    ("ITUNES_SERVER", "iTunes server URL (appstore mode)"),
    ("TEST_DEVICE_UDID", "iPhone XR UDID"),
    ("TEST_DEVICE_IP", "iPhone XR IP"),
    ("DECRYPT_SSH_HOST", "jailbroken iPhone 8 IP"),
    ("WEB_MAX_WORKERS", "concurrent non-device jobs"),
]
SECRETS = ("WEB_AUTH_TOKEN", "IPATOOL_PASSWORD", "SIGN_P12_PASSWORD", "APPFIGURES_COOKIE")


def _mask(v: str) -> str:
    if not v:
        return ""
    return v[:2] + "…" + v[-2:] if len(v) > 6 else "***"


def _current() -> dict:
    return {k: os.environ.get(k, "") for k, _ in EDITABLE}


def _write_env(updates: dict) -> None:
    """Update or append KEY=VALUE lines in .env, and reflect into os.environ."""
    env_path = PROJECT_ROOT / ".env"
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    seen = set()
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                out.append(f"{key}={updates[key]}")
                seen.add(key)
                continue
        out.append(line)
    for key, val in updates.items():
        if key not in seen:
            out.append(f"{key}={val}")
    env_path.write_text("\n".join(out) + "\n")
    for key, val in updates.items():
        os.environ[key] = val


@router.get("/settings")
def settings_page(request: Request, _: None = Depends(require_auth)):
    return templates.TemplateResponse(request, "settings.html", {
        "request": request,
        "editable": EDITABLE,
        "current": _current(),
        "secrets": {k: _mask(os.environ.get(k, "")) for k in SECRETS},
    })


@router.post("/settings/save")
async def settings_save(request: Request, _: None = Depends(require_auth)):
    form = await request.form()
    updates = {k: str(form.get(k, "")).strip() for k, _ in EDITABLE if k in form}
    _write_env(updates)
    return templates.TemplateResponse(request, "_settings_saved.html", {
        "request": request, "updates": updates})


@router.get("/settings/doctor")
def settings_doctor(request: Request, _: None = Depends(require_auth)):
    tools = {}
    for t in ("git", "idevice_id", "ideviceinstaller", "codesign", "otool",
              "strings", "zsign"):
        tools[t] = bool(shutil.which(t)) or (
            t == "zsign" and Path(CONFIG.signing.zsign).exists())
    assets = {
        "p12": Path(CONFIG.signing.p12).exists(),
        "profile": Path(CONFIG.signing.mobileprovision).exists(),
        "ipadecrypt_bootstrapped": CONFIG.decrypt_device.is_bootstrapped,
    }
    return templates.TemplateResponse(request, "_doctor.html", {
        "request": request, "tools": tools, "assets": assets})
