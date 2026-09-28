"""Stage B: acquire + decrypt via the prebuilt ipadecrypt binary.

ipadecrypt runs on the Mac and drives the jailbroken iPhone 8 over SSH (its own
connection config lives in ~/.ipadecrypt/config.json after a one-time
`ipadecrypt bootstrap`). Per app we run:

    ipadecrypt decrypt <bundle-id|app-id> -o <out.ipa> --storefront <cc>

Failures map onto the tri-state work queue: unavailable/removed apps are a
permanent skip, transient errors (timeout, device hiccup) stay UNTESTED so the
next run retries.
"""

from __future__ import annotations

from .config import CONFIG
from .db import Database
from .models import Stage, WorkState
from .util import get_logger, run_cmd

log = get_logger("acquire", CONFIG.paths.log_dir)

# Substrings in ipadecrypt output that mean the app is permanently unavailable.
_PERMANENT = ("not found", "no such app", "404", "not available",
              "does not exist", "unavailable in", "license")
_TOO_LARGE = ("too large", "exceeds")


def _identifier(row) -> str:
    """Prefer bundle id (stable across storefronts); fall back to track id."""
    return row["bundle_id"] or row["app_id"]


def decrypt_one(app_id: str, identifier: str, country: str,
                from_appstore: bool = False, timeout: int = 900) -> tuple[WorkState, str, str]:
    """Decrypt one app. Returns (work_state, ipa_path, error)."""
    CONFIG.paths.ipa_dir.mkdir(parents=True, exist_ok=True)
    out = CONFIG.paths.ipa_dir / f"{app_id}.ipa"
    if out.exists() and out.stat().st_size > 0:
        return WorkState.POSITIVE, str(out), ""

    cmd = [CONFIG.decrypt_device.ipadecrypt_cmd, "decrypt", identifier,
           "-o", str(out), "--storefront", country.upper(), "--redact"]
    if from_appstore:
        cmd.append("--from-appstore")

    proc = run_cmd(cmd, timeout=timeout)

    if out.exists() and out.stat().st_size > 0:
        return WorkState.POSITIVE, str(out), ""

    text = (proc.stdout + " " + proc.stderr).lower()
    if any(m in text for m in _PERMANENT):
        return WorkState.DONE_NEGATIVE, "", "unavailable: " + text[:200]
    if any(m in text for m in _TOO_LARGE):
        return WorkState.DONE_NEGATIVE, "", "too_large"
    if proc.returncode == 124:
        return WorkState.UNTESTED, "", "timeout"        # transient: retry
    if proc.returncode == 127:
        return WorkState.UNTESTED, "", "ipadecrypt not found on PATH/config"
    return WorkState.UNTESTED, "", (proc.stderr or proc.stdout or "unknown error")[:300]


def run(db: Database, limit: int | None = None, from_appstore: bool = False) -> dict[str, int]:
    """Acquire all apps still needing decryption. Resumable via the work queue."""
    if not CONFIG.decrypt_device.is_bootstrapped:
        log.error("ipadecrypt not bootstrapped. Run `%s bootstrap` first.",
                  CONFIG.decrypt_device.ipadecrypt_cmd)
        return {"attempted": 0, "ok": 0, "skipped": 0, "retry": 0}

    rows = db.apps_needing(Stage.ACQUIRED)
    if limit:
        rows = rows[:limit]

    stats = {"attempted": 0, "ok": 0, "skipped": 0, "retry": 0}
    for row in rows:
        app_id = row["app_id"]
        ident = _identifier(row)
        stats["attempted"] += 1
        state, path, err = decrypt_one(app_id, ident, row["country"], from_appstore)
        db.save_acquisition(app_id, state, ipa_path=path, error=err)
        if state == WorkState.POSITIVE:
            db.set_stage(app_id, Stage.ACQUIRED)
            stats["ok"] += 1
            log.info("decrypted %s (%s)", ident, app_id)
        elif state == WorkState.DONE_NEGATIVE:
            stats["skipped"] += 1
            log.info("skip %s: %s", ident, err)
        else:
            stats["retry"] += 1
            log.warning("retry-later %s: %s", ident, err)
    log.info("acquire: %s", stats)
    return stats
