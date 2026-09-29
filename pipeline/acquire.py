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


def _ipatool_login() -> bool:
    """Log ipatool in if creds are configured; a stored keychain session also works."""
    it = CONFIG.ipatool
    # If already authenticated, `auth info` returns 0.
    if run_cmd([it.cmd, "auth", "info"], timeout=30).ok:
        return True
    if it.email and it.password:
        p = run_cmd([it.cmd, "auth", "login", "-e", it.email, "-p", it.password,
                     "--non-interactive"], timeout=120)
        if p.ok:
            return True
        log.error("ipatool login failed: %s", (p.stderr or p.stdout)[:200])
    else:
        log.error("ipatool not authenticated and no IPATOOL_EMAIL/PASSWORD set")
    return False


def download_with_ipatool(app_id: str, row) -> tuple[bool, str, str]:
    """Download the still-encrypted IPA with ipatool. Returns (ok, path, error)."""
    bundle = row["bundle_id"]
    if not bundle:
        return False, "", "ipatool needs a bundle id"
    enc = CONFIG.paths.work_dir / f"{app_id}.enc.ipa"
    enc.parent.mkdir(parents=True, exist_ok=True)
    cmd = [CONFIG.ipatool.cmd, "download", "-b", bundle, "-o", str(enc),
           "--purchase", "--non-interactive"]
    p = run_cmd(cmd, timeout=900)
    if enc.exists() and enc.stat().st_size > 0:
        return True, str(enc), ""
    return False, "", (p.stderr or p.stdout or "ipatool download failed")[:300]


def decrypt_one(app_id: str, row, from_appstore: bool = False,
                timeout: int = 900) -> tuple[WorkState, str, str]:
    """Acquire + decrypt one app. Returns (work_state, ipa_path, error).

    Two modes (config.acquire_mode):
      ipadecrypt: ipadecrypt downloads from the App Store (--storefront) and
                  decrypts in one step.
      ipatool:    ipatool downloads the encrypted IPA, then ipadecrypt decrypts
                  that local file.
    """
    CONFIG.paths.ipa_dir.mkdir(parents=True, exist_ok=True)
    out = CONFIG.paths.ipa_dir / f"{app_id}.ipa"
    if out.exists() and out.stat().st_size > 0:
        return WorkState.POSITIVE, str(out), ""

    country = row["country"]
    if CONFIG.acquire_mode == "ipatool":
        ok, enc_path, err = download_with_ipatool(app_id, row)
        if not ok:
            low = err.lower()
            if any(m in low for m in _PERMANENT):
                return WorkState.DONE_NEGATIVE, "", "unavailable: " + err
            return WorkState.UNTESTED, "", err
        # Decrypt the local encrypted IPA on the jailbroken device.
        cmd = [CONFIG.decrypt_device.ipadecrypt_cmd, "decrypt", enc_path,
               "-o", str(out), "--redact"]
    else:
        cmd = [CONFIG.decrypt_device.ipadecrypt_cmd, "decrypt", _identifier(row),
               "-o", str(out), "--storefront", country.upper(), "--redact"]
        if from_appstore:
            cmd.append("--from-appstore")

    proc = run_cmd(cmd, timeout=timeout)

    # Clean up the encrypted staging file if we made one.
    enc = CONFIG.paths.work_dir / f"{app_id}.enc.ipa"
    if enc.exists():
        try:
            enc.unlink()
        except OSError:
            pass

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


def acquire_one(db: Database, bundle_id: str, country: str = "us",
                app_id: str | None = None, from_appstore: bool = False) -> tuple[WorkState, str, str]:
    """Download + install + decrypt ONE specific app by bundle id. Returns
    (work_state, ipa_path, error). Records it in the DB like the corpus path."""
    if not CONFIG.decrypt_device.is_bootstrapped:
        return WorkState.UNTESTED, "", "ipadecrypt not bootstrapped"
    if CONFIG.acquire_mode == "ipatool" and not _ipatool_login():
        return WorkState.UNTESTED, "", "ipatool not authenticated"
    app_id = app_id or bundle_id
    row = {"app_id": app_id, "bundle_id": bundle_id, "country": country}
    state, path, err = decrypt_one(app_id, row, from_appstore)
    db.upsert_app(app_id, country, bundle_id=bundle_id)
    db.save_acquisition(app_id, state, ipa_path=path, error=err)
    if state == WorkState.POSITIVE:
        db.set_stage(app_id, Stage.ACQUIRED)
        log.info("acquired %s -> %s", bundle_id, path)
    else:
        log.warning("acquire %s: %s (%s)", bundle_id, err, state.name)
    return state, path, err


def run(db: Database, limit: int | None = None, from_appstore: bool = False) -> dict[str, int]:
    """Acquire all apps still needing decryption. Resumable via the work queue."""
    if not CONFIG.decrypt_device.is_bootstrapped:
        log.error("ipadecrypt not bootstrapped. Run `%s bootstrap` first.",
                  CONFIG.decrypt_device.ipadecrypt_cmd)
        return {"attempted": 0, "ok": 0, "skipped": 0, "retry": 0}

    if CONFIG.acquire_mode == "ipatool" and not _ipatool_login():
        return {"attempted": 0, "ok": 0, "skipped": 0, "retry": 0}

    rows = db.apps_needing(Stage.ACQUIRED)
    if limit:
        rows = rows[:limit]

    stats = {"attempted": 0, "ok": 0, "skipped": 0, "retry": 0}
    for row in rows:
        app_id = row["app_id"]
        ident = _identifier(row)
        stats["attempted"] += 1
        state, path, err = decrypt_one(app_id, row, from_appstore)
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
