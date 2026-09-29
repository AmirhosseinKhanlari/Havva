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


def _field(row, key):
    """Read a field from a sqlite3.Row or a dict, returning None if absent."""
    try:
        return row[key]
    except (KeyError, IndexError):
        return None


def _identifier(row) -> str:
    """Prefer bundle id (stable across storefronts); fall back to track id."""
    return _field(row, "bundle_id") or _field(row, "app_id")


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
    """Download the still-encrypted IPA with ipatool by bundle id or numeric app
    id. Returns (ok, path, error)."""
    bundle = _field(row, "bundle_id")
    store_id = _field(row, "store_id")
    if not store_id:
        # fall back to app_id if it is a numeric App Store id
        cand = str(_field(row, "app_id") or "")
        store_id = cand if cand.isdigit() else None
    enc = CONFIG.paths.work_dir / f"{app_id}.enc.ipa"
    enc.parent.mkdir(parents=True, exist_ok=True)
    # Identifier flags (bundle id overrides numeric app id).
    if bundle:
        idflags = ["-b", bundle]
    elif store_id:
        idflags = ["-i", str(store_id)]
    else:
        return False, "", "ipatool needs a bundle id or numeric app id"

    # 1. Obtain the license first (free apps must be "purchased" to the account).
    #    Best-effort: an already-owned app returns an error we intentionally ignore.
    pr = run_cmd([CONFIG.ipatool.cmd, "purchase", *idflags, "--non-interactive"], timeout=120)
    low = (pr.stdout + " " + pr.stderr).lower()
    if not pr.ok and not any(m in low for m in ("already", "owned", "licen")):
        log.info("ipatool purchase note (%s): %s", app_id, (pr.stderr or pr.stdout)[:160])

    # 2. Download the (now-licensed) encrypted IPA.
    p = run_cmd([CONFIG.ipatool.cmd, "download", *idflags, "-o", str(enc),
                 "--purchase", "--non-interactive"], timeout=900)
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


def acquire_one(db: Database, bundle_id: str | None = None, app_id: str | None = None,
                country: str = "us", from_appstore: bool = False) -> tuple[WorkState, str, str]:
    """Download + install + decrypt ONE specific app by bundle id and/or numeric
    App Store id. At least one identifier is required. Returns
    (work_state, ipa_path, error) and records it in the DB like the corpus path."""
    if not bundle_id and not app_id:
        return WorkState.DONE_NEGATIVE, "", "need a bundle id or app id"
    if not CONFIG.decrypt_device.is_bootstrapped:
        return WorkState.UNTESTED, "", "ipadecrypt not bootstrapped"
    if CONFIG.acquire_mode == "ipatool" and not _ipatool_login():
        return WorkState.UNTESTED, "", "ipatool not authenticated"
    key = bundle_id or str(app_id)          # DB primary key / output filename
    row = {"app_id": key, "bundle_id": bundle_id, "country": country, "store_id": app_id}
    state, path, err = decrypt_one(key, row, from_appstore)
    db.upsert_app(key, country, bundle_id=bundle_id)
    db.save_acquisition(key, state, ipa_path=path, error=err)
    if state == WorkState.POSITIVE:
        db.set_stage(key, Stage.ACQUIRED)
        log.info("acquired %s -> %s", key, path)
    else:
        log.warning("acquire %s: %s (%s)", key, err, state.name)
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
