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

import os
import re

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


def _mb(path) -> float:
    try:
        return os.path.getsize(path) / (1024 * 1024)
    except OSError:
        return 0.0


def _short_reason(text: str) -> str:
    """Condense a noisy ipatool/ipadecrypt error to one clean phrase."""
    t = (text or "").lower()
    if "301" in t or "another network" in t or "no usable authentication" in t:
        return "Apple auth throttled (HTTP 301)"
    if "already" in t or "owned" in t or "licen" in t:
        return "already owned"
    if "not found" in t or "404" in t:
        return "not found"
    if "429" in t or "rate" in t:
        return "rate limited (429)"
    # first non-empty line, trimmed
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:120]
    return "unknown"


_IPADEC_OK = re.compile(r"decrypted (\d+) image\(s\)[^\n]*?\(([\d.]+ [KMG]B)", re.IGNORECASE)
_IPADEC_VERIFIED = re.compile(r"(\d+) Mach-O\(s\) verified", re.IGNORECASE)


def _ipadecrypt_summary(stdout: str) -> str:
    """Human summary from ipadecrypt output, e.g. '6 images, 108.0 MB, 11 Mach-Os verified'."""
    parts = []
    m = _IPADEC_OK.search(stdout or "")
    if m:
        parts.append(f"{m.group(1)} images, {m.group(2)}")
    v = _IPADEC_VERIFIED.search(stdout or "")
    if v:
        parts.append(f"{v.group(1)} Mach-Os verified")
    return ", ".join(parts) if parts else "decrypted"


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


def download_with_ipatool(app_id: str, row, purchase: bool = False,
                          auth_code: str = "") -> tuple[bool, str, str]:
    """Download the still-encrypted IPA with ipatool by bundle id or numeric app
    id. Returns (ok, path, error).

    purchase=False (default): plain download, works for apps ALREADY in the
      account's library; never triggers a purchase (so no 'auth code required').
    purchase=True: single `ipatool download --purchase` call, which obtains the
      license and downloads in one step (needed for unowned/free-but-not-yet-
      acquired apps). No separate `ipatool purchase` step. Apple may require an
      --auth-code, pass it via auth_code.
    """
    bundle = _field(row, "bundle_id")
    store_id = _field(row, "store_id")
    if not store_id:
        cand = str(_field(row, "app_id") or "")
        store_id = cand if cand.isdigit() else None
    enc = CONFIG.paths.work_dir / f"{app_id}.enc.ipa"
    enc.parent.mkdir(parents=True, exist_ok=True)
    if bundle:
        idflags = ["-b", bundle]
    elif store_id:
        idflags = ["-i", str(store_id)]
    else:
        return False, "", "ipatool needs a bundle id or numeric app id"

    auth = ["--auth-code", auth_code] if auth_code else []

    log.info("  ipatool: downloading encrypted IPA%s ...",
             " (with --purchase)" if purchase else "")
    dl = [CONFIG.ipatool.cmd, "download", *idflags, "-o", str(enc), "--non-interactive"]
    if purchase:
        dl.append("--purchase")
        dl += auth
    p = run_cmd(dl, timeout=900)
    if enc.exists() and enc.stat().st_size > 0:
        log.info("        downloaded %.1f MB", _mb(enc))
        return True, str(enc), ""
    low = (p.stdout + " " + p.stderr).lower()
    if "auth code" in low or "2fa" in low:
        return False, "", "download needs 2FA/auth code (pass --auth-code)"
    return False, "", (p.stderr or p.stdout or "ipatool download failed")[:300]


def decrypt_one(app_id: str, row, from_appstore: bool = False, purchase: bool = False,
                auth_code: str = "", timeout: int = 900) -> tuple[WorkState, str, str]:
    """Acquire + decrypt one app. Returns (work_state, ipa_path, error).

    Two modes (config.acquire_mode):
      ipadecrypt: ipadecrypt downloads from the App Store (--storefront) and
                  decrypts in one step.
      ipatool:    ipatool downloads the encrypted IPA, then ipadecrypt decrypts
                  that local file.
    """
    CONFIG.paths.ipa_dir.mkdir(parents=True, exist_ok=True)
    # Decrypted outputs are marked ".decrypted.ipa" so they're never confused
    # with encrypted App Store IPAs.
    out = CONFIG.paths.ipa_dir / f"{app_id}.decrypted.ipa"
    if out.exists() and out.stat().st_size > 0:
        return WorkState.POSITIVE, str(out), ""

    country = _field(row, "country") or "us"
    ident = _identifier(row)
    if CONFIG.acquire_mode == "ipatool":
        ok, enc_path, err = download_with_ipatool(app_id, row, purchase=purchase, auth_code=auth_code)
        if not ok:
            low = err.lower()
            if any(m in low for m in _PERMANENT):
                log.warning("  ✗ %s unavailable: %s", ident, _short_reason(err))
                return WorkState.DONE_NEGATIVE, "", "unavailable: " + err
            log.warning("  ✗ %s download failed: %s (will retry)", ident, _short_reason(err))
            return WorkState.UNTESTED, "", err
        # Decrypt the local encrypted IPA on the jailbroken device.
        cmd = [CONFIG.decrypt_device.ipadecrypt_cmd, "decrypt", enc_path,
               "-o", str(out), "--redact", "-v"]
    else:
        cmd = [CONFIG.decrypt_device.ipadecrypt_cmd, "decrypt", ident,
               "-o", str(out), "--storefront", country.upper(), "--redact", "-v"]
        if from_appstore:
            cmd.append("--from-appstore")

    log.info("  decrypting on device (ipadecrypt) ...")
    proc = run_cmd(cmd, timeout=timeout)

    # Clean up the encrypted staging file if we made one.
    enc = CONFIG.paths.work_dir / f"{app_id}.enc.ipa"
    if enc.exists():
        try:
            enc.unlink()
        except OSError:
            pass

    if out.exists() and out.stat().st_size > 0:
        log.info("  ✓ decrypted: %s (%.1f MB) -> %s",
                 _ipadecrypt_summary(proc.stdout), _mb(out), out)
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
                country: str = "us", from_appstore: bool = False, purchase: bool = False,
                auth_code: str = "") -> tuple[WorkState, str, str]:
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
    label = bundle_id or f"id{app_id}"
    log.info("== acquire %s (%s)%s ==", label, country.upper(),
             " [purchase]" if purchase else "")
    state, path, err = decrypt_one(key, row, from_appstore, purchase=purchase, auth_code=auth_code)
    db.upsert_app(key, country, bundle_id=bundle_id)
    db.save_acquisition(key, state, ipa_path=path, error=err)
    if state == WorkState.POSITIVE:
        db.set_stage(key, Stage.ACQUIRED)
        log.info("== DONE %s: decrypted -> %s ==", label, path)
    else:
        log.warning("== %s %s: %s ==", state.name, label, _short_reason(err))
    return state, path, err


def run(db: Database, limit: int | None = None, from_appstore: bool = False,
        purchase: bool = False) -> dict[str, int]:
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

    total = len(rows)
    log.info("acquire: %d app(s) queued (mode=%s)", total, CONFIG.acquire_mode)
    stats = {"attempted": 0, "ok": 0, "skipped": 0, "retry": 0}
    for i, row in enumerate(rows, 1):
        app_id = row["app_id"]
        ident = _identifier(row)
        stats["attempted"] += 1
        log.info("[%d/%d] == acquire %s ==", i, total, ident)
        state, path, err = decrypt_one(app_id, row, from_appstore, purchase=purchase)
        db.save_acquisition(app_id, state, ipa_path=path, error=err)
        if state == WorkState.POSITIVE:
            db.set_stage(app_id, Stage.ACQUIRED)
            stats["ok"] += 1
            log.info("[%d/%d] ✓ %s decrypted (%.1f MB)", i, total, ident, _mb(path))
        elif state == WorkState.DONE_NEGATIVE:
            stats["skipped"] += 1
            log.info("[%d/%d] – skip %s: %s", i, total, ident, _short_reason(err))
        else:
            stats["retry"] += 1
            log.warning("[%d/%d] ↺ retry-later %s: %s", i, total, ident, _short_reason(err))
        log.info("      progress: %d ok / %d skip / %d retry (of %d)",
                 stats["ok"], stats["skipped"], stats["retry"], total)
    log.info("acquire complete: %s", stats)
    return stats
