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
from .util import get_logger, run_cmd, run_cmd_streamed

log = get_logger("acquire", CONFIG.paths.log_dir)


def sync_ipadecrypt_host() -> None:
    """ipadecrypt keeps its own ~/.ipadecrypt/config.json (device.host/port/user),
    which it uses for the SSH decrypt. Keep it in sync with DECRYPT_SSH_HOST so the
    .env / web settings are the single source of truth for the iPhone 8 IP."""
    import json
    dd = CONFIG.decrypt_device
    if not dd.ssh_host:
        return
    cfg = dd.bootstrap_config
    try:
        data = json.loads(cfg.read_text())
    except (OSError, ValueError):
        return
    dev = data.get("device")
    if not isinstance(dev, dict):
        return
    # host is the one value .env owns outright. user/port only override the
    # bootstrap values when the operator set them EXPLICITLY (config defaults
    # of root/22 must not clobber e.g. a device bootstrapped as mobile@:2222).
    wanted = [("host", dd.ssh_host)]
    if "DECRYPT_SSH_PORT" in os.environ:
        wanted.append(("port", dd.ssh_port))
    if "DECRYPT_SSH_USER" in os.environ:
        wanted.append(("user", dd.ssh_user))
    changed = False
    for key, val in wanted:
        if val and dev.get(key) != val:
            dev[key] = val
            changed = True
    if changed:
        try:
            _atomic_write_text(cfg, json.dumps(data, indent=1))
            log.info("synced ipadecrypt device -> %s@%s:%s", dev.get("user"),
                     dev.get("host"), dev.get("port"))
        except OSError as e:
            log.warning("could not sync ipadecrypt config: %s", e)


def _atomic_write_text(path, text: str) -> None:
    """Write via a temp file in the same directory + os.replace, so a crash
    mid-write can never leave a truncated config behind."""
    import tempfile
    from pathlib import Path as _P
    path = _P(path)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

# Anchored patterns in ipadecrypt / ipatool / appstore output that mean the app
# is permanently unavailable. They are only applied to error-looking lines (see
# `_error_lines`) because loose substrings ("404" in a container UUID, "exceeds"
# or "not available" in prose) turned transient failures into permanent skips.
_PERMANENT = (
    re.compile(r"\bnot found\b", re.I),
    re.compile(r"\bno such app\b", re.I),
    re.compile(r"(?:\bhttp\b.*|status\D{0,8})\b404\b", re.I),
    re.compile(r"\bnot available\b", re.I),
    re.compile(r"\bdoes not exist\b", re.I),
    re.compile(r"\bunavailable in\b", re.I),
)
_TOO_LARGE = (
    re.compile(r"\btoo large\b", re.I),
    re.compile(r"\bexceeds\b.{0,40}\b(?:limit|size|maximum|max)\b", re.I),
    re.compile(r"\b(?:size|limit)\b.{0,40}\bexceeds\b", re.I),
)
_ERRORISH = re.compile(r"error|fail|\[!\]|✗", re.I)
# Lines about the transport / decrypt device are transient by nature ("device
# not found", "ssh: connection refused"); never let them trip a permanent skip.
_TRANSIENT_HINT = re.compile(r"\b(?:device|usbmux|ssh|sshpass|connection|host|socket|timed? ?out)\b", re.I)


def _error_lines(text: str, tail: int = 3) -> list[str]:
    """Lines of tool output worth matching failure patterns against: those that
    look like errors, plus the final `tail` non-empty lines (a tool's closing
    status). Everything else (progress, container paths, prose) is ignored."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return []
    keep = [ln for ln in lines if _ERRORISH.search(ln)]
    for ln in lines[-tail:]:
        if ln not in keep:
            keep.append(ln)
    return keep


def _match_failure(text: str, patterns, kind: str) -> str | None:
    """Return the pattern (source) that fired on an error-looking line of `text`,
    logging it, or None."""
    for ln in _error_lines(text):
        if patterns is _PERMANENT and _TRANSIENT_HINT.search(ln):
            continue
        for rx in patterns:
            if rx.search(ln):
                log.info("  %s matched /%s/ on: %s", kind, rx.pattern, ln[:160])
                return rx.pattern
    return None


def is_permanent_failure(text: str) -> bool:
    return _match_failure(text, _PERMANENT, "permanent-failure") is not None


def is_too_large(text: str) -> bool:
    return _match_failure(text, _TOO_LARGE, "too-large") is not None


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
    if "license is required" in t or "licence is required" in t:
        return "license required (not yet acquired; use --purchase)"
    if "already" in t or "owned" in t:
        return "already owned"
    if re.search(r"\bnot found\b", t) or re.search(r"(?:\bhttp\b.*|status\D{0,8})\b404\b", t):
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
    _unlink_quiet(enc)        # never let a stale staging file pass as this download
    if bundle:
        idflags = ["-b", bundle]
    elif store_id:
        idflags = ["-i", str(store_id)]
    else:
        return False, "", "ipatool needs a bundle id or numeric app id"

    auth = ["--auth-code", auth_code] if auth_code else []

    def _run_download(with_purchase: bool):
        dl = [CONFIG.ipatool.cmd, "download", *idflags, "-o", str(enc), "--non-interactive"]
        if with_purchase:
            dl.append("--purchase")
            dl += auth
        return run_cmd(dl, timeout=900)

    log.info("  ipatool: downloading encrypted IPA%s ...",
             " (with --purchase)" if purchase else "")
    p = _run_download(purchase)

    # Free app not yet in the library: `download` returns "license is required".
    # Auto-acquire the free license with a single `download --purchase` retry
    # (no separate purchase step). Free apps need no auth code.
    low = (p.stdout + " " + p.stderr).lower()
    if not purchase and ("license is required" in low or "licence is required" in low):
        log.info("        license required -> retrying with --purchase (free license) ...")
        p = _run_download(True)
        low = (p.stdout + " " + p.stderr).lower()

    if p.ok and enc.exists() and enc.stat().st_size > 0:
        log.info("        downloaded %.1f MB", _mb(enc))
        return True, str(enc), ""
    # The command failed (or left nothing usable): drop any partial/stale file so
    # a later decrypt never picks it up.
    _unlink_quiet(enc)
    if "auth code" in low or "2fa" in low:
        return False, "", "download needs 2FA/auth code (paid app; pass --auth-code)"
    return False, "", (p.stderr or p.stdout or "ipatool download failed")[:300]


def _unlink_quiet(path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def download_with_appstore(app_id: str, row, country: str = "us",
                           app_ver_id: str | None = None,
                           progress_cb=None) -> tuple[bool, str, str]:
    """Download the still-encrypted IPA via the Windows iTunes server (MZStore
    protocol). Auth material comes from real iTunes, so it is not throttled like
    ipatool. Returns (ok, path, error). Stages the file as {app_id}.enc.ipa so
    the decrypt/cleanup path is identical to the ipatool backend.

    app_ver_id: optional externalVersionId (or dotted short version) to fetch an
    OLDER build instead of the current one."""
    from . import appstore_dl

    # The MZStore download needs the numeric App Store id.
    store_id = _field(row, "store_id")
    if not store_id:
        cand = str(_field(row, "app_id") or "")
        store_id = cand if cand.isdigit() else None
    if not store_id:
        bundle = _field(row, "bundle_id")
        if bundle:
            store_id = appstore_dl.lookup_app_id(bundle, country.upper())
    if not store_id:
        return False, "", "appstore needs a numeric app id (lookup failed)"

    verid = None
    if app_ver_id:
        verid = appstore_dl.resolve_version(str(store_id), str(app_ver_id),
                                            CONFIG.appstore.itunes_server)
        if not verid:
            return False, "", f"version {app_ver_id} not found in app history"

    work = CONFIG.paths.work_dir
    work.mkdir(parents=True, exist_ok=True)
    enc = work / f"{app_id}.enc.ipa"
    _unlink_quiet(enc)        # a stale staging file must never pass as this download
    ok, path, err = appstore_dl.download_encrypted(
        str(store_id), str(work), CONFIG.appstore.itunes_server, country.upper(),
        app_ver_id=verid, progress_cb=progress_cb)
    if not ok:
        _unlink_quiet(enc)
        return False, "", err or "appstore download failed"
    if not (path and os.path.exists(path) and os.path.getsize(path) > 0):
        _unlink_quiet(enc)
        return False, "", "appstore download reported success but produced no file"
    try:
        if os.path.abspath(path) != os.path.abspath(enc):
            os.replace(path, enc)
    except OSError as e:
        return False, "", f"stage rename failed: {e}"
    return True, str(enc), ""


_BID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,200}$")


def _bundle_id_from_conflict(text: str) -> str | None:
    """Pull the conflicting bundle id out of ipadecrypt / appinst install output.
    Prefers the `Installing "X"` line; falls back to the application-identifier in
    the MismatchedApplicationIdentifierEntitlement message."""
    m = re.search(r'Installing "([^"]+)"', text)
    if not m:
        m = re.search(r"application-identifier entitlement string "
                      r"\([0-9A-Za-z]+\.([A-Za-z0-9._-]+)\)", text)
    if not m:
        return None
    bid = m.group(1).strip()
    return bid if _BID_RE.match(bid) else None


def _decrypt_ssh_argv(remote_cmd: str) -> tuple[list[str], dict] | None:
    """Build (argv, env) to run `remote_cmd` on the jailbroken decrypt device over
    SSH, reusing ipadecrypt's stored connection config (~/.ipadecrypt/config.json).
    A password is handed to sshpass through the SSHPASS environment variable
    (`sshpass -e`), never on argv where `ps` would show it. Returns None if the
    host is unknown or password auth is needed but sshpass is missing."""
    import json
    import shutil
    from pathlib import Path

    host = CONFIG.decrypt_device.ssh_host
    port = str(CONFIG.decrypt_device.ssh_port)
    user = CONFIG.decrypt_device.ssh_user
    password = keyfile = None
    try:
        dev = json.loads((Path.home() / ".ipadecrypt" / "config.json").read_text()).get("device", {})
        host = dev.get("host") or host
        port = str(dev.get("port") or port)
        user = dev.get("user") or user
        auth = dev.get("auth", {}) or {}
        if auth.get("method") == "password":
            password = auth.get("password")
        else:
            keyfile = auth.get("keyPath") or auth.get("identityFile")
    except (OSError, ValueError):
        pass
    if not host:
        return None
    argv = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=15",
            "-o", "NumberOfPasswordPrompts=1", "-p", port]
    env = dict(os.environ)
    if password:
        if not shutil.which("sshpass"):
            log.warning("  autoremove needs sshpass for the device's password auth; "
                        "install it (brew install sshpass) or switch the device to a key")
            return None
        argv = ["sshpass", "-e", *argv,
                "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no"]
        env["SSHPASS"] = password
    elif keyfile:
        argv += ["-i", keyfile]
    argv += [f"{user}@{host}", remote_cmd]
    return argv, env


def _uninstall_on_decrypt_device(bundle_id: str) -> bool:
    """Uninstall `bundle_id` on the jailbroken decrypt device. ideviceinstaller does
    not work on-device (no local usbmux broker), so we remove the app's bundle and
    data containers by bundle id and refresh LaunchServices with uicache. Returns
    True if a bundle was removed."""
    if not _BID_RE.match(bundle_id):
        return False
    script = _uninstall_script(bundle_id)
    built = _decrypt_ssh_argv(script)
    if built is None:
        return False
    argv, env = built
    proc = run_cmd_streamed(argv, timeout=120, env=env,
                            line_cb=lambda ln: log.info("  autoremove | %s", ln))
    return "REMOVED_BUNDLE" in (proc.stdout or "")


def _uninstall_script(bundle_id: str) -> str:
    """Device-side shell for `_uninstall_on_decrypt_device`. Matches containers
    by an EXACT bundle-identifier comparison: `plutil -extract ... raw` reads
    the plist key, then `[ "$id" = "$BID" ]`. The old `grep -qa "$BID"` was an
    unanchored regex substring, so com.foo matched com.foo.bar (and '.' matched
    anything) and could `rm -rf` a different app. If plutil is unavailable the
    fallback is a fixed-string grep that additionally rejects any file carrying
    a LONGER id with this one as a prefix ("$BID.")."""
    assert _BID_RE.match(bundle_id)
    return (
        'BID="%s"; '
        # matches <key> <file> -> 0 when the file's id is exactly $BID. Uses
        # plutil's extracted value when available; otherwise (no plutil, or a
        # plutil without -extract) a fixed-string grep that also rejects a
        # longer id sharing this prefix.
        'matches() { '
        '  id=""; '
        '  if command -v plutil >/dev/null 2>&1; then '
        '    id=$(plutil -extract "$1" raw "$2" 2>/dev/null); '
        '  fi; '
        '  if [ -n "$id" ]; then [ "$id" = "$BID" ]; '
        '  else grep -qaF -- "$BID" "$2" 2>/dev/null && ! grep -qaF -- "$BID." "$2" 2>/dev/null; '
        '  fi; }; '
        'find /var/containers/Bundle/Application -maxdepth 2 -name "*.app" 2>/dev/null | '
        'while IFS= read -r app; do '
        '  if matches CFBundleIdentifier "$app/Info.plist"; then '
        '    uicache -u "$app" 2>/dev/null; '
        '    rm -rf "$(dirname "$app")" && echo "REMOVED_BUNDLE $app"; '
        '  fi; done; '
        'find /var/mobile/Containers/Data/Application -maxdepth 2 '
        '  -name ".com.apple.mobile_container_manager.metadata.plist" 2>/dev/null | '
        'while IFS= read -r m; do '
        '  if matches MCMMetadataIdentifier "$m"; then '
        '    rm -rf "$(dirname "$m")" && echo "REMOVED_DATA $(dirname "$m")"; '
        '  fi; done; '
        'uicache -a 2>/dev/null; echo "UNINSTALL_DONE $BID"'
    ) % bundle_id


def decrypt_one(app_id: str, row, from_appstore: bool = False, purchase: bool = False,
                auth_code: str = "", timeout: int = 900,
                app_ver_id: str | None = None, progress_cb=None) -> tuple[WorkState, str, str]:
    """Acquire + decrypt one app. Returns (work_state, ipa_path, error).

    Two modes (config.acquire_mode):
      ipadecrypt: ipadecrypt downloads from the App Store (--storefront) and
                  decrypts in one step.
      ipatool:    ipatool downloads the encrypted IPA, then ipadecrypt decrypts
                  that local file.
      appstore:   MZStore download via the Windows iTunes server (supports
                  app_ver_id to fetch an OLDER build), then ipadecrypt decrypts.
    """
    CONFIG.paths.ipa_dir.mkdir(parents=True, exist_ok=True)
    sync_ipadecrypt_host()   # keep ipadecrypt's host in sync with DECRYPT_SSH_HOST
    # Decrypted outputs are marked ".decrypted.ipa" so they're never confused
    # with encrypted App Store IPAs. A specific older version gets its verId in
    # the name so it never collides with the current build.
    suffix = f"-v{app_ver_id}" if app_ver_id else ""
    out = CONFIG.paths.ipa_dir / f"{app_id}{suffix}.decrypted.ipa"
    if out.exists() and out.stat().st_size > 0:
        return WorkState.POSITIVE, str(out), ""

    country = _field(row, "country") or "us"
    ident = _identifier(row)
    if CONFIG.acquire_mode in ("ipatool", "appstore"):
        if CONFIG.acquire_mode == "appstore":
            ok, enc_path, err = download_with_appstore(app_id, row, country=country,
                                                       app_ver_id=app_ver_id,
                                                       progress_cb=progress_cb)
        else:
            ok, enc_path, err = download_with_ipatool(app_id, row, purchase=purchase, auth_code=auth_code)
        if not ok:
            # `err` is the downloader's own failure message, so every line of it
            # is error-looking; the anchored patterns still apply.
            if is_permanent_failure("error: " + err):
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

    if progress_cb:
        progress_cb(0)   # download done; decrypt has no % -> indeterminate bar
    log.info("  decrypting on device (ipadecrypt) ...")
    # Stream ipadecrypt's live output so its progress is visible, and forward each
    # line to the logger so the web-UI job console (which tails the "acquire"
    # logger) shows ipadecrypt's real output, including device-side install errors
    # like MismatchedApplicationIdentifierEntitlement.
    _emit = lambda ln: log.info("  ipadecrypt | %s", ln)
    proc = run_cmd_streamed(cmd, timeout=timeout, line_cb=_emit)

    # Auto-remove a conflicting pre-existing install and retry once. ipadecrypt's
    # appinst refuses to upgrade an app that is already installed under a different
    # signer (MismatchedApplicationIdentifierEntitlement, e.g. a copy we re-signed
    # earlier). Uninstall it on the jailbroken device, then retry the decrypt.
    combined = (proc.stdout or "") + " " + (proc.stderr or "")
    if (not (out.exists() and out.stat().st_size > 0)
            and "MismatchedApplicationIdentifierEntitlement" in combined):
        conflict = _bundle_id_from_conflict(combined)
        if conflict:
            log.warning("  install blocked: '%s' is already installed under a different "
                        "signer; auto-removing it on the device and retrying", conflict)
            if _uninstall_on_decrypt_device(conflict):
                log.info("  autoremove: removed '%s'; retrying decrypt", conflict)
                proc = run_cmd_streamed(cmd, timeout=timeout, line_cb=_emit)
            else:
                log.warning("  autoremove could not remove '%s' (see device); not retrying",
                            conflict)

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

    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if is_permanent_failure(text):
        return WorkState.DONE_NEGATIVE, "", "unavailable: " + " ".join(_error_lines(text))[:200]
    if is_too_large(text):
        return WorkState.DONE_NEGATIVE, "", "too_large"
    if proc.returncode == 124:
        return WorkState.UNTESTED, "", "timeout"        # transient: retry
    if proc.returncode == 127:
        return WorkState.UNTESTED, "", "ipadecrypt not found on PATH/config"
    return WorkState.UNTESTED, "", (proc.stderr or proc.stdout or "unknown error")[:300]


def acquire_one(db: Database, bundle_id: str | None = None, app_id: str | None = None,
                country: str = "us", from_appstore: bool = False, purchase: bool = False,
                auth_code: str = "", app_ver_id: str | None = None,
                progress_cb=None) -> tuple[WorkState, str, str]:
    """Download + install + decrypt ONE specific app by bundle id and/or numeric
    App Store id. At least one identifier is required. Returns
    (work_state, ipa_path, error) and records it in the DB like the corpus path.

    app_ver_id (appstore mode only): a specific externalVersionId or dotted short
    version to fetch an OLDER build instead of the current one."""
    if not bundle_id and not app_id:
        return WorkState.DONE_NEGATIVE, "", "need a bundle id or app id"
    if not CONFIG.decrypt_device.is_bootstrapped:
        return WorkState.UNTESTED, "", "ipadecrypt not bootstrapped"
    if not CONFIG.decrypt_device.online():
        dd = CONFIG.decrypt_device
        where = f"{dd.ssh_host}:{dd.ssh_port}" if dd.ssh_host else "(DECRYPT_SSH_HOST not set)"
        log.error("decrypt device (iPhone 8) offline at %s; not acquiring", where)
        return WorkState.UNTESTED, "", f"decrypt device (iPhone 8) offline at {where}"
    if CONFIG.acquire_mode == "ipatool" and not _ipatool_login():
        return WorkState.UNTESTED, "", "ipatool not authenticated"
    if app_ver_id and CONFIG.acquire_mode != "appstore":
        return WorkState.DONE_NEGATIVE, "", "--version needs ACQUIRE_MODE=appstore"
    # DB primary key / output filename: reuse the existing corpus row for this
    # bundle id (or numeric id) so a bundle-id acquire never inserts a duplicate
    # `apps` row keyed by bundle id next to the crawled numeric one.
    key = db.app_id_for_bundle(bundle_id) if bundle_id else None
    if not key and app_id and db.get_app(str(app_id)):
        key = str(app_id)
    key = key or bundle_id or str(app_id)
    row = {"app_id": key, "bundle_id": bundle_id, "country": country, "store_id": app_id}
    label = bundle_id or f"id{app_id}"
    log.info("== acquire %s (%s)%s%s ==", label, country.upper(),
             " [purchase]" if purchase else "",
             f" [version {app_ver_id}]" if app_ver_id else "")
    state, path, err = decrypt_one(key, row, from_appstore, purchase=purchase,
                                   auth_code=auth_code, app_ver_id=app_ver_id,
                                   progress_cb=progress_cb)
    # Recover the real bundle id from the decrypted IPA (the crawl often has none).
    resolved_bid = bundle_id
    if state == WorkState.POSITIVE and path:
        from . import instrument
        resolved_bid = bundle_id or instrument.bundle_id_from_ipa(path)
    db.upsert_app(key, country, bundle_id=resolved_bid)
    if app_ver_id:
        # A specific older build: record it in acquisition_versions only. The
        # canonical row describes the CURRENT build and must not be overwritten
        # (nor marked unavailable because one old version was not found).
        db.save_acquisition_version(key, str(app_ver_id), state, ipa_path=path, error=err)
    else:
        db.save_acquisition(key, state, ipa_path=path, error=err)
        if state == WorkState.UNTESTED:
            n = db.record_acquisition_attempt(key, err)
            log.info("  transient failure; attempt %d/%d", n, db.acquire_max_attempts())
    if state == WorkState.POSITIVE:
        if not app_ver_id:
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
            n = db.record_acquisition_attempt(app_id, err)
            log.warning("[%d/%d] ↺ retry-later %s: %s (attempt %d/%d)", i, total, ident,
                        _short_reason(err), n, db.acquire_max_attempts())
        log.info("      progress: %d ok / %d skip / %d retry (of %d)",
                 stats["ok"], stats["skipped"], stats["retry"], total)
    log.info("acquire complete: %s", stats)
    return stats
