"""Offline FairPlay decryption via tools/fairplay-decrypt.

ipadecrypt decrypts by uploading the IPA to the jailbroken iPhone 8, installing,
launching and dumping it: minutes per app, and it fails for apps that will not
launch. fairplay-decrypt derives the page keys from the IPA's own SINF/SUPF
records plus a 16-byte credential for the Apple ACCOUNT that owns the IPA, and
decrypts on the Mac in seconds. Verified byte-identical to ipadecrypt's output
(Link 1623228342, main executable and Sentry.framework, 2026-10-22).

One credential covers every app of one account. Credentials live outside the
repo as <credentials_dir>/<account>.bin, where <account> is the 8-hex-digit
SINF `user` id (the same id for every IPA that account downloads). The
credential is retrieved ONCE per account from the jailbroken device
(`pipeline fairplay-credential --ipa <some encrypted IPA of that account>`),
which needs root SSH by key and one app of that account installed on the device.
"""
from __future__ import annotations

import importlib.util
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import CONFIG
from .util import get_logger, run_cmd_streamed

log = get_logger("fairplay", CONFIG.paths.log_dir)

_ACCOUNT_RE = re.compile(r"^[0-9a-f]{8}$")
_SUMMARY_RE = re.compile(r"decrypted-binaries=(\d+) pages=(\d+)")
_TOOL_FILES = ("decrypt.py", "core.py", "transform", "transform_const_data.bin")
_DEVICE_FILES = ("credential.ios", "selector21.ios", "trigger.ios",
                 "static-key-table.bin", "core4-word-table.bin")


@dataclass
class Result:
    ok: bool
    summary: str = ""          # e.g. "2 binaries, 13388 pages"
    error: str = ""
    no_credential: bool = False   # expected miss (account not provisioned), not a fault


# ---- license / account ---------------------------------------------------------

def _atoms(data: bytes, start: int, end: int):
    at = start
    while at + 8 <= end:
        size = int.from_bytes(data[at:at + 4], "big")
        if size < 8 or at + size > end:
            return
        yield data[at + 4:at + 8], at + 8, at + size
        at += size


def sinf_account(sinf: bytes) -> str | None:
    """The 8-hex-digit account id (`user` field) of a SINF record, or None."""
    for tag, s, e in _atoms(sinf, 0, len(sinf)):
        if tag != b"sinf":
            continue
        for t2, s2, e2 in _atoms(sinf, s, e):
            if t2 != b"schi":
                continue
            for t3, s3, e3 in _atoms(sinf, s2, e2):
                if t3 == b"user" and e3 - s3 == 4:
                    return sinf[s3:e3].hex()
    return None


def account_of(ipa: str | Path) -> str | None:
    """Account id that owns an encrypted IPA, read from the main app's SINF
    (falls back to any SINF in the archive; all share the account)."""
    try:
        with zipfile.ZipFile(ipa) as z:
            sinfs = [n for n in z.namelist() if "/SC_Info/" in n and n.endswith(".sinf")]
            # main app first: Payload/X.app/SC_Info/*.sinf (shortest path), plain before .v4
            sinfs.sort(key=lambda n: (n.count("/"), n.endswith(".v4.sinf"), n))
            for n in sinfs:
                acct = sinf_account(z.read(n))
                if acct:
                    return acct
    except (zipfile.BadZipFile, OSError, KeyError):
        return None
    return None


def credential_path(account: str) -> Path:
    if not _ACCOUNT_RE.match(account or ""):
        raise ValueError(f"bad account id: {account!r}")
    return CONFIG.fairplay.credentials_dir / f"{account}.bin"


def accounts() -> list[str]:
    """Accounts that have a stored 16-byte credential."""
    d = CONFIG.fairplay.credentials_dir
    if not d.is_dir():
        return []
    out = []
    for p in sorted(d.glob("*.bin")):
        if _ACCOUNT_RE.match(p.stem):
            try:
                if p.stat().st_size == 16:
                    out.append(p.stem)
            except OSError:
                pass
    return out


# ---- readiness / decrypt -------------------------------------------------------

def tool_ready() -> tuple[bool, str]:
    """Is the decryptor itself installed and built (credentials aside)?"""
    fp = CONFIG.fairplay
    if not fp.enabled:
        return False, "disabled (FAIRPLAY_OFFLINE=0)"
    missing = [f for f in _TOOL_FILES if not (fp.tool_dir / f).exists()]
    if missing:
        return False, (f"{', '.join(missing)} missing in {fp.tool_dir} "
                       f"(clone + `make -C {fp.tool_dir}`, see .gitignore)")
    if not os.access(fp.tool_dir / "transform", os.X_OK):
        return False, f"{fp.tool_dir / 'transform'} is not executable"
    if importlib.util.find_spec("cryptography") is None:
        return False, "python package 'cryptography' missing (pip install 'cryptography>=41')"
    return True, ""


def ready() -> tuple[bool, str]:
    """Can acquire decrypt offline at all (tool built AND >= 1 credential)?"""
    ok, why = tool_ready()
    if not ok:
        return ok, why
    if not accounts():
        return False, f"no credential in {CONFIG.fairplay.credentials_dir}"
    return True, ""


def decrypt(enc: str | Path, out: str | Path, timeout: int = 900, line_cb=None) -> Result:
    """Decrypt `enc` into `out` (which must not exist). Never raises."""
    # The tool runs with its own directory as cwd: relative paths would break.
    enc, out = Path(enc).resolve(), Path(out).resolve()
    ok, why = tool_ready()
    if not ok:
        return Result(False, error=why)
    acct = account_of(enc)
    if not acct:
        return Result(False, error="no readable SINF account in the IPA")
    cred = credential_path(acct)
    if not cred.exists():
        return Result(False, error=f"no credential for account {acct}", no_credential=True)
    if Path(out).exists():
        return Result(False, error=f"output exists: {out}")
    proc = run_cmd_streamed([sys.executable, str(CONFIG.fairplay.tool_dir / "decrypt.py"),
                             str(enc), str(out), "--credential", str(cred)],
                            timeout=timeout, cwd=CONFIG.fairplay.tool_dir, echo=False,
                            line_cb=line_cb)
    text = proc.stdout or ""
    m = _SUMMARY_RE.search(text)
    if proc.returncode == 0 and m and Path(out).exists() and Path(out).stat().st_size > 0:
        return Result(True, summary=f"{m.group(1)} binaries, {m.group(2)} pages, account {acct}")
    tail = [ln.strip() for ln in text.splitlines() if ln.strip()][-1:] or ["no output"]
    return Result(False, error=f"exit {proc.returncode}: {tail[0][:200]}")


# ---- credential provisioning (one time per account) ----------------------------

def _store(cred: bytes, account: str, force: bool) -> Path:
    if len(cred) != 16:
        raise ValueError(f"credential must be 16 bytes, got {len(cred)}")
    dest = credential_path(account)
    if dest.exists():
        if dest.read_bytes() == cred:
            return dest
        if not force:
            raise FileExistsError(f"a DIFFERENT credential already exists for {account} "
                                  f"({dest}); pass --force to replace it")
    dest.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(dest.parent, 0o700)
    fd, tmp = tempfile.mkstemp(prefix=f".{account}.", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(cred)
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return dest


def _self_test(cred: bytes, ipa: Path) -> str:
    """Decrypt `ipa` with `cred` in a temp dir and require that every image the
    app needs at launch comes out with cryptid 0. Returns the summary."""
    from .acquire import verify_decrypted   # lazy: acquire imports this module
    ipa = Path(ipa).resolve()               # the tool's cwd is its own directory
    with tempfile.TemporaryDirectory(prefix="fairplay-selftest-") as td:
        cpath = Path(td) / "credential.bin"
        cpath.write_bytes(cred)
        out = Path(td) / "out.ipa"
        proc = run_cmd_streamed([sys.executable, str(CONFIG.fairplay.tool_dir / "decrypt.py"),
                                 str(ipa), str(out), "--credential", str(cpath)],
                                timeout=900, cwd=CONFIG.fairplay.tool_dir, echo=False)
        m = _SUMMARY_RE.search(proc.stdout or "")
        if proc.returncode != 0 or not m or not out.exists():
            raise RuntimeError(f"self-test decrypt failed: {(proc.stdout or '')[-300:]}")
        v = verify_decrypted(out)
        if v["critical"]:
            raise RuntimeError(f"self-test: still encrypted after decrypt: {v['critical'][:3]} "
                               f"(wrong credential for this account?)")
        return f"{m.group(1)} binaries, {m.group(2)} pages"


def import_credential(src: str | Path, ipa: str | Path, force: bool = False) -> tuple[str, Path, str]:
    """Store an existing 16-byte credential.bin under the account of `ipa`,
    after proving it decrypts `ipa`. Returns (account, path, self-test summary)."""
    ok, why = tool_ready()
    if not ok:
        raise RuntimeError(why)
    acct = account_of(ipa)
    if not acct:
        raise ValueError(f"{ipa}: no readable SINF account (is it an ENCRYPTED IPA?)")
    cred = Path(src).read_bytes()
    summary = _self_test(cred, Path(ipa))
    return acct, _store(cred, acct, force), summary


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, proc: subprocess.Popen, secs: float = 15.0) -> None:
    deadline = time.monotonic() + secs
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("SSH tunnel to the decrypt device exited (root key auth?)")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("SSH tunnel to the decrypt device did not open")


def retrieve_credential(ipa: str | Path, force: bool = False, line_cb=None) -> tuple[str, Path, str]:
    """Retrieve the credential for the account that owns `ipa` from the
    jailbroken iPhone 8 (upstream credential-retrieval/retrieve.py), self-test it
    on `ipa`, and store it. Returns (account, path, self-test summary).

    Needs: root SSH by key on DECRYPT_SSH_HOST (key = FAIRPLAY_ROOT_KEY, in
    /var/jb/var/root/.ssh/authorized_keys on a rootless jailbreak), and at least
    one App Store app of the same account installed on the device. Restarts the
    device's fairplayd once (it respawns)."""
    ok, why = tool_ready()
    if not ok:
        raise RuntimeError(why)
    fp = CONFIG.fairplay
    ipa = Path(ipa).resolve()
    acct = account_of(ipa)
    if not acct:
        raise ValueError(f"{ipa}: no readable SINF account (is it an ENCRYPTED IPA?)")
    if credential_path(acct).exists() and not force:
        return acct, credential_path(acct), "already present"
    host = CONFIG.decrypt_device.ssh_host
    if not host:
        raise RuntimeError("DECRYPT_SSH_HOST is not set")
    if not fp.root_key.exists():
        raise RuntimeError(f"root SSH key {fp.root_key} not found (FAIRPLAY_ROOT_KEY)")
    bundle = fp.tool_dir / "credential-retrieval" / "build" / "bundle"
    missing = [f for f in _DEVICE_FILES if not (bundle / f).exists()]
    if missing:
        raise RuntimeError(f"device bundle incomplete ({', '.join(missing)}): run `make -C {fp.tool_dir}`")
    real_ssh = shutil.which("ssh") or "/usr/bin/ssh"
    emit = line_cb or (lambda ln: log.info("  retrieve | %s", ln))

    with tempfile.TemporaryDirectory(prefix="fairplay-retrieve-") as td:
        td = Path(td)
        known = td / "known_hosts"
        # retrieve.py runs plain `ssh root@127.0.0.1 -p PORT` with BatchMode; a
        # PATH shim pins our key (IdentitiesOnly avoids MaxAuthTries lockouts)
        # and a private known_hosts (the tunnel endpoint's key is per-port).
        shim = td / "bin"
        shim.mkdir()
        (shim / "ssh").write_text(
            "#!/bin/sh\n"
            f'exec "{real_ssh}" -i "{fp.root_key}" -o IdentitiesOnly=yes '
            f'-o UserKnownHostsFile="{known}" "$@"\n')
        os.chmod(shim / "ssh", 0o755)
        env = dict(os.environ, PATH=f"{shim}{os.pathsep}{os.environ.get('PATH', '')}")

        port = _free_port()
        tunnel = subprocess.Popen(
            [real_ssh, "-i", str(fp.root_key), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
             "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=accept-new",
             "-o", "ConnectTimeout=10", "-N", "-L", f"{port}:127.0.0.1:22", f"root@{host}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            _wait_port(port, tunnel)
            udid = _device_udid(port, bundle, env)
            emit(f"device udid {udid}, account {acct}")
            out_dir = td / "out"
            proc = run_cmd_streamed(
                [sys.executable, str(fp.tool_dir / "credential-retrieval" / "retrieve.py"),
                 "--device-udid", udid, "--ssh-port", str(port), "--ipa", str(ipa),
                 "--output-dir", str(out_dir)],
                timeout=300, cwd=fp.tool_dir, env=env, echo=False, line_cb=emit)
            cpath = out_dir / "credential.bin"
            if proc.returncode != 0 or not cpath.exists():
                tail = (proc.stdout or "").strip().splitlines()[-3:]
                raise RuntimeError("retrieve.py failed: " + " | ".join(tail))
            cred = cpath.read_bytes()
        finally:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
    summary = _self_test(cred, ipa)
    return acct, _store(cred, acct, force), summary


def _device_udid(port: int, bundle: Path, env: dict) -> str:
    """The device's 40-hex UDID, read on the device with credential.ios (the
    same check retrieve.py verifies against). Works over WiFi, where idevice_id
    cannot see the device."""
    remote = f"/var/tmp/fp-udid-{os.getpid()}-{int(time.time())}"
    ssh = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=10", "-p", str(port), "root@127.0.0.1"]

    def run(cmd: str, data: bytes | None = None) -> bytes:
        r = subprocess.run(ssh + [cmd], input=data, capture_output=True, env=env, timeout=60)
        if r.returncode:
            raise RuntimeError(f"device command failed: {(r.stdout + r.stderr).decode('utf-8', 'replace')[:200]}")
        return r.stdout
    run(f"umask 077; mkdir -p {remote}")
    try:
        run(f"cat > {remote}/credential.ios", (bundle / "credential.ios").read_bytes())
        run(f"chmod 700 {remote}/credential.ios && {remote}/credential.ios device-udid {remote}/udid.bin")
        raw = run(f"cat {remote}/udid.bin")
    finally:
        try:
            run(f"rm -rf {remote}")
        except RuntimeError:
            pass
    if len(raw) != 20:
        raise RuntimeError(f"unexpected UDID length {len(raw)}")
    return raw.hex()
