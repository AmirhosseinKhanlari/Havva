"""Offline FairPlay decryption: license/account parsing, the credential store,
and acquire's decision between offline decrypt and the ipadecrypt fallback."""
from __future__ import annotations

import os
import plistlib
import struct
import types
import zipfile
from pathlib import Path

import pytest

import pipeline.acquire as acq
from pipeline import fairplay
from pipeline.models import WorkState
from pipeline.util import Proc


# ---- fixtures -------------------------------------------------------------------

def _atom(tag: bytes, body: bytes) -> bytes:
    return struct.pack(">I", 8 + len(body)) + tag + body


def _sinf(account_hex: str) -> bytes:
    schi = _atom(b"user", bytes.fromhex(account_hex)) + _atom(b"key ", b"\x00\x00\x00\x01")
    return _atom(b"sinf", _atom(b"frma", b"game") + _atom(b"schi", schi))


def _macho(cryptid: int) -> bytes:
    """Minimal thin arm64 Mach-O with one LC_ENCRYPTION_INFO_64, >= 4 KiB so
    verify_decrypted treats it as an image."""
    lc = struct.pack("<IIIII", 0x2C, 24, 0x4000, 0x1000, cryptid) + b"\x00" * 4
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(lc), 0, 0)
    return (hdr + lc).ljust(8192, b"\x00")


def _ipa(path: Path, cryptid: int, account: str = "a1b2c3d4", sinf: bool = True) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/A.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "A"}))
        z.writestr("Payload/A.app/A", _macho(cryptid))
        if sinf:
            z.writestr("Payload/A.app/SC_Info/A.sinf", _sinf(account))
    return path


def _fp_config(monkeypatch, tmp_path):
    fp = types.SimpleNamespace(enabled=True, tool_dir=tmp_path / "tool",
                               credentials_dir=tmp_path / "creds", root_key=tmp_path / "key")
    monkeypatch.setattr(fairplay, "CONFIG", types.SimpleNamespace(fairplay=fp, paths=None))
    return fp


def _acq_env(monkeypatch, tmp_path, online=True):
    """acquire in appstore mode with a staged encrypted IPA; returns
    (enc_path, out_path, calls) where calls records ipadecrypt invocations."""
    ipas, work = tmp_path / "ipas", tmp_path / "work"
    ipas.mkdir()
    work.mkdir()
    dd = types.SimpleNamespace(is_bootstrapped=True, online=lambda timeout=2.5: online,
                               ssh_host="10.0.0.1", ssh_port=22, ipadecrypt_cmd="ipadecrypt",
                               bootstrap_config=tmp_path / "absent.json")
    monkeypatch.setattr(acq, "CONFIG", types.SimpleNamespace(
        decrypt_device=dd, acquire_mode="appstore", fairplay=types.SimpleNamespace(enabled=True),
        paths=types.SimpleNamespace(ipa_dir=ipas, work_dir=work)))
    enc = work / "1.enc.ipa"
    monkeypatch.setattr(acq, "download_with_appstore",
                        lambda app_id, row, **kw: (True, str(_ipa(enc, cryptid=1)), ""))
    monkeypatch.setattr(fairplay, "tool_ready", lambda: (True, ""))
    calls = []

    def fake_ipadecrypt(cmd, **kw):
        calls.append(cmd)
        _ipa(Path(cmd[cmd.index("-o") + 1]), cryptid=0)
        return Proc(0, "decrypted 1 image(s) (1.0 MB)", "")
    monkeypatch.setattr(acq, "run_cmd_streamed", fake_ipadecrypt)
    return enc, ipas / "1.decrypted.ipa", calls


# ---- license / account ------------------------------------------------------------

def test_sinf_account_parses_user_field():
    assert fairplay.sinf_account(_sinf("a1b2c3d4")) == "a1b2c3d4"
    assert fairplay.sinf_account(b"garbage") is None
    assert fairplay.sinf_account(_atom(b"sinf", _atom(b"frma", b"game"))) is None   # no schi


def test_account_of_prefers_main_app_sinf(tmp_path):
    p = tmp_path / "x.ipa"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("Payload/A.app/PlugIns/W.appex/SC_Info/W.sinf", _sinf("11111111"))
        z.writestr("Payload/A.app/SC_Info/A.sinf", _sinf("a1b2c3d4"))
    assert fairplay.account_of(p) == "a1b2c3d4"
    assert fairplay.account_of(_ipa(tmp_path / "n.ipa", 1, sinf=False)) is None
    (tmp_path / "bad.ipa").write_bytes(b"not a zip")
    assert fairplay.account_of(tmp_path / "bad.ipa") is None


# ---- credential store ---------------------------------------------------------------

def test_credential_store_is_private_idempotent_and_guarded(tmp_path, monkeypatch):
    fp = _fp_config(monkeypatch, tmp_path)
    p = fairplay._store(b"A" * 16, "a1b2c3d4", force=False)
    assert p == fp.credentials_dir / "a1b2c3d4.bin" and p.read_bytes() == b"A" * 16
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    assert oct(fp.credentials_dir.stat().st_mode & 0o777) == "0o700"
    assert fairplay._store(b"A" * 16, "a1b2c3d4", force=False) == p          # same bytes: no-op
    with pytest.raises(FileExistsError):
        fairplay._store(b"B" * 16, "a1b2c3d4", force=False)                   # never silently replaced
    assert p.read_bytes() == b"A" * 16
    fairplay._store(b"B" * 16, "a1b2c3d4", force=True)
    assert p.read_bytes() == b"B" * 16
    with pytest.raises(ValueError):
        fairplay._store(b"short", "a1b2c3d4", force=True)
    with pytest.raises(ValueError):
        fairplay.credential_path("../etc")
    (fp.credentials_dir / "deadbeef.bin").write_bytes(b"x" * 15)               # wrong size
    (fp.credentials_dir / "notanacct.bin").write_bytes(b"x" * 16)              # bad name
    assert fairplay.accounts() == ["a1b2c3d4"]


def test_decrypt_flags_missing_credential(tmp_path, monkeypatch):
    _fp_config(monkeypatch, tmp_path)
    monkeypatch.setattr(fairplay, "tool_ready", lambda: (True, ""))
    r = fairplay.decrypt(_ipa(tmp_path / "e.ipa", 1), tmp_path / "o.ipa")
    assert not r.ok and r.no_credential and "a1b2c3d4" in r.error
    assert not (tmp_path / "o.ipa").exists()


# ---- acquire: offline first, ipadecrypt as fallback -----------------------------------

def test_offline_success_never_touches_the_device(tmp_path, monkeypatch):
    enc, out, calls = _acq_env(monkeypatch, tmp_path, online=False)

    def fake_decrypt(e, o, **kw):
        _ipa(Path(o), cryptid=0)
        return fairplay.Result(True, summary="1 binaries, 1 pages, account a1b2c3d4")
    monkeypatch.setattr(fairplay, "decrypt", fake_decrypt)
    state, path, note = acq.decrypt_one("1", {"app_id": "1", "country": "us"})
    assert state == WorkState.POSITIVE and path == str(out) and out.exists()
    assert calls == []                                    # ipadecrypt never ran
    assert not enc.exists()                               # staging cleaned
    assert not list(out.parent.glob(".*.fairplay"))       # no temp left behind


def test_falls_back_to_ipadecrypt_without_credential(tmp_path, monkeypatch):
    enc, out, calls = _acq_env(monkeypatch, tmp_path)
    monkeypatch.setattr(fairplay, "decrypt", lambda e, o, **kw:
                        fairplay.Result(False, error="no credential for account 11111111",
                                        no_credential=True))
    state, path, _ = acq.decrypt_one("1", {"app_id": "1", "country": "us"})
    assert state == WorkState.POSITIVE and out.exists()
    assert len(calls) == 1 and calls[0][2] == str(enc)    # ipadecrypt got the staged IPA


def test_still_encrypted_offline_output_is_discarded(tmp_path, monkeypatch):
    enc, out, calls = _acq_env(monkeypatch, tmp_path)

    def bad_decrypt(e, o, **kw):
        _ipa(Path(o), cryptid=1)                          # "succeeded" but main image encrypted
        return fairplay.Result(True, summary="1 binaries, 0 pages")
    monkeypatch.setattr(fairplay, "decrypt", bad_decrypt)
    state, path, _ = acq.decrypt_one("1", {"app_id": "1", "country": "us"})
    assert len(calls) == 1                                # fell back
    assert state == WorkState.POSITIVE                    # ipadecrypt's output accepted
    assert not list(out.parent.glob(".*.fairplay"))


def test_no_credential_and_device_offline_is_retryable(tmp_path, monkeypatch):
    enc, out, calls = _acq_env(monkeypatch, tmp_path, online=False)
    monkeypatch.setattr(fairplay, "decrypt", lambda e, o, **kw:
                        fairplay.Result(False, error="no credential", no_credential=True))
    state, path, err = acq.decrypt_one("1", {"app_id": "1", "country": "us"})
    assert state == WorkState.UNTESTED and path == ""
    assert "offline FairPlay could not decrypt" in err and "offline at 10.0.0.1:22" in err
    assert calls == [] and not enc.exists() and not out.exists()


def test_disabled_offline_goes_straight_to_ipadecrypt(tmp_path, monkeypatch):
    enc, out, calls = _acq_env(monkeypatch, tmp_path)
    acq.CONFIG.fairplay.enabled = False
    monkeypatch.setattr(fairplay, "decrypt", lambda *a, **k: pytest.fail("offline must not run"))
    state, _, _ = acq.decrypt_one("1", {"app_id": "1", "country": "us"})
    assert state == WorkState.POSITIVE and len(calls) == 1


def test_acquire_one_needs_device_only_without_offline(tmp_path, monkeypatch):
    from pipeline.db import Database
    db = Database(tmp_path / "p.db")
    dd = types.SimpleNamespace(is_bootstrapped=True, online=lambda timeout=2.5: False,
                               ssh_host="10.0.0.1", ssh_port=22)
    monkeypatch.setattr(acq, "CONFIG", types.SimpleNamespace(decrypt_device=dd, acquire_mode="appstore"))
    reached = []
    monkeypatch.setattr(acq, "decrypt_one", lambda key, row, *a, **k:
                        reached.append(key) or (WorkState.POSITIVE, "/x.ipa", ""))
    monkeypatch.setattr(acq, "offline_capable", lambda: False)
    state, _, err = acq.acquire_one(db, app_id="555")
    assert state == WorkState.UNTESTED and "offline" in err and reached == []
    monkeypatch.setattr(acq, "offline_capable", lambda: True)
    state, _, _ = acq.acquire_one(db, app_id="555")
    assert state == WorkState.POSITIVE and reached == ["555"]


def test_offline_capable_requires_local_staging_mode(monkeypatch):
    monkeypatch.setattr(fairplay, "ready", lambda: (True, ""))
    for mode, want in (("appstore", True), ("ipatool", True), ("ipadecrypt", False)):
        monkeypatch.setattr(acq, "CONFIG", types.SimpleNamespace(acquire_mode=mode))
        assert acq.offline_capable() is want
