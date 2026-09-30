"""Stage D: instrument builder (re-sign + inject bypass dylibs).

Produces, on demand, a signed IPA for a named bypass config by injecting dylibs
into the decrypted IPA and re-signing with zsign. Host-side; needs the device
only at install time (device.py).

Configs (see escalate.py ladder):
  stage0  : SideloadFix only, no bypass (baseline, so the app runs)
  control : nothing injected, pure re-sign (crash-cause disambiguation)
  dylib   : SSKS + SideloadFix
  renamed : SSKS renamed/stripped + SideloadFix
  frida   : Frida gadget (renamed) + gadget config + SideloadFix
  evasion : renamed SSKS + SideloadFix + evasion module (detector neutralization)

Injection uses LIEF to add a load command to the main executable and drops the
dylib in Payload/<App>.app/Frameworks/. Idea carried from paper 1's inject.py
(weak load for hook dylibs, strong load for the Frida gadget).
"""

from __future__ import annotations

import json
import plistlib
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .config import CONFIG
from .models import BypassStage
from .util import get_logger, run_cmd

log = get_logger("instrument", CONFIG.paths.log_dir)


@dataclass
class DylibSpec:
    source: str          # file name in dylib_dir
    install_as: str      # name inside the app's Frameworks/
    load: str            # "weak" or "strong"
    config_listen: bool = False  # write a Frida-gadget .config next to it


def _d() -> "CONFIG.dylibs.__class__":
    return CONFIG.dylibs


# Map a config name to the dylibs it injects. Resolved lazily so config/env win.
def config_specs(config: str) -> list[DylibSpec]:
    d = CONFIG.dylibs
    sideloadfix = DylibSpec(d.sideloadfix, d.sideloadfix, "weak")
    if config == "stage0":
        return [sideloadfix]
    if config == "control":
        return []
    if config == BypassStage.DYLIB.value:
        return [DylibSpec(d.ssks, d.ssks, "weak"), sideloadfix]
    if config == BypassStage.RENAMED_DYLIB.value:
        return [DylibSpec(d.ssks, d.ssks_alias, "weak"), sideloadfix]
    if config == BypassStage.FRIDA.value:
        return [DylibSpec(d.frida_gadget, d.frida_alias, "strong", config_listen=True),
                sideloadfix]
    if config == BypassStage.EVASION.value:
        return [DylibSpec(d.ssks, d.ssks_alias, "weak"),
                DylibSpec("EvasionKit.dylib", "libSystemBridge.dylib", "weak"),
                sideloadfix]
    if config == "attest_observe":
        # See traffic (pinning bypassed) + observe App Attest API calls.
        return [DylibSpec(d.ssks, d.ssks_alias, "weak"),
                DylibSpec("AttestObserver.dylib", "AttestObserver.dylib", "weak"),
                sideloadfix]
    raise ValueError(f"unknown config: {config}")


def dylib_catalog() -> list[dict]:
    """User-selectable dylibs for the dynamic stage, with on-disk availability."""
    d = CONFIG.dylibs
    items = [
        {"id": "ssks", "label": "SSL Kill Switch 2", "desc": "Certificate-pinning bypass",
         "source": d.ssks, "alias": d.ssks_alias, "load": "weak", "default": True},
        {"id": "sideloadfix", "label": "SideloadFix",
         "desc": "Prevents the re-signed app from crashing (recommended)",
         "source": d.sideloadfix, "alias": "libMobileBridge.dylib", "load": "weak", "default": True},
        {"id": "frida", "label": "Frida Gadget", "desc": "Runtime instrumentation (listens :27042)",
         "source": d.frida_gadget, "alias": d.frida_alias, "load": "strong",
         "config_listen": True, "default": False},
        {"id": "evasion", "label": "EvasionKit", "desc": "Hides injection from anti-tamper / anti-debug",
         "source": "EvasionKit.dylib", "alias": "libSystemBridge.dylib", "load": "weak", "default": False},
        {"id": "attest", "label": "AttestObserver", "desc": "Logs App Attest / DeviceCheck API calls",
         "source": "AttestObserver.dylib", "alias": "libServiceBridge.dylib", "load": "weak", "default": False},
    ]
    for it in items:
        it["present"] = _dylib_path(it["source"]).exists()
    return items


def custom_specs(selected_ids: list[str], aliased: bool = True) -> list[DylibSpec]:
    """Build a DylibSpec list from a user-selected set of catalog ids. When
    `aliased`, dylibs are installed under a disguised name to evade detection."""
    cat = {it["id"]: it for it in dylib_catalog()}
    specs = []
    for sid in selected_ids:
        it = cat.get(sid)
        if not it:
            continue
        install_as = it["alias"] if (it.get("alias") and (aliased or it["id"] == "evasion")) else it["source"]
        specs.append(DylibSpec(it["source"], install_as, it["load"], it.get("config_listen", False)))
    return specs


def ensure_pem() -> bool:
    """Make sure a signing PEM exists; export it from the .p12 if needed."""
    s = CONFIG.signing
    if s.pem.exists():
        return True
    if not s.p12.exists():
        log.error("no signing cert: %s missing", s.p12)
        return False
    for extra in (["-legacy"], []):
        p = run_cmd(["openssl", "pkcs12", *extra, "-in", str(s.p12), "-out", str(s.pem),
                     "-nodes", "-passin", f"pass:{s.p12_password}"], timeout=60)
        if s.pem.exists():
            return True
    log.error("failed to export PEM from p12")
    return False


def _dylib_path(name: str) -> Path:
    # Bypass dylibs live in the project root; the Frida gadget in ../Dylibs.
    for base in (CONFIG.paths.dylib_dir, CONFIG.paths.root.parent / "Dylibs"):
        p = base / name
        if p.exists():
            return p
    return CONFIG.paths.dylib_dir / name


def _app_dir(unzipped: Path) -> Path | None:
    payload = unzipped / "Payload"
    apps = list(payload.glob("*.app")) if payload.exists() else []
    return apps[0] if apps else None


def _inject(main_binary: Path, install_name: str, load: str) -> bool:
    """Add a load command for @rpath/<install_name> to the main executable."""
    try:
        import lief
    except ImportError:
        log.error("lief not installed (pip install lief)")
        return False
    fat = lief.MachO.parse(str(main_binary))
    if fat is None:
        return False
    rpath_name = f"@rpath/{install_name}"
    for macho in fat:  # every arch slice
        if load == "strong":
            macho.add_library(rpath_name)
        else:
            cmd = lief.MachO.DylibCommand.weak_lib(rpath_name)
            macho.add(cmd)
    fat.write(str(main_binary))
    return True


def _write_gadget_config(dest: Path) -> None:
    cfg = {"interaction": {"type": "listen", "address": "127.0.0.1", "port": 27042,
                           "on_load": "resume"}, "code_signing": "required"}
    dest.write_text(json.dumps(cfg))


def build(app_id: str, decrypted_ipa: str | Path, config: str,
          specs: "list[DylibSpec] | None" = None) -> tuple[bool, str, str]:
    """Build a signed IPA for `config`. If `specs` is given, inject exactly those
    dylibs (a custom selection) instead of the named config's fixed set.
    Returns (ok, signed_ipa_path, error)."""
    if not ensure_pem():
        return False, "", "no signing PEM"
    decrypted_ipa = Path(decrypted_ipa)
    if not decrypted_ipa.exists():
        return False, "", "decrypted ipa missing"

    work = CONFIG.paths.work_dir / f"inst_{app_id}_{config}"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(decrypted_ipa) as z:
            z.extractall(work)
    except (zipfile.BadZipFile, OSError) as e:
        return False, "", f"unzip failed: {e}"

    app_dir = _app_dir(work)
    if not app_dir:
        return False, "", "no .app in ipa"
    info = plistlib.loads((app_dir / "Info.plist").read_bytes())
    main_binary = app_dir / info.get("CFBundleExecutable", "")
    if not main_binary.exists():
        return False, "", "main binary missing"

    fw = app_dir / "Frameworks"
    fw.mkdir(exist_ok=True)

    if specs is None:
        try:
            specs = config_specs(config)
        except ValueError as e:
            return False, "", str(e)

    log.info("unpacked %s (%s)", main_binary.name, info.get("CFBundleIdentifier", "?"))
    for spec in specs:
        src = _dylib_path(spec.source)
        if not src.exists():
            log.error("dylib not found: %s", spec.source)
            return False, "", f"dylib not found: {spec.source}"
        shutil.copy2(src, fw / spec.install_as)
        if not _inject(main_binary, spec.install_as, spec.load):
            log.error("inject failed: %s", spec.install_as)
            return False, "", f"inject failed: {spec.install_as}"
        alias = f" as {spec.install_as}" if spec.install_as != spec.source else ""
        log.info("  injected %s%s (%s load)", spec.source, alias, spec.load)
        if spec.config_listen:
            # Frida gadget wants its .config in Frameworks/ and the app root.
            stem = Path(spec.install_as).stem
            _write_gadget_config(fw / f"{stem}.config")
            _write_gadget_config(app_dir / f"{stem}.config")
            log.info("  wrote Frida gadget config (%s.config)", stem)

    # Repack.
    log.info("repacking IPA ...")
    staged_ipa = work.parent / f"{app_id}_{config}.staged.ipa"
    if staged_ipa.exists():
        staged_ipa.unlink()
    # make_archive returns the actual archive path it created (e.g. ...staged.zip);
    # use it directly rather than guessing the name.
    made = Path(shutil.make_archive(str(staged_ipa.with_suffix("")), "zip", work))
    if made.resolve() != staged_ipa.resolve():
        made.replace(staged_ipa)
    shutil.rmtree(work, ignore_errors=True)

    # Re-sign.
    out = CONFIG.paths.work_dir / f"{app_id}_{config}.signed.ipa"
    if out.exists():
        out.unlink()
    s = CONFIG.signing
    log.info("re-signing with zsign ...")
    p = run_cmd([str(s.zsign), "-k", str(s.pem), "-m", str(s.mobileprovision),
                 "-o", str(out), str(staged_ipa)], timeout=300)
    staged_ipa.unlink(missing_ok=True)
    if out.exists() and out.stat().st_size > 0:
        log.info("  signed -> %s (%.1f MB)", out.name, out.stat().st_size / (1024 * 1024))
        return True, str(out), ""
    return False, "", f"zsign failed: {(p.stderr or p.stdout)[:300]}"
