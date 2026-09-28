"""Pipeline entry point.

Usage:
    python -m pipeline.cli status          # DB counts + config readiness
    python -m pipeline.cli doctor          # check tools/config before a run

Stage subcommands (crawl, acquire, static, dynamic, attest, aggregate) are wired
in as their modules land.
"""

from __future__ import annotations

import argparse
import shutil

from .config import CONFIG
from .db import Database


def cmd_status(_args: argparse.Namespace) -> int:
    db = Database(CONFIG.paths.db)
    counts = db.counts()
    print(f"DB: {CONFIG.paths.db}")
    for k, v in counts.items():
        print(f"  {k:16} {v}")
    missing = CONFIG.missing_for_dynamic()
    if missing:
        print("\nMissing config for on-device stages:")
        for m in missing:
            print(f"  - {m}")
    else:
        print("\nOn-device config: ready")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    print("Tool availability:")
    for tool in ("git", "idevice_id", "ideviceinstaller", "xcrun", "zsign",
                 "codesign", "otool", "strings", "nm"):
        path = shutil.which(tool)
        # zsign may be a local binary, not on PATH.
        if tool == "zsign" and not path and CONFIG.signing.zsign.exists():
            path = str(CONFIG.signing.zsign)
        print(f"  {tool:16} {'found: ' + path if path else 'MISSING'}")
    print("\nSigning assets:")
    for name, p in (("p12", CONFIG.signing.p12), ("pem", CONFIG.signing.pem),
                    ("profile", CONFIG.signing.mobileprovision), ("zsign", CONFIG.signing.zsign)):
        print(f"  {name:16} {'ok: ' + str(p) if Path_exists(p) else 'missing: ' + str(p)}")
    print("\nBypass dylibs:")
    for name in (CONFIG.dylibs.ssks, CONFIG.dylibs.sideloadfix, CONFIG.dylibs.frida_gadget):
        p = CONFIG.paths.dylib_dir / name
        print(f"  {name:24} {'ok' if p.exists() else 'MISSING'}")
    return 0


def Path_exists(p) -> bool:
    try:
        return p.exists()
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(prog="pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="DB counts and config readiness").set_defaults(func=cmd_status)
    sub.add_parser("doctor", help="check tools and assets").set_defaults(func=cmd_doctor)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
