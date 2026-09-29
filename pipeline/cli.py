"""Pipeline entry point.

Usage:
    python -m pipeline.cli status          # DB counts + config readiness
    python -m pipeline.cli doctor          # check tools/config before a run

Stage subcommands (crawl, acquire, static, dynamic, attest, aggregate) are wired
in as their modules land.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from .config import CONFIG
from .db import Database


def cmd_crawl(args: argparse.Namespace) -> int:
    from . import crawl
    db = Database(CONFIG.paths.db)
    countries = args.countries.split(",") if args.countries else None
    cats = None
    if args.category:
        cats = {args.category: crawl.CATEGORIES.get(args.category, args.category)}
    n = crawl.crawl(db, countries=countries, categories=cats,
                    count=args.count, enrich=not args.no_enrich, source=args.source)
    print(f"upserted {n} app rows")
    return 0


def cmd_acquire(args: argparse.Namespace) -> int:
    from . import acquire
    db = Database(CONFIG.paths.db)
    if args.bundle or args.app_id:
        state, path, err = acquire.acquire_one(db, bundle_id=args.bundle, app_id=args.app_id,
                                               country=args.country, from_appstore=args.from_appstore)
        print(f"state={state.name} path={path or '-'} error={err or '-'}")
        return 0 if state.name == "POSITIVE" else 1
    stats = acquire.run(db, limit=args.limit, from_appstore=args.from_appstore)
    print(stats)
    return 0


def cmd_static(args: argparse.Namespace) -> int:
    from . import static_classify
    db = Database(CONFIG.paths.db)
    print(static_classify.run(db, limit=args.limit))
    return 0


def cmd_dynamic(args: argparse.Namespace) -> int:
    from . import dynamic
    db = Database(CONFIG.paths.db)
    print(dynamic.run(db, limit=args.limit))
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    from . import attestation
    db = Database(CONFIG.paths.db)
    print(attestation.run(db, limit=args.limit))
    return 0


def cmd_attest_detect(args: argparse.Namespace) -> int:
    from . import attest_detect
    db = Database(CONFIG.paths.db)
    print(attest_detect.run(db, limit=args.limit))
    return 0


def cmd_aggregate(_args: argparse.Namespace) -> int:
    from . import aggregate
    db = Database(CONFIG.paths.db)
    m = aggregate.report(db)
    print(json.dumps(m, indent=2))
    return 0


def cmd_iap(args: argparse.Namespace) -> int:
    from . import iap
    db = Database(CONFIG.paths.db)
    print(iap.run(db, limit=args.limit, workers=args.workers, rotate_vpn=args.rotate_vpn))
    return 0


def cmd_export(_args: argparse.Namespace) -> int:
    db = Database(CONFIG.paths.db)
    out_dir = CONFIG.paths.results_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    with db.connect() as c:
        rows = c.execute(
            "SELECT app_id, country, bundle_id, primary_category, rank, name "
            "FROM apps ORDER BY primary_category, rank").fetchall()
    # Canonical id list (paper-1 style: appid,country)
    ids = out_dir / "app_ids.txt"
    ids.write_text("".join(f"{r['app_id']},{r['country']}\n" for r in rows))
    # Human-readable TSV list
    full = out_dir / "app_list.txt"
    with full.open("w") as f:
        f.write("app_id\tcountry\tbundle_id\tcategory\trank\tname\n")
        for r in rows:
            f.write(f"{r['app_id']}\t{r['country']}\t{r['bundle_id'] or ''}\t"
                    f"{r['primary_category'] or ''}\t{r['rank'] or ''}\t{r['name'] or ''}\n")
    print(f"wrote {len(rows)} apps to:\n  {ids}\n  {full}")
    return 0


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
    search_dirs = (CONFIG.paths.dylib_dir, CONFIG.paths.root.parent / "Dylibs")
    for name in (CONFIG.dylibs.ssks, CONFIG.dylibs.sideloadfix, CONFIG.dylibs.frida_gadget):
        found = next((str(d / name) for d in search_dirs if (d / name).exists()), "")
        print(f"  {name:24} {'ok: ' + found if found else 'MISSING'}")

    print("\nAcquire readiness (Stage B):")
    print(f"  ipadecrypt bootstrapped  {'yes' if CONFIG.decrypt_device.is_bootstrapped else 'NO (run bootstrap)'}")
    import shutil as _sh
    print(f"  ipadecrypt binary        {'ok' if _sh.which(CONFIG.decrypt_device.ipadecrypt_cmd) or Path_exists(Path(CONFIG.decrypt_device.ipadecrypt_cmd)) else 'MISSING'}")
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

    p_crawl = sub.add_parser("crawl", help="crawl AppFigures + enrich with iTunes metadata")
    p_crawl.add_argument("--countries", help="comma list, overrides STOREFRONTS")
    p_crawl.add_argument("--category", help="single category id (e.g. 6015 Finance)")
    p_crawl.add_argument("--count", type=int, help="apps per category")
    p_crawl.add_argument("--no-enrich", action="store_true", help="skip iTunes metadata")
    p_crawl.add_argument("--source", choices=["auto", "appfigures", "itunes"], default="auto",
                         help="chart source (auto: appfigures if APPFIGURES_COOKIE set, else itunes)")
    p_crawl.set_defaults(func=cmd_crawl)

    p_acq = sub.add_parser("acquire", help="download + decrypt IPAs (ipadecrypt or ipatool)")
    p_acq.add_argument("--limit", type=int, help="max apps this run (corpus mode)")
    p_acq.add_argument("--bundle", help="acquire ONE specific app by bundle id (e.g. com.calm.calmapp)")
    p_acq.add_argument("--app-id", help="optional App Store numeric id for the single app")
    p_acq.add_argument("--country", default="us", help="storefront for single-app acquire (default us)")
    p_acq.add_argument("--from-appstore", action="store_true", help="force App Store fetch")
    p_acq.set_defaults(func=cmd_acquire)

    p_static = sub.add_parser("static", help="static defense classifier over decrypted IPAs")
    p_static.add_argument("--limit", type=int, help="max apps this run")
    p_static.set_defaults(func=cmd_static)

    p_dyn = sub.add_parser("dynamic", help="run the bypass ladder on pinned apps")
    p_dyn.add_argument("--limit", type=int, help="max apps this run")
    p_dyn.set_defaults(func=cmd_dynamic)

    p_att = sub.add_parser("attest", help="attestation-enforcement differential test")
    p_att.add_argument("--limit", type=int, help="max apps this run")
    p_att.set_defaults(func=cmd_attest)

    p_ad = sub.add_parser("attest-detect", help="dynamically confirm App Attest usage + endpoint")
    p_ad.add_argument("--limit", type=int, help="max apps this run")
    p_ad.set_defaults(func=cmd_attest_detect)

    sub.add_parser("aggregate", help="compute metrics + write summary").set_defaults(func=cmd_aggregate)
    p_iap = sub.add_parser("iap", help="detect in-app purchases via App Store pages")
    p_iap.add_argument("--limit", type=int, help="max apps this run")
    p_iap.add_argument("--workers", type=int, default=8, help="concurrent fetchers")
    p_iap.add_argument("--rotate-vpn", action="store_true",
                       help="rotate NordVPN exit IP (openvpn, needs sudo) when throttled")
    p_iap.set_defaults(func=cmd_iap)

    sub.add_parser("export", help="write app_ids.txt + app_list.txt from the corpus").set_defaults(func=cmd_export)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
