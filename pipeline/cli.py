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
    # List available (older) versions for one app, then exit.
    if getattr(args, "list_versions", False):
        from . import appstore_dl
        store_id = args.app_id
        if not store_id and args.bundle:
            store_id = appstore_dl.lookup_app_id(args.bundle, args.country.upper())
        if not store_id:
            print("--list-versions needs --app-id (or a resolvable --bundle)")
            return 1
        vers = appstore_dl.list_versions(str(store_id), CONFIG.appstore.itunes_server,
                                         limit=args.version_limit)
        print(f"{len(vers)} versions (newest first) for {store_id}:")
        for v in vers:
            print(f"  {v['shortVersion']:20} verId={v['verId']}")
        return 0
    if args.bundle or args.app_id:
        state, path, err = acquire.acquire_one(db, bundle_id=args.bundle, app_id=args.app_id,
                                               country=args.country, from_appstore=args.from_appstore,
                                               purchase=args.purchase, auth_code=args.auth_code or "",
                                               app_ver_id=args.version)
        if state.name == "POSITIVE":
            import os
            mb = os.path.getsize(path) / (1024 * 1024) if path and os.path.exists(path) else 0
            print(f"\n✓ SUCCESS  decrypted -> {path}  ({mb:.1f} MB)")
            return 0
        print(f"\n✗ {state.name}  {args.bundle or args.app_id}: {err or '-'}")
        return 1
    stats = acquire.run(db, limit=args.limit, from_appstore=args.from_appstore,
                        purchase=args.purchase)
    print(stats)
    return 0


def cmd_static(args: argparse.Namespace) -> int:
    from . import static_classify
    db = Database(CONFIG.paths.db)
    print(static_classify.run(db, limit=args.limit))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from . import analysis
    db = Database(CONFIG.paths.db)
    if args.app_id:
        report = analysis.analyze_one(db, args.app_id)
        print(f"analyzed {args.app_id}: {len(report['sdks'])} SDKs, "
              f"{len(report['secrets'].get('findings', []))} secret findings")
        return 0
    print(analysis.run(db, limit=args.limit))
    return 0


def cmd_dynamic(args: argparse.Namespace) -> int:
    from . import dynamic
    db = Database(CONFIG.paths.db)
    print(dynamic.run(db, limit=args.limit))
    return 0


def cmd_detect_pinning(args: argparse.Namespace) -> int:
    from . import device, dynamic
    db = Database(CONFIG.paths.db)
    row = db.get_app(args.app)
    if not row:
        print(f"app not found: {args.app}")
        return 1
    driver = device.default_driver()
    res = dynamic.detect_pinning(db, row, driver, aliased=not args.no_alias,
                                 sign_env=args.sign_env, swap_certs=args.swap_certs)
    tag = "" if res["reliable"] else "  (open/bypassable split UNRELIABLE: clean run did not launch)"
    print(f"pinned, bypassable by SSL Kill Switch ({len(res['pinned'])}){tag}:")
    for h in res["pinned"]:
        print(f"  \N{LOCK} {h}")
    print(f"pinned, NOT bypassable / hard-pinned ({len(res['hard_pinned'])}):")
    for h in res["hard_pinned"]:
        print(f"  \N{SHIELD} {h}")
    if res["not_pinned"]:
        print(f"open, no enforced pinning ({len(res['not_pinned'])}):")
        for h in res["not_pinned"]:
            print(f"  \N{OPEN LOCK} {h}")
    if res["unresolved"]:
        print(f"unresolved / dead endpoints ({len(res['unresolved'])}):")
        for h in res["unresolved"]:
            print(f"  \N{BALLOT X} {h}")
    return 0


def cmd_iap_bypass(args: argparse.Namespace) -> int:
    from . import device, dynamic
    db = Database(CONFIG.paths.db)
    row = db.get_app(args.app)
    if not row:
        print(f"app not found: {args.app}")
        return 1
    driver = device.default_driver()
    res = dynamic.detect_iap_bypass(db, row, driver, sign_env=args.sign_env,
                                    swap_certs=args.swap_certs)
    print(f"verdict: {res['verdict']} ({res.get('n_iap_flows', 0)} IAP flows)")
    if res.get("method"):
        print(f"  method: {res['method']}")
    if res.get("fields"):
        print(f"  fields: {', '.join(res['fields'])}")
    if res.get("error"):
        print(f"  error: {res['error']}")
    return 0


def cmd_detect_sideload(args: argparse.Namespace) -> int:
    from . import dynamic
    db = Database(CONFIG.paths.db)
    row = db.get_app(args.app)
    if not row:
        print(f"app not found: {args.app}")
        return 1
    res = dynamic.detect_sideload(db, row, sign_env=args.sign_env,
                                  monitor_seconds=args.secs)
    print(f"verdict: {res['verdict']}")
    print(f"  {res['note']}")
    print(f"  plain re-sign survived: {res['control'].survived} | "
          f"+SideloadFix survived: {res['fixed'].survived}")
    return 0


def cmd_inspect_storage(args: argparse.Namespace) -> int:
    from . import dynamic
    db = Database(CONFIG.paths.db)
    row = db.get_app(args.app)
    if not row:
        print(f"app not found: {args.app}")
        return 1
    res = dynamic.inspect_storage(db, row, sign_env=args.sign_env, monitor_seconds=args.secs)
    print(f"verdict: {res['verdict']} — {res['note']}")
    print(f"stores: {res['stores']}")
    for f in res["findings"]:
        print(f"  [{f['severity']}] {f['store']} · {f['file']} · {f['type']}"
              + (f" · {f['detail']}" if f.get('detail') else ""))
    return 0


def cmd_backfill_bundles(_args: argparse.Namespace) -> int:
    db = Database(CONFIG.paths.db)
    fixed, missing = db.backfill_bundle_ids()
    print(f"backfilled {fixed} bundle id(s); {missing} still missing (no metadata / not acquired)")
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path
    from . import cve
    db = Database(CONFIG.paths.db)
    an = db.get_analysis(args.app)
    if not an:
        print(f"app not analyzed: {args.app} (run deep analysis first)")
        return 1
    deps = json.loads(an["dependencies"]) if an["dependencies"] else []
    row = db.get_app(args.app)
    meta = {"app_id": args.app, "name": row["name"] if row else args.app,
            "version": (row["current_version"] if row else "")}
    sbom = cve.build_sbom(meta, deps)
    out = args.out or f"sbom_{args.app}.json"
    Path(out).write_text(json.dumps(sbom, indent=2))
    print(f"wrote {out} ({len(sbom.get('components', []))} components, "
          f"{len(sbom.get('vulnerabilities', []))} vulnerabilities)")
    return 0


def cmd_dep_stats(args: argparse.Namespace) -> int:
    from . import cve
    s = cve.prevalence(Database(CONFIG.paths.db))
    print(f"apps analyzed: {s['apps_analyzed']} | with deps: {s['apps_with_deps']} | "
          f"with vulnerable dep: {s['apps_with_vuln_dep']} ({s['pct_vulnerable']}%)")
    print("top vulnerable libraries:")
    for n, c in s["top_vulnerable_libs"]:
        print(f"  {c:4d}  {n}")
    print("top CVEs:")
    for n, c in s["top_cves"]:
        print(f"  {c:4d}  {n}")
    return 0


def _print_ats(app_id: str, res: dict) -> None:
    if not res.get("checked"):
        print(f"{app_id}: skipped ({res.get('reason')})")
        return
    print(f"{app_id}: {res['verdict']} | {res['n_pass_default']}/{res['n_tested']} pass default ATS | "
          f"{res['n_unnecessary']} unnecessary weakening(s)")
    for u in res.get("unnecessary_weakenings", []):
        print(f"    {u['domain']}: {u['detail']}")


def cmd_ats_gap(args: argparse.Namespace) -> int:
    from . import ats_runtime
    db = Database(CONFIG.paths.db)
    if args.app:
        _print_ats(args.app, ats_runtime.assess_and_store(db, args.app))
        return 0
    with db.connect() as c:
        ids = [r["app_id"] for r in c.execute(
            "SELECT app_id FROM analysis WHERE ats_gap IS NULL").fetchall()]
    if args.limit:
        ids = ids[:args.limit]
    for aid in ids:
        try:
            _print_ats(aid, ats_runtime.assess_and_store(db, aid))
        except Exception as e:  # noqa: BLE001
            print(f"{aid}: error {e}")
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


def cmd_web(_args: argparse.Namespace) -> int:
    from .web.__main__ import main as web_main
    web_main()
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

    from . import acquire, fairplay
    fp = CONFIG.fairplay
    t_ok, t_why = fairplay.tool_ready()
    accts = fairplay.accounts()
    print("\nOffline FairPlay (fairplay-decrypt):")
    print(f"  tool                     {'ok: ' + str(fp.tool_dir) if t_ok else 'NOT READY: ' + t_why}")
    print(f"  credentials              {', '.join(accts) if accts else 'none'}  ({fp.credentials_dir})")
    print(f"  used by acquire          {'yes' if acquire.offline_capable() else 'no'} "
          f"(ACQUIRE_MODE={CONFIG.acquire_mode}; needs appstore/ipatool + tool + a credential)")
    return 0


def cmd_fairplay_credential(args: argparse.Namespace) -> int:
    """Provision the offline FairPlay credential for one Apple account."""
    from . import fairplay
    if args.list:
        accts = fairplay.accounts()
        print(f"{len(accts)} credential(s) in {CONFIG.fairplay.credentials_dir}")
        for a in accts:
            print(f"  {a}")
        return 0
    if not args.ipa:
        print("--ipa <encrypted IPA of the account> is required (it names the account and is "
              "used to self-test the credential)")
        return 1
    try:
        if args.import_file:
            acct, path, summary = fairplay.import_credential(args.import_file, args.ipa, force=args.force)
        else:
            print("retrieving from the jailbroken decrypt device (restarts its fairplayd once) ...")
            acct, path, summary = fairplay.retrieve_credential(
                args.ipa, force=args.force, line_cb=lambda ln: print("  " + ln))
    except (OSError, ValueError, RuntimeError) as e:
        print(f"✗ {e}")
        return 1
    print(f"✓ account {acct}: {path}  (self-test: {summary})")
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
    sub.add_parser("web", help="launch the Havva web UI").set_defaults(func=cmd_web)

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
    p_acq.add_argument("--purchase", action="store_true",
                       help="obtain a license for unowned apps (may need --auth-code); "
                            "default off = download owned apps only, no purchase")
    p_acq.add_argument("--auth-code", help="Apple 2FA/verification code for --purchase")
    p_acq.add_argument("--from-appstore", action="store_true", help="force App Store fetch")
    p_acq.add_argument("--version", help="download a specific OLD build: an externalVersionId "
                                        "or a dotted short version (e.g. 1.0.5). appstore mode only")
    p_acq.add_argument("--list-versions", action="store_true",
                       help="list an app's available (older) versions and exit (appstore mode)")
    p_acq.add_argument("--version-limit", type=int, default=None,
                       help="cap how many newest versions to resolve for --list-versions")
    p_acq.set_defaults(func=cmd_acquire)

    p_fpc = sub.add_parser("fairplay-credential",
                           help="provision the offline FairPlay credential for one Apple account "
                                "(one time per account; acquire then decrypts that account's IPAs "
                                "on the Mac without the iPhone 8)")
    p_fpc.add_argument("--ipa", help="an ENCRYPTED IPA downloaded by that account (names the "
                                     "account and self-tests the credential)")
    p_fpc.add_argument("--import", dest="import_file",
                       help="store an existing 16-byte credential.bin instead of retrieving one")
    p_fpc.add_argument("--force", action="store_true", help="replace a different stored credential")
    p_fpc.add_argument("--list", action="store_true", help="list stored credentials and exit")
    p_fpc.set_defaults(func=cmd_fairplay_credential)

    p_static = sub.add_parser("static", help="static defense classifier over decrypted IPAs")
    p_static.add_argument("--limit", type=int, help="max apps this run")
    p_static.set_defaults(func=cmd_static)

    p_an = sub.add_parser("analyze", help="deep MobSF-style analysis of decrypted IPAs")
    p_an.add_argument("--app-id", help="analyze one app by id (else all acquired apps)")
    p_an.add_argument("--limit", type=int, help="max apps this run (batch mode)")
    p_an.set_defaults(func=cmd_analyze)

    p_dyn = sub.add_parser("dynamic", help="run the bypass ladder on pinned apps")
    p_dyn.add_argument("--limit", type=int, help="max apps this run")
    p_dyn.set_defaults(func=cmd_dynamic)

    p_pin = sub.add_parser("detect-pinning",
                           help="differential SSL-pinning probe (clean vs SSL Kill Switch) on one app")
    p_pin.add_argument("--app", required=True, help="app_id to probe")
    p_pin.add_argument("--no-alias", action="store_true",
                       help="inject dylibs under their real names (no evasion rename)")
    p_pin.add_argument("--sign-env", choices=["dev", "dist"], default="dev",
                       help="signing environment: dev (devicectl launch) or dist (ad-hoc, DVT)")
    p_pin.add_argument("--swap-certs", action="store_true",
                       help="also overwrite bundled certificate files with the MITM CA (MASTG-TECH-0064)")
    p_pin.set_defaults(func=cmd_detect_pinning)

    p_iapb = sub.add_parser("iap-bypass",
                            help="IAP/subscription bypass detection via Llama on captured traffic")
    p_iapb.add_argument("--app", required=True, help="app_id to probe")
    p_iapb.add_argument("--sign-env", choices=["dev", "dist"], default="dev")
    p_iapb.add_argument("--swap-certs", action="store_true", help="also swap bundled certs")
    p_iapb.set_defaults(func=cmd_iap_bypass)

    p_sl = sub.add_parser("detect-sideload",
                          help="sideload/anti-resign probe (plain re-sign vs SideloadFix) on one app")
    p_sl.add_argument("--app", required=True, help="app_id to probe")
    p_sl.add_argument("--sign-env", choices=["dev", "dist"], default="dev",
                      help="signing environment: dev (devicectl launch) or dist (ad-hoc, DVT)")
    p_sl.add_argument("--secs", type=int, default=5, help="seconds to wait per launch (default 5)")
    p_sl.set_defaults(func=cmd_detect_sideload)

    p_st = sub.add_parser("inspect-storage",
                          help="dynamic insecure-data-storage scan (pull app container + scan) on one app")
    p_st.add_argument("--app", required=True, help="app_id to probe")
    p_st.add_argument("--sign-env", choices=["dev", "dist"], default="dev",
                      help="signing env; dev gives full-container access (default dev)")
    p_st.add_argument("--secs", type=int, default=6, help="seconds to exercise the app (default 6)")
    p_st.set_defaults(func=cmd_inspect_storage)

    sub.add_parser("backfill-bundles",
                   help="populate missing app bundle ids from raw_json / analysis / IPA"
                   ).set_defaults(func=cmd_backfill_bundles)

    p_sbom = sub.add_parser("sbom", help="write a CycloneDX SBOM for one app (MASTG-TECH-0132)")
    p_sbom.add_argument("--app", required=True, help="app_id")
    p_sbom.add_argument("--out", help="output path (default sbom_<app>.json)")
    p_sbom.set_defaults(func=cmd_sbom)

    p_ds = sub.add_parser("dep-stats", help="corpus dependency-vulnerability prevalence")
    p_ds.set_defaults(func=cmd_dep_stats)

    p_ag = sub.add_parser("ats-gap",
                          help="ATS declared-vs-needed gap via nscurl (MASTG-TECH-0149)")
    p_ag.add_argument("--app", help="one app_id (omit to batch over analyzed apps)")
    p_ag.add_argument("--limit", type=int, help="max apps in batch mode")
    p_ag.set_defaults(func=cmd_ats_gap)

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
