"""Diagnostic: drive Google login up to the consent screen, then dump the Appium
contexts and the accessibility tree so we can see whether the final 'Continue' is
reachable by WDA or lives in the inaccessible ASWebAuthenticationSession process.

Usage: python3 scripts/diag_google.py [app_id]   (default 309735670 = Indeed)
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.config import CONFIG            # noqa: E402
from pipeline.db import Database              # noqa: E402
from pipeline import instrument, device, attestation  # noqa: E402

OUT = Path(CONFIG.paths.work_dir) / "consent_tree.xml"


def main() -> int:
    app_id = sys.argv[1] if len(sys.argv) > 1 else "309735670"
    db = Database(str(CONFIG.paths.db))
    with db.connect() as c:
        app = c.execute("SELECT bundle_id FROM apps WHERE app_id=?", (app_id,)).fetchone()
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
    bundle = app["bundle_id"]
    creds = attestation.creds_for(attestation.load_accounts(), app_id, bundle)
    email = (creds or {}).get("google_email", "")

    ok, signed, err = instrument.build(app_id, ac["ipa_path"], "attest_observe")
    if not ok:
        print("build failed:", err)
        return 1
    device.install_ipa(signed)

    d = device.AppiumDriver(credentials=creds)
    drv = d._make_driver(bundle)

    def dump(tag: str):
        try:
            ctx = drv.contexts
        except Exception as e:
            ctx = [f"err {e}"]
        try:
            src = drv.page_source
        except Exception as e:
            src = f"<err>{e}</err>"
        hits = re.findall(r'<[^>]*(?:Continue|Allow|Agree|Accept)[^>]*>', src)
        print(f"\n=== DUMP [{tag}] ===")
        print("CONTEXTS:", ctx)
        print("TREE LEN:", len(src))
        print(f"confirm-ish elements: {len(hits)}")
        for h in hits[:12]:
            print("  ", h[:220])
        p = OUT.with_name(f"consent_{tag}.xml")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
        print("saved ->", p)

    # Poll for the login screen (handle a welcome screen) and tap Google.
    tapped = False
    for _ in range(15):
        if d._tap_label(drv, ("Continue with Google", "Sign in with Google",
                              "Sign up with Google")):
            tapped = True
            break
        d._goto_login(drv)
        time.sleep(2)
    print("tapped Google:", tapped)
    time.sleep(2)
    d._accept_native_alert(drv)
    time.sleep(5)
    dump("after_google")          # this should be the OAuth sheet / account chooser
    if email and d._tap_label(drv, (email, email.split("@")[0])):
        time.sleep(5)
        dump("after_account")     # this should be the final consent 'Continue'
    print("(app left on screen; driver quitting)")
    drv.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
