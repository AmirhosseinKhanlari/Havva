"""Test automated login on ONE app, in isolation (no attestation machinery).

Re-signs + installs the app's decrypted IPA, drives the UI to attempt login using
the method/credentials in results/accounts.json, and prints the login status.
Leaves the app installed so you can inspect the result on the device.

Usage:
    python3 scripts/test_login.py <app_id> [duration_seconds]

Prereqs:
    - Appium server running on :4723 + WebDriverAgent on the XR (else it cold-
      launches and cannot log in).
    - For method "google": the test Google account signed into Safari on the XR.
    - results/accounts.json has an entry for <app_id>.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.config import CONFIG          # noqa: E402
from pipeline.db import Database            # noqa: E402
from pipeline import instrument, device, attestation  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 scripts/test_login.py <app_id> [duration_seconds]")
        return 1
    app_id = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 90

    db = Database(str(CONFIG.paths.db))
    with db.connect() as c:
        app = c.execute("SELECT app_id, bundle_id, name FROM apps WHERE app_id=?",
                        (app_id,)).fetchone()
        ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?",
                       (app_id,)).fetchone()
    if not app:
        print(f"no app {app_id}")
        return 1
    bundle_id = app["bundle_id"]
    decrypted = ac["ipa_path"] if ac else ""
    if not decrypted or not Path(decrypted).exists():
        print(f"no decrypted IPA for {app_id}")
        return 1

    creds = attestation.creds_for(attestation.load_accounts(), app_id, bundle_id or "")
    if not creds:
        print(f"no accounts.json entry for {app_id} / {bundle_id}")
        return 1
    print(f"app: {app['name']} ({bundle_id})  method={creds.get('method')}")

    ok, signed, err = instrument.build(app_id, decrypted, "attest_observe")
    if not ok:
        print(f"build failed: {err}")
        return 1
    installed, ierr = device.install_ipa(signed)
    if not installed:
        print(f"install failed: {ierr}")
        return 1

    driver = device.AppiumDriver(credentials=creds)
    res = driver.drive(bundle_id, duration, login=True)
    print("=" * 50)
    print(f"launched:     {res.launched}")
    print(f"login_status: {res.login_status}")
    if res.login_status == "none":
        print("  -> no login attempted. Check: Appium on :4723 running, "
              "a login button/form present, or method mismatch.")
    print(f"app left installed ({bundle_id}) for inspection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
