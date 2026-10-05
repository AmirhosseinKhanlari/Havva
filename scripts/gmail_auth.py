"""One-time Gmail OAuth consent for Google Voice OTP retrieval (pipeline/otp.py).

Prereq: in Google Cloud Console create an OAuth client (type: Desktop app) for the
throwaway Google account, download its JSON, and save it as
results/gmail_credentials.json (or set GMAIL_CREDENTIALS). Google Voice on that
account must be set to forward SMS to its Gmail inbox.

Run once:  python3 scripts/gmail_auth.py
It opens a browser for consent and writes results/gmail_token.json.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.config import CONFIG  # noqa: E402
from pipeline.otp import GMAIL_SCOPE  # noqa: E402


def main() -> int:
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("Install deps first: pip install google-api-python-client "
              "google-auth google-auth-oauthlib")
        return 1
    creds_path = Path(os.environ.get(
        "GMAIL_CREDENTIALS", str(CONFIG.paths.results_dir / "gmail_credentials.json")))
    token_path = Path(os.environ.get(
        "GMAIL_TOKEN", str(CONFIG.paths.results_dir / "gmail_token.json")))
    if not creds_path.exists():
        print(f"Missing OAuth client JSON at: {creds_path}")
        print("Create an OAuth client (Desktop app) in Google Cloud Console, "
              "download it, and save it there.")
        return 1
    flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), [GMAIL_SCOPE])
    creds = flow.run_local_server(port=0)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(creds.to_json())
    print(f"Wrote {token_path}. OTP retrieval is ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
