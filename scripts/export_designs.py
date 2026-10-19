"""Export every web-UI page as a self-contained HTML file (CSS inlined) into
design_export/, for handing off to a redesign. Renders the REAL pages with real
DB data via the FastAPI test client.

Usage: python3 scripts/export_designs.py [app_id]   (default: a populated app)
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("WEB_AUTH_TOKEN", "t")

from fastapi.testclient import TestClient          # noqa: E402
from pipeline.web import app as appmod             # noqa: E402
from pipeline.config import CONFIG                 # noqa: E402

OUT = CONFIG.paths.root / "design_export"
OUT.mkdir(exist_ok=True)
CSS = (CONFIG.paths.root / "pipeline/web/static/console.css").read_text()


def _pick_app() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]
    import sqlite3
    c = sqlite3.connect(str(CONFIG.paths.db)); c.row_factory = sqlite3.Row
    # prefer an app that is acquired + classified + analyzed (richest tabs)
    row = c.execute(
        "SELECT a.app_id FROM apps a JOIN static_profile s ON s.app_id=a.app_id "
        "JOIN analysis an ON an.app_id=a.app_id JOIN acquisition ac ON ac.app_id=a.app_id "
        "LIMIT 1").fetchone()
    if row:
        return row["app_id"]
    row = c.execute("SELECT app_id FROM apps LIMIT 1").fetchone()
    return row["app_id"] if row else ""


def inline_css(html: str) -> str:
    return re.sub(r'<link[^>]*console\.css[^>]*>', f"<style>\n{CSS}\n</style>", html)


def wrap(fragment: str, title: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">\n'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{title}</title>\n<style>\n{CSS}\n</style></head>\n'
            f'<body style="padding:24px;max-width:1100px;margin:0 auto">\n'
            f'<div class="section">{fragment}</div></body></html>')


def main() -> int:
    app_id = _pick_app()
    c = TestClient(appmod.create_app())
    c.post("/login", data={"token": os.environ["WEB_AUTH_TOKEN"]})

    written = []
    for name, url in (("dashboard", "/"), ("corpus", "/corpus"), ("jobs", "/jobs")):
        r = c.get(url)
        (OUT / f"{name}.html").write_text(inline_css(r.text))
        written.append((f"{name}.html", r.status_code, url))

    r = c.get(f"/app/{app_id}")
    (OUT / "app_detail.html").write_text(inline_css(r.text))
    written.append(("app_detail.html", r.status_code, f"/app/{app_id}"))

    # Pick the best-populated app per tab so the designs show real components,
    # not empty states. Falls back to the default app.
    import sqlite3
    db = sqlite3.connect(str(CONFIG.paths.db)); db.row_factory = sqlite3.Row

    def pick(sql: str) -> str:
        try:
            r = db.execute(sql).fetchone()
            return r[0] if r else app_id
        except Exception:
            return app_id

    tab_app = {
        "overview": app_id,
        "acquire": pick("SELECT app_id FROM acquisition WHERE decrypt_status=1 LIMIT 1"),
        "static": pick("SELECT s.app_id FROM static_profile s JOIN analysis an "
                       "ON an.app_id=s.app_id WHERE s.pins_flag=1 LIMIT 1"),
        "dynamic": pick("SELECT app_id FROM pinning_probe LIMIT 1"),
        "iap": pick("SELECT app_id FROM iap_bypass LIMIT 1"),
        "attest": pick("SELECT app_id FROM static_profile "
                       "WHERE attest_confidence IS NOT NULL LIMIT 1"),
    }
    for tab, aid in tab_app.items():
        r = c.get(f"/app/{aid}/tab/{tab}")
        (OUT / f"tab_{tab}.html").write_text(wrap(r.text, f"Tab: {tab} (app {aid})"))
        written.append((f"tab_{tab}.html", r.status_code, f"/app/{aid}/tab/{tab}"))

    print(f"app used: {app_id}")
    for fn, code, url in written:
        print(f"  {code}  {fn:22} <- {url}")
    print(f"\nwrote {len(written)} files to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
