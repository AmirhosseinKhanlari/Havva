"""Dump the interactive elements of whatever screen an installed app shows.
Usage: python3 scripts/dump_screen.py <bundle_id> [wait_seconds]
The app must already be installed on the device. Prints buttons / texts / cells
with their labels + enabled/visible, and saves the full tree to work/screen_dump.xml.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline import device          # noqa: E402
from pipeline.config import CONFIG   # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 scripts/dump_screen.py <bundle_id> [wait_seconds]")
        return 1
    bundle = sys.argv[1]
    wait = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    d = device.AppiumDriver(credentials={})
    drv = d._make_driver(bundle)
    time.sleep(wait)
    src = drv.page_source
    print("=== interactive elements ===")
    for m in re.findall(r'<XCUIElementType(?:Button|StaticText|Link|Cell|TextField|SecureTextField)[^>]*>', src):
        typ = re.search(r'XCUIElementType(\w+)', m).group(1)
        lbl = re.search(r'label="([^"]*)"', m)
        nm = re.search(r'name="([^"]*)"', m)
        en = re.search(r'enabled="([^"]*)"', m)
        vis = re.search(r'visible="([^"]*)"', m)
        text = (lbl.group(1) if lbl else "") or (nm.group(1) if nm else "")
        if text.strip():
            print(f"[{typ:12}] '{text[:70]}'  enabled={en.group(1) if en else '?'} "
                  f"visible={vis.group(1) if vis else '?'}")
    out = Path(CONFIG.paths.work_dir) / "screen_dump.xml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(src)
    print("saved ->", out)
    drv.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
