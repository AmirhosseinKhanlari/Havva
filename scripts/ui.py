"""Interactive UI-automation REPL for live manual testing on the device.

Usage:
    python3 scripts/ui.py <bundle_id>          # app must already be installed

Commands (type at the 'ui>' prompt):
    tree            list buttons / text / fields with their labels + enabled/visible
    src             save the full page source to work/screen_dump.xml
    ctx             list Appium contexts (NATIVE_APP / WEBVIEW_*)
    tap <text>      tap the first element whose label CONTAINS <text>
    tapx <text>     tap the EXACT, enabled button labelled <text> (e.g. tapx Continue)
    xy <x> <y>      tap raw screen coordinates
    type <text>     send keys to the first text field on screen
    alert           accept a native iOS alert (best-effort)
    launch          relaunch the app
    help            show this
    q / quit        exit (ends the Appium session)

You can also tap on the device BY HAND while this is running, then run 'tree' to
inspect the new screen. Requires Appium running on :4723 and WDA set up.
"""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline import device          # noqa: E402
from pipeline.config import CONFIG   # noqa: E402


def show_tree(drv):
    try:
        src = drv.page_source
    except Exception as e:  # noqa: BLE001
        print("err:", e)
        return
    pat = r'<XCUIElementType(?:Button|StaticText|TextField|SecureTextField|Link|Cell)[^>]*>'
    n = 0
    for m in re.findall(pat, src):
        typ = re.search(r'XCUIElementType(\w+)', m).group(1)
        lbl = re.search(r'label="([^"]*)"', m)
        nm = re.search(r'name="([^"]*)"', m)
        en = re.search(r'enabled="([^"]*)"', m)
        vis = re.search(r'visible="([^"]*)"', m)
        text = (lbl.group(1) if lbl else "") or (nm.group(1) if nm else "")
        if text.strip():
            n += 1
            print(f"  [{typ:12}] '{text[:64]}'  en={en.group(1) if en else '?'} "
                  f"vis={vis.group(1) if vis else '?'}")
    if not n:
        print("  (no labelled elements; screen may be a splash or an opaque sheet)")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python3 scripts/ui.py <bundle_id>")
        return 1
    bundle = sys.argv[1]
    d = device.AppiumDriver(credentials={})
    print(f"connecting to {bundle} (launching)...")
    drv = d._make_driver(bundle)
    time.sleep(3)
    print("connected. type 'help' for commands.")
    while True:
        try:
            line = input("ui> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        cmd, _, arg = line.partition(" ")
        cmd, arg = cmd.lower(), arg.strip()
        try:
            if cmd in ("q", "quit", "exit"):
                break
            elif cmd == "help":
                print(__doc__)
            elif cmd == "tree":
                show_tree(drv)
            elif cmd == "ctx":
                print(drv.contexts)
            elif cmd == "src":
                p = Path(CONFIG.paths.work_dir) / "screen_dump.xml"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(drv.page_source)
                print("saved", p)
            elif cmd == "tap":
                print("tapped" if d._tap_label(drv, (arg,)) else "not found")
            elif cmd == "tapx":
                print("tapped" if d._tap_exact_enabled(drv, (arg,)) else "not found")
            elif cmd == "xy":
                x, y = arg.split()
                drv.execute_script("mobile: tap", {"x": int(x), "y": int(y)})
                print("tapped", x, y)
            elif cmd == "swipe":
                sz = drv.get_window_size()
                w, h = sz["width"], sz["height"]
                x = w // 2
                if (arg or "up") == "down":
                    y1, y2 = int(h * 0.30), int(h * 0.75)   # scroll content up
                else:
                    y1, y2 = int(h * 0.75), int(h * 0.30)   # scroll content down
                drv.execute_script("mobile: dragFromToForDuration",
                                   {"fromX": x, "fromY": y1, "toX": x, "toY": y2,
                                    "duration": 0.4})
                print("swiped", arg or "up", f"(window {w}x{h})")
            elif cmd == "type":
                fs = (d._find(drv, "XCUIElementTypeTextField")
                      + d._find(drv, "XCUIElementTypeSecureTextField"))
                if fs:
                    fs[0].send_keys(arg)
                    print("typed")
                else:
                    print("no text field")
            elif cmd == "alert":
                d._accept_native_alert(drv)
                print("alert accept attempted")
            elif cmd == "launch":
                drv.execute_script("mobile: launchApp", {"bundleId": bundle})
                print("launched")
            else:
                print("unknown command; type 'help'")
        except Exception as e:  # noqa: BLE001
            print("err:", e)
    try:
        drv.quit()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
