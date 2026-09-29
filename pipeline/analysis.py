"""Deep static analysis of a DECRYPTED IPA (MobSF-style), offline on the Mac.

Extends static_classify (which stays authoritative for the pinning/attest funnel)
with a rich per-app report: Info.plist, entitlements, ATS, framework/SDK
inventory, a secrets/URL scan, an in-IPA file tree, and crypto/API usage hints.

Each extractor is isolated and best-effort: one failing extractor returns its
empty shape instead of sinking the whole report. Used by both the web UI
(deep_analyze job) and the CLI (`pipeline.cli analyze`).
"""
from __future__ import annotations

import logging
import plistlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .config import CONFIG
from .db import Database
from .models import Stage
from .util import run_cmd

log = logging.getLogger("analysis")

# Third-party SDKs worth fingerprinting (substring -> friendly name).
_SDK_SIGNS = {
    "Alamofire": "Alamofire", "AFNetworking": "AFNetworking", "TrustKit": "TrustKit",
    "FirebaseCore": "Firebase", "FirebaseAnalytics": "Firebase Analytics",
    "GoogleUtilities": "Google Utilities", "FBSDKCoreKit": "Facebook SDK",
    "Branch": "Branch", "Segment": "Segment", "Analytics": "Segment/Analytics",
    "Adjust": "Adjust", "AppsFlyer": "AppsFlyer", "Braze": "Braze",
    "Sentry": "Sentry", "Bugsnag": "Bugsnag", "Crashlytics": "Crashlytics",
    "Stripe": "Stripe", "Realm": "Realm", "SDWebImage": "SDWebImage",
    "Kingfisher": "Kingfisher", "Lottie": "Lottie", "RxSwift": "RxSwift",
    "KakaoSDK": "Kakao SDK", "LineSDK": "LINE SDK", "WeiboSDK": "Weibo SDK",
    "OneSignal": "OneSignal", "Amplitude": "Amplitude", "Mixpanel": "Mixpanel",
}

_CRYPTO_SYMS = ("SecItemAdd", "SecItemCopyMatching", "SecTrustEvaluate",
                "SecTrustEvaluateWithError", "kSecAttrAccessible", "CCCrypt",
                "CC_SHA256", "SecKeyCreateSignature", "DCAppAttestService",
                "DCDevice", "LAContext", "SecRandomCopyBytes")

# Secret/endpoint patterns: (label, regex, severity).
_SECRET_PATTERNS = [
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}"), "high"),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "high"),
    ("Stripe live key", re.compile(rb"sk_live_[0-9A-Za-z]{16,}"), "high"),
    ("Stripe pub key", re.compile(rb"pk_live_[0-9A-Za-z]{16,}"), "medium"),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "medium"),
    ("Bearer token", re.compile(rb"[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}"), "medium"),
    ("Private key block", re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "high"),
    ("S3 bucket URL", re.compile(rb"[a-z0-9.\-]+\.s3[.-][a-z0-9.\-]*amazonaws\.com"), "low"),
    ("Hardcoded IP", re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "low"),
]
_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{6,}")


def _find_app_dir(names: list[str]) -> str | None:
    """Return 'Payload/<Name>.app' derived from any member path. Works whether or
    not the zip contains explicit directory entries."""
    for c in names:
        parts = c.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return f"Payload/{parts[1]}"
    return None


def info_plist(zf: zipfile.ZipFile, app_dir: str) -> dict:
    try:
        pl = plistlib.loads(zf.read(f"{app_dir}/Info.plist"))
    except Exception:
        return {}
    keys = ("CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion",
            "CFBundleName", "CFBundleDisplayName", "MinimumOSVersion",
            "CFBundleExecutable", "UIBackgroundModes", "CFBundleURLTypes",
            "LSApplicationQueriesSchemes")
    summary = {k: pl.get(k) for k in keys if k in pl}
    perms = {k: v for k, v in pl.items() if k.endswith("UsageDescription")}
    return {"summary": summary, "permissions": perms, "raw_keys": sorted(pl.keys())}


def ats(zf: zipfile.ZipFile, app_dir: str) -> dict:
    try:
        pl = plistlib.loads(zf.read(f"{app_dir}/Info.plist"))
    except Exception:
        return {}
    a = pl.get("NSAppTransportSecurity")
    if not isinstance(a, dict):
        return {"present": False}
    return {
        "present": True,
        "allows_arbitrary_loads": bool(a.get("NSAllowsArbitraryLoads", False)),
        "allows_arbitrary_loads_media": bool(a.get("NSAllowsArbitraryLoadsForMedia", False)),
        "allows_arbitrary_loads_web": bool(a.get("NSAllowsArbitraryLoadsInWebContent", False)),
        "exception_domains": list((a.get("NSExceptionDomains") or {}).keys()),
        "pinned_domains": list((a.get("NSPinnedDomains") or {}).keys()),
    }


def file_tree(zf: zipfile.ZipFile, limit: int = 4000) -> list[dict]:
    out = []
    for i in zf.infolist():
        if i.is_dir():
            continue
        out.append({"path": i.filename, "size": i.file_size})
        if len(out) >= limit:
            break
    out.sort(key=lambda e: e["size"], reverse=True)
    return out


def frameworks(zf: zipfile.ZipFile, app_dir: str, bin_path: Path | None) -> dict:
    embedded = sorted({
        c.split(f"{app_dir}/Frameworks/", 1)[1].split("/")[0]
        for c in zf.namelist() if f"{app_dir}/Frameworks/" in c
        and c.split(f"{app_dir}/Frameworks/", 1)[1]
    })
    linked = []
    if bin_path and bin_path.exists():
        p = run_cmd(["otool", "-L", str(bin_path)], timeout=60)
        for line in p.stdout.splitlines()[1:]:
            line = line.strip()
            if line:
                linked.append(line.split(" (")[0])
    return {"embedded": embedded, "linked": linked}


def fingerprint_sdks(fw: dict) -> list[str]:
    blob = " ".join(fw.get("embedded", []) + fw.get("linked", []))
    found = {name for sign, name in _SDK_SIGNS.items() if sign in blob}
    return sorted(found)


def crypto_hints(strings_blob: bytes) -> list[str]:
    return sorted({s for s in _CRYPTO_SYMS if s.encode() in strings_blob})


def scan_secrets(strings_blob: bytes) -> dict:
    findings = []
    for label, rx, sev in _SECRET_PATTERNS:
        seen = set()
        for m in rx.findall(strings_blob):
            val = m.decode("utf-8", "replace")
            if val in seen:
                continue
            seen.add(val)
            findings.append({"type": label, "severity": sev,
                             "value": val[:120]})
            if len(seen) >= 20:
                break
    urls = sorted({u.decode("utf-8", "replace")[:200] for u in _URL_RE.findall(strings_blob)})
    # Drop apple/cdn noise from the URL list top.
    urls = [u for u in urls if not any(n in u for n in (
        "apple.com", "mzstatic", "w3.org", "schema"))][:200]
    return {"findings": findings, "urls": urls}


def entitlements(bin_path: Path | None) -> dict:
    if not bin_path or not bin_path.exists():
        return {}
    for args in (["codesign", "-d", "--entitlements", "-", "--xml", str(bin_path)],
                 ["codesign", "-d", "--entitlements", ":-", str(bin_path)]):
        p = run_cmd(args, timeout=60)
        raw = p.stdout.encode() if p.stdout else b""
        start = raw.find(b"<?xml")
        if start >= 0:
            try:
                return plistlib.loads(raw[start:])
            except Exception:
                continue
    return {}


def _strings_of(bin_path: Path | None) -> bytes:
    """Raw bytes from `strings` (binary safe: the executable is not valid UTF-8),
    with a fallback to reading the file bytes directly if `strings` is absent."""
    if not bin_path or not bin_path.exists():
        return b""
    try:
        p = subprocess.run(["strings", "-n", "6", str(bin_path)],
                           capture_output=True, timeout=120)
        if p.stdout:
            return p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        return bin_path.read_bytes()
    except OSError:
        return b""


def analyze_ipa(ipa_path: str) -> dict:
    """Full deep-analysis report for one decrypted IPA. Best-effort per section."""
    result: dict = {"info_plist": {}, "entitlements": {}, "ats": {},
                    "frameworks": {}, "sdks": [], "secrets": {},
                    "file_tree": [], "crypto_hints": []}
    tmp = Path(tempfile.mkdtemp(prefix="satella-analysis-"))
    try:
        with zipfile.ZipFile(ipa_path) as zf:
            app_dir = _find_app_dir(zf.namelist())
            if not app_dir:
                return result
            result["file_tree"] = _safe(file_tree, zf)
            result["info_plist"] = _safe(info_plist, zf, app_dir)
            result["ats"] = _safe(ats, zf, app_dir)

            exe = (result["info_plist"].get("summary", {}) or {}).get("CFBundleExecutable")
            bin_path = None
            if exe:
                member = f"{app_dir}/{exe}"
                if member in zf.namelist():
                    zf.extract(member, tmp)
                    bin_path = tmp / member

            result["frameworks"] = _safe(frameworks, zf, app_dir, bin_path)
            result["sdks"] = fingerprint_sdks(result["frameworks"])
            result["entitlements"] = _safe(entitlements, bin_path)

            blob = _strings_of(bin_path)
            result["crypto_hints"] = crypto_hints(blob)
            result["secrets"] = scan_secrets(blob)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return result


def _safe(fn, *args):
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001
        log.warning("analysis extractor %s failed: %s", getattr(fn, "__name__", fn), e)
        return {} if fn not in (file_tree,) else []


def analyze_one(db: Database, app_id: str, log_fn=None) -> dict:
    """Analyze the decrypted IPA recorded for app_id, persist, and return it."""
    def _log(m):
        (log_fn or log.info)(m)
    ac = db.get_acquisition(app_id)
    if not ac or not ac["ipa_path"]:
        raise RuntimeError("app not acquired (no decrypted IPA)")
    ipa = ac["ipa_path"]
    if not Path(ipa).exists():
        raise RuntimeError(f"decrypted IPA missing on disk: {ipa}")
    _log(f"analyzing {ipa}\n")
    report = analyze_ipa(ipa)
    db.save_analysis(app_id, report)
    n_sec = len(report["secrets"].get("findings", []))
    _log(f"done: {len(report['sdks'])} SDKs, {len(report['frameworks'].get('embedded', []))} "
         f"frameworks, {n_sec} secret findings, {len(report['file_tree'])} files\n")
    return report


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    """Batch: analyze all acquired-but-not-yet-analyzed apps."""
    with db.connect() as c:
        rows = c.execute(
            "SELECT a.app_id FROM apps a "
            "JOIN acquisition ac ON ac.app_id=a.app_id AND ac.decrypt_status=1 "
            "LEFT JOIN analysis an ON an.app_id=a.app_id "
            "WHERE an.app_id IS NULL").fetchall()
    if limit:
        rows = rows[:limit]
    stats = {"analyzed": 0, "failed": 0}
    for r in rows:
        try:
            analyze_one(db, r["app_id"])
            stats["analyzed"] += 1
        except Exception as e:  # noqa: BLE001
            log.warning("analyze %s failed: %s", r["app_id"], e)
            stats["failed"] += 1
    return stats
