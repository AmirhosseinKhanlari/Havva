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

# Third-party SDK fingerprints: friendly name -> distinctive signatures matched
# against framework/dylib names AND the binary's strings (catches static linking).
# Signatures are chosen to be specific (class prefixes / unique tokens) to avoid
# false positives. Never use a bare English word ("Adjust", "Split", "Branch",
# "Heap", "Singular", "Lottie"...): those collide with UIKit selectors and
# ordinary strings in every binary.
_SDK_SIGNS = {
    # Purchases / paywalls / IAP
    "RevenueCat": ["RevenueCat", "RCPurchases", "RCStoreProduct", "com.revenuecat"],
    "Superwall": ["SuperwallKit", "com.superwall", "api.superwall.com"],
    "Adapty": ["AdaptyUI", "AdaptyPaywall", "com.adapty", "api.adapty.io"],
    "Qonversion": ["Qonversion", "QNPurchases"],
    "Glassfy": ["Glassfy"],
    # Networking / TLS
    "Alamofire": ["Alamofire"],
    "AFNetworking": ["AFNetworking", "AFSecurityPolicy", "AFHTTPSessionManager"],
    "TrustKit": ["TrustKit", "TSKPinningValidator", "kTSKPublicKeyHashes"],
    # Firebase / Google
    "Firebase": ["FirebaseCore", "FIRApp", "FIROptions"],
    "Firebase Analytics": ["FirebaseAnalytics", "FIRAnalytics"],
    "Firebase Crashlytics": ["Crashlytics", "FIRCLS", "FIRCrashlytics"],
    "Firebase Messaging": ["FirebaseMessaging", "FIRMessaging"],
    "Firebase Remote Config": ["FirebaseRemoteConfig", "FIRRemoteConfig"],
    "Google Mobile Ads": ["GADMobileAds", "GoogleMobileAds", "GADRequest"],
    "Google Sign-In": ["GoogleSignIn", "GIDSignIn"],
    "Google Utilities": ["GoogleUtilities"],
    # Attribution / analytics
    "AppsFlyer": ["AppsFlyerLib", "AppsFlyer", "AFSDKAttribution"],
    "Adjust": ["AdjustSdk", "ADJConfig", "ADJAdjust", "com.adjust"],
    "Branch": ["BranchSDK", "BNCConfig", "BNCPreferenceHelper", "io.branch"],
    "Singular": ["SingularSDK", "SingularConfig", "com.singular"],
    "Tenjin": ["TenjinSDK", "TenjinSDK.framework"],
    "Amplitude": ["AMPAmplitude", "AmplitudeSwift", "com.amplitude"],
    "Mixpanel": ["Mixpanel", "MPTweak"],
    "Segment": ["SEGAnalytics", "com.segment"],
    "mParticle": ["mParticle", "MParticleUser"],
    "Adobe Analytics": ["ADBMobile", "AEPCore", "ACPCore"],
    "PostHog": ["PostHog", "PHGPostHog"],
    "Heap": ["HeapAnalytics", "HeapSwiftCore", "io.heap"],
    "Pendo": ["PendoManager", "PendoSDK", "sdk.pendo.io"],
    # Crash / monitoring
    "Sentry": ["SentrySDK", "SentryClient", "io.sentry"],
    "Bugsnag": ["Bugsnag", "BugsnagConfiguration"],
    "Datadog": ["DatadogCore", "DDLogs", "DDTrace", "dd-sdk-ios"],
    "New Relic": ["NewRelic", "NRMAAgent"],
    "Instabug": ["Instabug", "IBGLog"],
    "Embrace": ["EmbraceIO", "EMBEmbrace", "io.embrace"],
    "Firebase Performance": ["FirebasePerformance", "FIRPerformance"],
    # Engagement / messaging / support
    "OneSignal": ["OneSignal", "OSNotification"],
    "Braze": ["BrazeKit", "Appboy", "ABKUser"],
    "CleverTap": ["CleverTap", "CleverTapSDK"],
    "Iterable": ["IterableAPI", "IterableSDK"],
    "Airship": ["UAirship", "AirshipCore"],
    "MoEngage": ["MoEngage", "MOInApp"],
    "Intercom": ["IntercomSDK", "ITMIntercom", "ICMIntercom", "com.intercom"],
    "Zendesk": ["ZendeskSDK", "ZDKChat", "SupportSDK"],
    "LaunchDarkly": ["LaunchDarkly", "LDClient"],
    "Optimizely": ["Optimizely", "OPTLYClient"],
    "Split": ["SplitSdk", "io.split"],   # never bare "Split"
    # Ads / mediation
    "AppLovin MAX": ["AppLovinSDK", "ALSdk", "MAAd"],
    "ironSource": ["IronSource", "ISConfigurations"],
    "Unity Ads": ["UnityAds", "UADSServiceProvider"],
    "Vungle": ["VungleSDK", "VungleAds"],
    "AdColony": ["AdColony", "AdColonyAppOptions"],
    # UI / utility / storage
    "SDWebImage": ["SDWebImage", "SDImageCache"],
    "Kingfisher": ["Kingfisher", "KFImageCache", "KingfisherManager"],
    "Lottie": ["LOTAnimationView", "com.airbnb.lottie", "LottieAnimationView"],
    "RxSwift": ["RxSwift", "RxCocoa"],
    "SnapKit": ["SnapKit", "ConstraintMakerExtendable"],
    "Realm": ["RealmSwift", "RLMObject", "RLMRealm"],
    "Stripe": ["StripeCore", "STPPaymentConfiguration", "StripePaymentSheet"],
    # Social SDKs
    "Facebook SDK": ["FBSDKCoreKit", "FBSDKApplicationDelegate"],
    "Kakao SDK": ["KakaoSDK", "KakaoSDKCommon"],
    "LINE SDK": ["LineSDK", "LineSDKLogin"],
    "Weibo SDK": ["WeiboSDK"],
}

_CRYPTO_SYMS = ("SecItemAdd", "SecItemCopyMatching", "SecTrustEvaluate",
                "SecTrustEvaluateWithError", "kSecAttrAccessibleWhenUnlocked",
                "kSecAttrAccessibleAfterFirstUnlock", "kSecAttrAccessibleAlways",
                "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
                "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
                "kSecAttrAccessibleAlwaysThisDeviceOnly",
                "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly", "CCCrypt",
                "CC_SHA256", "SecKeyCreateSignature", "DCAppAttestService",
                "DCDevice", "LAContext", "SecRandomCopyBytes")

# Insecure / interesting binary API rules (mirrors MobSF ipa_rules.py). Each entry:
# (category, severity, [tokens matched as WHOLE symbols in the strings+nm blob]).
# Tokens are matched by _sym_hits: a token must be delimited by non-identifier
# characters on both sides (so `_gets` never matches `_getschedparam`), and a
# token without a leading underscore also matches its C-symbol form (`CC_MD5`
# matches nm's `_CC_MD5`).
_API_RULES = [
    ("Insecure C functions", "high",
     [b"_strcpy", b"_strcat", b"_strncpy", b"_strncat", b"_sprintf", b"_vsprintf",
      b"_gets", b"_memcpy", b"_sscanf", b"_stpcpy"]),
    ("Weak hashing (MD5/SHA1)", "medium",
     [b"CC_MD5", b"CC_MD4", b"CC_SHA1", b"MD5_Init", b"MD5_Update", b"MD5_Final",
      b"SHA1_Init", b"SHA1_Update"]),
    ("Weak crypto (DES/3DES/RC4/RC2/ECB)", "high",
     [b"kCCAlgorithmDES", b"kCCAlgorithm3DES", b"kCCAlgorithmRC4",
      b"kCCAlgorithmRC2", b"kCCOptionECBMode"]),
    ("Insecure random", "medium", [b"_srand", b"_random", b"_rand"]),
    ("Malloc usage", "info", [b"_malloc"]),
    ("NSLog logging", "info", [b"_NSLog"]),
    ("ptrace anti-debug (non-public API)", "medium", [b"_ptrace"]),
    ("UIWebView (deprecated/insecure)", "medium", [b"UIWebView"]),
    # ---- Insecure local data storage (Trelis iOS static guide / MobSF) ----
    # These stores are unencrypted by default; flag so sensitive data landing
    # there can be reviewed. Locations: Library/Preferences/*.plist (NSUserDefaults),
    # app-container *.sqlite / Cache.db, Realm files, pasteboard, Cookies/.
    ("NSUserDefaults (unencrypted storage)", "info",
     [b"NSUserDefaults", b"standardUserDefaults"]),
    ("Local SQLite / Core Data (unencrypted DB)", "info",
     [b"sqlite3_open", b"sqlite3_open_v2", b"sqlite3_exec", b"sqlite3_prepare",
      b"sqlite3_prepare_v2", b"NSSQLiteStoreType",
      b"NSPersistentStoreCoordinator", b"NSManagedObjectContext"]),
    ("Realm database (verify encryptionKey)", "info", [b"RLMRealm", b"RealmSwift"]),
    ("Weak Keychain accessibility (kSecAttrAccessibleAlways)", "medium",
     [b"kSecAttrAccessibleAlways", b"kSecAttrAccessibleAlwaysThisDeviceOnly"]),
    ("Pasteboard use (system-wide data leakage)", "info",
     [b"generalPasteboard", b"UIPasteboard"]),
    ("Cookie storage (may persist session/sensitive data)", "info",
     [b"NSHTTPCookieStorage"]),
    ("Keyboard cache (disable for sensitive fields)", "info",
     [b"autocorrectionType", b"UITextAutocorrectionType"]),
]

_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")

# Tracker / analytics / attribution endpoints (Exodus-style, extended from the
# subscription paper). domain substring -> tracker name. Catches SDKs by the
# hosts they phone home to, independent of static linking.
_TRACKER_DOMAINS = {
    "revenuecat.com": "RevenueCat", "adapty.io": "Adapty", "superwall.com": "Superwall",
    "qonversion.io": "Qonversion", "purchasely.com": "Purchasely",
    "admob.com": "Google AdMob", "doubleclick.net": "Google DoubleClick",
    "googleadservices.com": "Google Ads", "googlesyndication.com": "Google AdSense",
    "googletagmanager.com": "Google Tag Manager", "google-analytics.com": "Google Analytics",
    "firebaseio.com": "Firebase", "firebase.google.com": "Firebase",
    "crashlytics.com": "Crashlytics", "app-measurement.com": "Firebase Analytics",
    "adjust.com": "Adjust", "adjust.io": "Adjust", "adjust.net.in": "Adjust",
    "appsflyer.com": "AppsFlyer", "branch.io": "Branch", "app.link": "Branch",
    "singular.net": "Singular", "tenjin.com": "Tenjin", "kochava.com": "Kochava",
    "amplitude.com": "Amplitude", "mixpanel.com": "Mixpanel", "segment.com": "Segment",
    "segment.io": "Segment", "posthog.com": "PostHog", "heap.io": "Heap",
    "heapanalytics.com": "Heap", "flurry.com": "Flurry", "localytics.com": "Localytics",
    "leanplum.com": "Leanplum", "braze.com": "Braze", "appboy.com": "Braze",
    "onesignal.com": "OneSignal", "clevertap.com": "CleverTap", "iterable.com": "Iterable",
    "pushwoosh.com": "Pushwoosh", "urbanairship.com": "Airship", "moengage.com": "MoEngage",
    "sentry.io": "Sentry", "bugsnag.com": "Bugsnag", "newrelic.com": "New Relic",
    "nr-data.net": "New Relic", "datadoghq.com": "Datadog", "instabug.com": "Instabug",
    "intercom.io": "Intercom", "zendesk.com": "Zendesk",
    "facebook.com": "Facebook", "facebook.net": "Facebook", "fbcdn.net": "Facebook",
    "chartboost.com": "Chartboost", "inmobi.com": "InMobi", "ironsrc.com": "ironSource",
    "mopub.com": "MoPub", "applovin.com": "AppLovin", "vungle.com": "Vungle",
    "adcolony.com": "AdColony", "tapjoy.com": "Tapjoy", "fyber.com": "Fyber",
    "unity3d.com": "Unity", "bytedance.com": "ByteDance/Pangle", "pangle.io": "Pangle",
    "scorecardresearch.com": "Comscore", "omtrdc.net": "Adobe Analytics",
    "demdex.net": "Adobe Audience", "amazon-adsystem.com": "Amazon Ads",
    "stripe.com": "Stripe", "launchdarkly.com": "LaunchDarkly", "optimizely.com": "Optimizely",
    "split.io": "Split",
}

# Secret/endpoint patterns: (label, regex, severity).
_SECRET_PATTERNS = [
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}"), "high"),
    # Google API keys / Stripe publishable keys are public by design (client
    # identifiers, restricted server-side): reported for inventory, never scored.
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "info"),
    ("Stripe live key", re.compile(rb"sk_live_[0-9A-Za-z]{16,}"), "high"),
    ("Stripe pub key", re.compile(rb"pk_live_[0-9A-Za-z]{16,}"), "info"),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "high"),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), "medium"),
    ("Bearer token", re.compile(rb"[Bb]earer[ \t]+[A-Za-z0-9\-._~+/]{20,}"), "medium"),
    ("Private key block", re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "high"),
    ("S3 bucket URL", re.compile(rb"[a-z0-9.\-]+\.s3[.-][a-z0-9.\-]*amazonaws\.com"), "low"),
    # Not adjacent to letters/digits/dots (so "v2.3.0.0" / "1.2.3.4.5" are not IPs).
    ("Hardcoded IP", re.compile(rb"(?<![A-Za-z0-9.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![A-Za-z0-9.])"), "low"),
]


def _plausible_ip(val: str) -> bool:
    """Reject version-like dotted quads: last two octets both 0 (2.3.0.0, 0.0.0.0)."""
    octs = val.split(".")
    return not (len(octs) == 4 and octs[2] == "0" and octs[3] == "0")


_SECRET_VALIDATORS = {"Hardcoded IP": _plausible_ip}
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
            "LSApplicationQueriesSchemes", "UIFileSharingEnabled",
            "LSSupportsOpeningDocumentsInPlace", "WKAppBoundDomains",
            "CFBundleDocumentTypes")
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
    # Granular per-domain exceptions (MASTG-TEST-0342): min TLS, insecure HTTP,
    # forward secrecy, cert transparency, subdomains.
    exc = a.get("NSExceptionDomains") or {}
    details = []
    for domain, cfg in exc.items():
        if not isinstance(cfg, dict):
            continue
        details.append({
            "domain": domain,
            "insecure_http": bool(cfg.get("NSExceptionAllowsInsecureHTTPLoads", False)),
            "min_tls": cfg.get("NSExceptionMinimumTLSVersion", "TLSv1.2"),
            "forward_secrecy": bool(cfg.get("NSExceptionRequiresForwardSecrecy", True)),
            "includes_subdomains": bool(cfg.get("NSIncludesSubdomains", False)),
            "requires_ct": bool(cfg.get("NSRequiresCertificateTransparency", False)),
        })
    return {
        "present": True,
        "allows_arbitrary_loads": bool(a.get("NSAllowsArbitraryLoads", False)),
        "allows_arbitrary_loads_media": bool(a.get("NSAllowsArbitraryLoadsForMedia", False)),
        "allows_arbitrary_loads_web": bool(a.get("NSAllowsArbitraryLoadsInWebContent", False)),
        "allows_local_networking": bool(a.get("NSAllowsLocalNetworking", False)),
        "exception_domains": list(exc.keys()),
        "exception_details": details,
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


_SYM_RX_CACHE: dict[tuple, re.Pattern] = {}


def _sym_hits(evidence: bytes, tokens) -> list[str]:
    """Tokens that occur in `evidence` (strings + nm output) as WHOLE symbols.

    A hit must be delimited by non-identifier characters on both sides:
    `(?<![A-Za-z0-9_])TOKEN(?![A-Za-z0-9_])`, so `_gets` does not match
    `_getschedparam` and `_rand` does not match `_random`. A token that does not
    start with an underscore also matches its C-symbol spelling with one leading
    underscore (`CC_MD5` <-> nm's `_CC_MD5`, `UIWebView` <-> `_OBJC_CLASS_$_UIWebView`).
    Returns the tokens as given (str), sorted."""
    toks = tuple(t.decode() if isinstance(t, bytes) else str(t) for t in tokens)
    toks = tuple(t.strip() for t in toks if t.strip())
    if not toks or not evidence:
        return []
    rx = _SYM_RX_CACHE.get(toks)
    if rx is None:
        alts = "|".join(re.escape(t) for t in sorted(toks, key=len, reverse=True))
        rx = re.compile(rb"(?<![A-Za-z0-9_])_?(?:" + alts.encode() + rb")(?![A-Za-z0-9_])")
        _SYM_RX_CACHE[toks] = rx
    want = set(toks)
    found: set[str] = set()
    for m in set(rx.findall(evidence)):
        s = m.decode("utf-8", "replace")
        if s in want:
            found.add(s)
        elif s.startswith("_") and s[1:] in want:
            found.add(s[1:])
        if len(found) == len(want):
            break
    return sorted(found)


def fingerprint_sdks(fw: dict, strings_blob: bytes = b"") -> list[str]:
    """Detect third-party SDKs from framework/dylib names AND the binary evidence
    (strings + symbols, so statically-linked SDKs with no separate .framework are
    caught too)."""
    names = " ".join(fw.get("embedded", []) + fw.get("linked", []))
    found = set()
    for name, sigs in _SDK_SIGNS.items():
        for sig in sigs:
            if sig in names or sig.encode() in strings_blob:
                found.add(name)
                break
    return sorted(found)


def crypto_hints(evidence: bytes) -> list[str]:
    """Security-framework / crypto symbols referenced by the binary (whole-symbol
    matches over strings + nm output)."""
    return _sym_hits(evidence, _CRYPTO_SYMS)


def scan_secrets(strings_blob: bytes) -> dict:
    findings = []
    for label, rx, sev in _SECRET_PATTERNS:
        seen = set()
        check = _SECRET_VALIDATORS.get(label)
        for m in rx.findall(strings_blob):
            val = m.decode("utf-8", "replace")
            if val in seen or (check and not check(val)):
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


def _nm(bin_path: Path) -> bytes:
    try:
        p = subprocess.run(["nm", str(bin_path)], capture_output=True, timeout=90)
        return (p.stdout or b"") + (p.stderr or b"")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return b""


def checksec(bin_path: Path | None) -> dict:
    """Mach-O binary hardening report (PIE, NX, stack canary, ARC, RPATH, code
    signature, encryption, symbols) using otool + nm. All best-effort."""
    out = {"pie": None, "nx": None, "stack_canary": None, "arc": None,
           "rpath": None, "code_signature": None, "encrypted": None,
           "symbols_stripped": None}
    if not bin_path or not bin_path.exists():
        return out
    try:
        flags = subprocess.run(["otool", "-hv", str(bin_path)],
                               capture_output=True, text=True, timeout=60).stdout
        out["pie"] = "PIE" in flags
        out["nx"] = "ALLOW_STACK_EXECUTION" not in flags
    except Exception:
        pass
    try:
        lc = subprocess.run(["otool", "-l", str(bin_path)],
                            capture_output=True, text=True, timeout=90).stdout
        out["rpath"] = "LC_RPATH" in lc
        out["code_signature"] = "LC_CODE_SIGNATURE" in lc
        if "LC_ENCRYPTION_INFO" in lc:
            # cryptid 1 => still encrypted; 0 => decrypted
            import re as _re
            m = _re.search(r"cryptid (\d+)", lc)
            out["encrypted"] = bool(m and m.group(1) != "0")
        else:
            out["encrypted"] = False
    except Exception:
        pass
    syms = _nm(bin_path)
    if syms:
        out["stack_canary"] = (b"___stack_chk_fail" in syms or b"__stack_chk_guard" in syms
                               or b"_stack_chk_fail" in syms)
        out["arc"] = (b"_objc_release" in syms or b"_objc_autoreleaseReturnValue" in syms
                      or b"_objc_storeStrong" in syms)
        # A binary with debug/local symbols (lowercase 't'/'d'/'b' entries) is not stripped.
        out["symbols_stripped"] = not any(f" {c} " in syms.decode("utf-8", "replace")
                                          for c in ("t", "d", "b"))
    return out


def binary_type(fw: dict, evidence: bytes) -> str:
    """Swift / Objective-C / unknown from linked libs + symbol evidence (the
    runtime entry points live in the symbol table, so `evidence` must include nm)."""
    linked = " ".join(fw.get("linked", []) + fw.get("embedded", []))
    if "libswiftCore" in linked or _sym_hits(
            evidence, ("_swift_release", "_swift_retain", "_swift_getObjectType",
                       "_swift_allocObject")):
        return "Swift"
    if _sym_hits(evidence, ("_objc_msgSend", "_objc_msgSendSuper2", "_objc_retain")):
        return "Objective-C"
    return "unknown"


def insecure_apis(evidence: bytes) -> list[dict]:
    """MobSF-style API rules over the strings + nm evidence (whole-symbol matches)."""
    findings = []
    for category, sev, tokens in _API_RULES:
        hits = _sym_hits(evidence, tokens)
        if hits:
            findings.append({"category": category, "severity": sev, "matches": hits})
    return findings


_FILE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".json", ".plist", ".html",
             ".css", ".js", ".webp", ".svg", ".mp3", ".mp4", ".ttf", ".otf", ".car")


def _looks_like_email(e: str) -> bool:
    if "%" in e or " " in e:                    # format-string / concatenation artifacts
        return False
    if e.lower().endswith(_FILE_EXT):           # e.g. logo@2x.png
        return False
    dom = e.rsplit("@", 1)[-1].lower()
    return "." in dom and dom.rsplit(".", 1)[-1].isalpha()


def emails_domains(strings_blob: bytes) -> dict:
    emails = sorted({m.decode("utf-8", "replace") for m in _EMAIL_RE.findall(strings_blob)
                     if _looks_like_email(m.decode("utf-8", "replace"))})[:60]
    doms = {m.decode("utf-8", "replace").lower() for m in _DOMAIN_RE.findall(strings_blob)}
    noise = ("apple.com", "mzstatic.com", "w3.org", "example.com", "schemas.android.com")
    domains = sorted(d for d in doms if not any(n in d for n in noise)
                     and not d.endswith(_FILE_EXT) and "." in d and len(d) < 60)[:120]
    return {"emails": emails, "domains": domains}


def detect_trackers(secrets: dict) -> list[dict]:
    """Match extracted URLs/domains against the known-tracker list. Returns
    [{name, domain}], one per detected tracker (deduped by name)."""
    hosts = set(secrets.get("domains") or [])
    for u in secrets.get("urls") or []:
        m = re.search(r"https?://([^/:?#]+)", u)
        if m:
            hosts.add(m.group(1).lower())
    found = {}
    for host in hosts:
        for dom, name in _TRACKER_DOMAINS.items():
            if host == dom or host.endswith("." + dom):
                found.setdefault(name, dom)
    return sorted(({"name": n, "domain": d} for n, d in found.items()),
                  key=lambda x: x["name"])


def security_score(report: dict) -> dict:
    """Roll findings into a 0-100 score + letter grade with itemized deductions.
    When no binary was examined (missing/unreadable executable, unparsable
    Info.plist) there is nothing to grade: score None / grade "n/a"."""
    if report.get("binary_examined") is False:
        return {"score": None, "grade": "n/a", "deductions": [],
                "reason": "no binary examined (executable missing or Info.plist unparsable)"}
    score = 100
    items = []

    def cut(points, reason):
        nonlocal score
        score -= points
        items.append({"points": -points, "reason": reason})

    cs = report.get("binary_protections") or {}
    if cs.get("pie") is False:
        cut(10, "No PIE (position-independent executable)")
    if cs.get("stack_canary") is False:
        cut(10, "No stack canary")
    if cs.get("arc") is False:
        cut(5, "No ARC")
    if cs.get("code_signature") is False:
        cut(10, "No code signature")
    if cs.get("rpath") is True:
        cut(5, "Uses runpath search path (RPATH)")

    for f in report.get("insecure_apis") or []:
        pts = {"high": 12, "medium": 6, "info": 0}.get(f["severity"], 3)
        if pts:
            cut(pts, f"{f['category']}")

    highs = sum(1 for s in (report.get("secrets") or {}).get("findings", [])
                if s.get("severity") == "high")
    if highs:
        cut(min(30, highs * 15), f"{highs} high-severity secret finding(s)")

    vuln_deps = sum(1 for d in (report.get("dependencies") or []) if d.get("cves"))
    if vuln_deps:
        cut(min(30, vuln_deps * 10), f"{vuln_deps} dependency(ies) with known CVEs")

    score = max(0, min(100, score))
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
             else "D" if score >= 40 else "F")
    return {"score": score, "grade": grade, "deductions": items}


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


_MACHO_MAGICS = (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",   # fat
                 b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",   # 64-bit
                 b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce")   # 32-bit


def _framework_macho_blob(zf: zipfile.ZipFile, app_dir: str,
                          cap: int = 80 * 1024 * 1024) -> bytes:
    """Concatenated raw bytes of embedded framework Mach-O executables, for scans
    (StoreKit / receipt / SDK tokens) that must see code living in frameworks, not
    just the main binary. ASCII tokens we look for live in the binary's __cstring
    sections, so raw-byte substring search needs no `strings` pass. Capped."""
    prefix = f"{app_dir}/Frameworks/"
    out = bytearray()
    for n in zf.namelist():
        if not n.startswith(prefix):
            continue
        rest = n[len(prefix):].split("/")
        if len(rest) != 2 or not rest[0].endswith(".framework"):
            continue
        if rest[1] != rest[0][:-len(".framework")]:   # the framework's main binary
            continue
        try:
            data = zf.read(n)
        except (OSError, KeyError):
            continue
        if data[:4] not in _MACHO_MAGICS:
            continue
        out += data
        if len(out) >= cap:
            break
    return bytes(out)


def dependencies(zf: zipfile.ZipFile, app_dir: str) -> list[dict]:
    """Embedded framework dependencies with versions (for CVE lookup). Reads each
    Payload/<App>.app/Frameworks/<X>.framework/Info.plist CFBundleShortVersionString."""
    prefix = f"{app_dir}/Frameworks/"
    fw_dirs = sorted({c.split(prefix, 1)[1].split("/")[0]
                      for c in zf.namelist() if prefix in c and c.split(prefix, 1)[1]})
    out = []
    for fw in fw_dirs:
        if not fw.endswith(".framework"):
            continue
        name = fw[:-len(".framework")]
        ver = ""
        member = f"{prefix}{fw}/Info.plist"
        if member in zf.namelist():
            try:
                info = plistlib.loads(zf.read(member))
                ver = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or ""
            except Exception:  # noqa: BLE001
                ver = ""
        out.append({"name": name, "version": str(ver)})
    return out


def debuggable_findings(ents: dict) -> list[dict]:
    """MASTG-TEST-0261: a shipping app signed with get-task-allow=true is
    debuggable in production."""
    if ents and ents.get("get-task-allow") is True:
        return [{"category": "Debuggable in production (get-task-allow=true)",
                 "severity": "high", "matches": ["get-task-allow"]}]
    return []


_CERT_EXTS = (".cer", ".der", ".crt", ".pem", ".p12", ".pfx", ".cert", ".pub", ".key")


def bundled_certs(zf: zipfile.ZipFile, app_dir: str) -> list[str]:
    """Certificate / public-key files shipped inside the app bundle. Apps that
    pin by comparing against a bundled cert/key are a strong pinning signal, and
    (MASTG-TEST-0064) such files can be swapped with the MITM CA to bypass."""
    out = []
    for n in zf.namelist():
        if not n.startswith(f"{app_dir}/"):
            continue
        low = n.lower()
        if low.endswith(_CERT_EXTS) and "/frameworks/" not in low:
            out.append(n.split(f"{app_dir}/", 1)[1])
    return sorted(out)[:60]


_EXT_TYPE_NAMES = {
    "com.apple.share-services": "Share", "com.apple.widget-extension": "Today/Widget",
    "com.apple.widgetkit-extension": "WidgetKit", "com.apple.usernotifications.content-extension": "Notification Content",
    "com.apple.usernotifications.service": "Notification Service", "com.apple.keyboard-service": "Custom Keyboard",
    "com.apple.intents-service": "Siri Intents", "com.apple.intents-ui-service": "Siri Intents UI",
    "com.apple.fileprovider-nonui": "File Provider", "com.apple.ui-services": "Action",
    "com.apple.authentication-services-credential-provider-ui": "Credential Provider",
    "com.apple.message-payload-provider": "iMessage", "com.apple.broadcast-services-upload": "Broadcast Upload",
    "com.apple.watchkit": "WatchKit", "com.apple.networkextension.packet-tunnel": "Network Extension (tunnel)",
    "com.apple.Safari.web-extension": "Safari Web Extension", "com.apple.dt.Xcode.extension.source-editor": "Xcode",
}


def app_extensions(zf: zipfile.ZipFile, app_dir: str) -> list[dict]:
    """Enumerate PlugIns/*.appex app extensions: type, bundle id, and whether the
    extension declares app-group sharing (MASTG-TECH-0170/0171). Extensions often
    skip the containing app's defenses, so they're an under-measured surface."""
    prefix = f"{app_dir}/PlugIns/"
    names = sorted({c.split(prefix, 1)[1].split("/")[0]
                    for c in zf.namelist() if prefix in c and c.split(prefix, 1)[1]})
    out = []
    for ax in names:
        if not ax.endswith(".appex"):
            continue
        info = {}
        try:
            info = plistlib.loads(zf.read(f"{prefix}{ax}/Info.plist"))
        except Exception:  # noqa: BLE001
            pass
        ext = info.get("NSExtension") or {}
        point = ext.get("NSExtensionPointIdentifier", "")
        out.append({
            "name": ax[:-len(".appex")],
            "bundle_id": info.get("CFBundleIdentifier", ""),
            "type_id": point,
            "type": _EXT_TYPE_NAMES.get(point, point or "unknown"),
        })
    return out


def privacy_manifest(zf: zipfile.ZipFile, app_dir: str) -> dict:
    """Parse PrivacyInfo.xcprivacy (app + bundled SDKs). iOS privacy manifests
    declare tracking, tracking domains, collected data types, and required-reason
    API usage."""
    members = [n for n in zf.namelist() if n.endswith("PrivacyInfo.xcprivacy")]
    app_member = f"{app_dir}/PrivacyInfo.xcprivacy"
    tracking = False
    tracking_domains: list[str] = []
    collected: list[str] = []
    accessed_apis: list[str] = []
    sdk_manifests = 0
    for m in members:
        try:
            pl = plistlib.loads(zf.read(m))
        except Exception:  # noqa: BLE001
            continue
        if m != app_member:
            sdk_manifests += 1
        if pl.get("NSPrivacyTracking"):
            tracking = True
        tracking_domains += list(pl.get("NSPrivacyTrackingDomains") or [])
        for d in pl.get("NSPrivacyCollectedDataTypes") or []:
            t = (d or {}).get("NSPrivacyCollectedDataType")
            if t:
                collected.append(t.replace("NSPrivacyCollectedDataType", ""))
        for d in pl.get("NSPrivacyAccessedAPITypes") or []:
            t = (d or {}).get("NSPrivacyAccessedAPIType")
            if t:
                accessed_apis.append(t.replace("NSPrivacyAccessedAPICategory", ""))
    return {
        "present": app_member in members,
        "sdk_manifests": sdk_manifests,
        "tracking": tracking,
        "tracking_domains": sorted(set(tracking_domains))[:40],
        "collected_data_types": sorted(set(collected))[:40],
        "accessed_api_types": sorted(set(accessed_apis))[:40],
    }


def config_findings(info: dict, ats_d: dict, priv: dict, secrets: dict) -> list[dict]:
    """Config-derived security findings: cleartext ATS/HTTP, file sharing, and a
    missing privacy manifest (MASTG-TEST-0321/0322/0342 + privacy)."""
    out: list[dict] = []
    if ats_d.get("allows_arbitrary_loads"):
        out.append({"category": "ATS disabled globally (NSAllowsArbitraryLoads) — cleartext allowed",
                    "severity": "high", "matches": ["NSAllowsArbitraryLoads"]})
    insecure_doms = [d["domain"] for d in (ats_d.get("exception_details") or [])
                     if d.get("insecure_http")]
    if insecure_doms:
        out.append({"category": "ATS per-domain insecure HTTP loads allowed",
                    "severity": "medium", "matches": insecure_doms[:8]})
    weak_tls = [f"{d['domain']} ({d['min_tls']})" for d in (ats_d.get("exception_details") or [])
                if str(d.get("min_tls")) in ("TLSv1.0", "TLSv1.1")]
    if weak_tls:
        out.append({"category": "ATS per-domain weak minimum TLS version",
                    "severity": "medium", "matches": weak_tls[:8]})
    http_urls = sorted({u for u in (secrets.get("urls") or []) if u.startswith("http://")})
    if http_urls:
        out.append({"category": "Cleartext HTTP endpoint(s) referenced",
                    "severity": "medium", "matches": http_urls[:8]})
    summ = info.get("summary", {}) if info else {}
    if summ.get("UIFileSharingEnabled") is True:
        out.append({"category": "Documents exposed via iTunes/Finder file sharing (UIFileSharingEnabled)",
                    "severity": "medium", "matches": ["UIFileSharingEnabled"]})
    if priv and not priv.get("present"):
        out.append({"category": "Missing app privacy manifest (PrivacyInfo.xcprivacy)",
                    "severity": "info", "matches": ["PrivacyInfo.xcprivacy"]})
    return out


def analyze_ipa(ipa_path: str, app_store_has_iap: bool | None = None) -> dict:
    """Full deep-analysis report for one decrypted IPA. Best-effort per section.
    `app_store_has_iap` is the App Store "offers IAP" flag, used to reconcile the
    static IAP detector (latent StoreKit symbols vs an actual IAP offering)."""
    result: dict = {"info_plist": {}, "entitlements": {}, "ats": {},
                    "frameworks": {}, "sdks": [], "secrets": {},
                    "file_tree": [], "crypto_hints": [],
                    "binary_protections": {}, "insecure_apis": [],
                    "binary_type": "unknown", "security_score": {}, "trackers": [],
                    "dependencies": [], "privacy_manifest": {}, "bundled_certs": [],
                    "app_extensions": [], "iap": {}, "binary_examined": False}
    tmp = Path(tempfile.mkdtemp(prefix="havva-analysis-"))
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
            result["entitlements"] = _safe(entitlements, bin_path)

            result["binary_examined"] = bool(bin_path and bin_path.exists())
            # Evidence = `strings` (cstrings, no symbol table on macOS) + `nm`
            # (symbol table). Symbol-shaped rules (_objc_msgSend, _CC_MD5,
            # _strcpy, kSecAttrAccessibleAlways, SecTrustEvaluate...) only fire
            # on the nm half, so every symbol scan must see the combined blob.
            blob = _strings_of(bin_path)
            nm_blob = _nm(bin_path) if bin_path else b""
            evidence = blob + b"\n" + nm_blob
            result["sdks"] = fingerprint_sdks(result["frameworks"], evidence)
            result["crypto_hints"] = crypto_hints(evidence)
            result["secrets"] = scan_secrets(blob)
            # emails + domains live alongside URLs in the secrets section
            result["secrets"].update(_safe(emails_domains, blob))
            result["binary_protections"] = _safe(checksec, bin_path)
            result["privacy_manifest"] = _safe(privacy_manifest, zf, app_dir)
            result["bundled_certs"] = _safe(bundled_certs, zf, app_dir)
            result["app_extensions"] = _safe(app_extensions, zf, app_dir)
            result["insecure_apis"] = _safe(insecure_apis, evidence)
            if result["bundled_certs"]:
                result["insecure_apis"].append({
                    "category": "Bundled certificate/key files (possible pinning-by-cert)",
                    "severity": "info", "matches": result["bundled_certs"][:8]})
            result["insecure_apis"] += debuggable_findings(result["entitlements"])
            result["insecure_apis"] += config_findings(
                result["info_plist"], result["ats"], result["privacy_manifest"], result["secrets"])
            result["binary_type"] = binary_type(result["frameworks"], evidence)
            # Static IAP security profile (StoreKit gen, validation path, endpoints).
            # Scan the main binary PLUS embedded framework binaries: modular apps
            # (e.g. Telegram) keep their IAP/StoreKit code in a framework, not the
            # main executable, so a main-binary-only scan misses it.
            try:
                from . import iap_static
                fw_blob = _framework_macho_blob(zf, app_dir)
                # Full bundle namelist (file_tree is capped and would miss a
                # .storekit config buried under thousands of assets).
                bundle_files = [n for n in zf.namelist() if n.startswith(f"{app_dir}/")]
                result["iap"] = iap_static.analyze(
                    blob + b"\n" + fw_blob, nm_blob, result["frameworks"],
                    bundle_files, app_store_has_iap=app_store_has_iap)
            except Exception as e:  # noqa: BLE001
                log.warning("iap_static failed: %s", e)
            result["trackers"] = detect_trackers(result["secrets"])
            # Dependency versions + known-CVE lookup (network, cached on disk).
            result["dependencies"] = _safe(dependencies, zf, app_dir)
            try:
                from . import cve
                result["dependencies"] = cve.enrich(result["dependencies"])
            except Exception as e:  # noqa: BLE001
                log.warning("CVE enrich failed: %s", e)
            result["security_score"] = security_score(result)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return result


def _safe(fn, *args):
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001
        log.warning("analysis extractor %s failed: %s", getattr(fn, "__name__", fn), e)
        return [] if fn in (file_tree, insecure_apis) else {}


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
    # Pass the App Store "offers IAP" flag so the static IAP detector can tell a
    # real IAP offering from latent StoreKit symbols (reviews/ads/dead code).
    has_iap = None
    try:
        with db.connect() as c:
            row = c.execute("SELECT has_iap FROM apps WHERE app_id=?", (app_id,)).fetchone()
        if row is not None and row["has_iap"] is not None:
            has_iap = bool(row["has_iap"])
    except Exception:  # noqa: BLE001
        has_iap = None
    report = analyze_ipa(ipa, app_store_has_iap=has_iap)
    db.save_analysis(app_id, report)
    # Backfill the bundle id from the Info.plist (the crawl often lacks it).
    bid = (report.get("info_plist", {}).get("summary", {}) or {}).get("CFBundleIdentifier")
    if bid:
        db.set_bundle_id(app_id, bid)
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
