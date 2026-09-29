"""Stage C: static defense classifier.

Builds a per-app defense profile from the decrypted IPA. Detection is split in
two: a pure `classify()` that reasons over already-extracted text (unit-tested),
and the I/O `extract_corpus()` that unzips the IPA and runs strings/nm/otool/
codesign. Pattern lists are ideas carried from paper 1's analyzer plus the new
axes this project needs (TLS stack, App Attest, anti-tamper).

This over-approximates: static flags are a superset of runtime pinning (the
dynamic stage is ground truth). That is intentional and reported as such.
"""

from __future__ import annotations

import plistlib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .config import CONFIG
from .db import Database
from .models import DefenseProfile, PinLayer, Stage, TlsStack
from .util import get_logger, run_cmd

log = get_logger("static", CONFIG.paths.log_dir)


# ---- Pattern lists (matched case-insensitively over symbols + strings) ------

PIN_LIBRARIES: dict[str, list[str]] = {
    "TrustKit": ["TSKPinningValidator", "TrustKit", "kTSKPublicKeyHashes"],
    "AFNetworking": ["AFSecurityPolicy", "AFSSLPinningMode"],
    "Alamofire": ["ServerTrustManager", "ServerTrustPolicy",
                  "PinnedCertificatesTrustEvaluator", "PublicKeysTrustEvaluator"],
    "Cordova": ["CustomURLConnectionDelegate", "isFingerprintTrusted",
                "SSLCertificateChecker"],
    "ReactNativeSSLPinning": ["react-native-ssl-pinning", "RNSslPinning"],
    "Approov": ["ApproovService", "_Approov", "approov"],
    "DataDome": ["DataDomeSDK"],
    "generic-pinned-material": ["pinnedCertificates", "pinnedPublicKeys",
                                "certificatePinning", "publicKeyPinning"],
}

PIN_NATIVE = [
    "SecTrustEvaluateWithError", "SecTrustEvaluate", "SecTrustCopyPublicKey",
    "SecTrustSetPolicies", "SecTrustSetAnchorCertificates", "SecPolicyCreateSSL",
    "SecCertificateCopyData", "SecKeyCopyExternalRepresentation",
]
PIN_DELEGATE = [
    "URLSession:didReceiveChallenge:completionHandler:",
    "connection:willSendRequestForAuthenticationChallenge:",
    "NSURLAuthenticationMethodServerTrust", "serverTrust",
]
PIN_BORINGSSL = ["SSL_set_custom_verify", "SSL_CTX_set_custom_verify", "boringssl"]

TLS_STACK_MARKERS: dict[TlsStack, list[str]] = {
    TlsStack.FLUTTER: ["Flutter.framework", "libflutter", "io.flutter", "flutter_assets"],
    TlsStack.REACT_NATIVE: ["RCTBridge", "libhermes", "React.framework", "jsi::"],
    TlsStack.XAMARIN: ["libmonosgen", "Xamarin", "Mono.framework", "libxamarin"],
    TlsStack.CORDOVA: ["Cordova", "CDVViewController", "Capacitor"],
}

APPATTEST_MARKERS = ["DCAppAttestService", "attestKeyWithClientDataHash",
                     "generateAssertionWithKeyId", "generateKeyWithCompletionHandler"]
DEVICECHECK_MARKERS = ["DCDevice", "generateTokenWithCompletionHandler"]

ANTI_TAMPER_MARKERS = [
    "IOSSecuritySuite", "FreeRASP", "amIJailbroken", "isJailbroken",
    "jailbroken", "/Applications/Cydia.app", "MobileSubstrate", "/bin/bash",
    "/etc/apt", "cydia://", "_dyld_get_image_name", "_dyld_image_count",
    "checkInjectedLibraries", "amIReverseEngineered",
]
ANTI_DEBUG_MARKERS = ["PT_DENY_ATTACH", "ptrace", "P_TRACED", "sysctl",
                      "task_get_exception_ports", "amIDebugged"]
JAILBREAK_MARKERS = ["/Applications/Cydia.app", "cydia://", "MobileSubstrate",
                     "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "jailbr"]

ENT_APPATTEST = "com.apple.developer.devicecheck.appattest-environment"
ENT_NETEXT = "com.apple.developer.networking.networkextension"


@dataclass
class ExtractedApp:
    """Everything the classifier reasons over, extracted from one IPA."""
    symbols: str = ""            # nm output
    strings: str = ""            # strings output
    linked_libs: list[str] = field(default_factory=list)  # otool -L
    frameworks: list[str] = field(default_factory=list)   # Frameworks/* names
    info_plist: dict = field(default_factory=dict)
    entitlements: dict = field(default_factory=dict)
    arch: str = ""

    @property
    def haystack(self) -> str:
        return "\n".join([self.symbols, self.strings,
                          "\n".join(self.linked_libs),
                          "\n".join(self.frameworks)])


def _find_all(haystack: str, patterns: list[str]) -> list[str]:
    low = haystack.lower()
    return [p for p in patterns if p.lower() in low]


def classify(app: ExtractedApp) -> DefenseProfile:
    """Pure classification from an extracted corpus. Unit-tested."""
    hay = app.haystack
    matched: dict[str, list[str]] = {}
    prof = DefenseProfile()

    # --- TLS stack ---
    prof.tls_stack = TlsStack.NATIVE
    fw_hay = "\n".join(app.frameworks) + "\n" + hay
    for stack, markers in TLS_STACK_MARKERS.items():
        hits = _find_all(fw_hay, markers)
        if hits:
            prof.tls_stack = stack
            matched[f"tls:{stack.value}"] = hits
            break

    # --- Pinning: library (L3) > native (L4) > delegate (L2) > ATS (L1) ---
    pin_lib = ""
    for lib, markers in PIN_LIBRARIES.items():
        hits = _find_all(hay, markers)
        if hits:
            pin_lib = lib
            matched[f"pinlib:{lib}"] = hits
            break

    native_hits = _find_all(hay, PIN_NATIVE)
    boring_hits = _find_all(hay, PIN_BORINGSSL)
    delegate_hits = _find_all(hay, PIN_DELEGATE)

    # ATS NSPinnedDomains (iOS 14+ declarative pinning) in Info.plist.
    ats = app.info_plist.get("NSAppTransportSecurity", {}) or {}
    ats_pinned = "NSPinnedDomains" in ats

    if pin_lib:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L3_LIBRARY
        prof.pin_library = pin_lib
    elif len(native_hits) >= 2 or boring_hits:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L4_SECTRUST
        matched["pin:native"] = native_hits + boring_hits
    elif ats_pinned:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L1_ATS
        matched["pin:ats"] = ["NSPinnedDomains"]
    elif len(delegate_hits) >= 2:
        # Delegate challenge handling alone is weak evidence; needs the trust
        # method plus the challenge selector to count.
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L2_DELEGATE
        matched["pin:delegate"] = delegate_hits

    # --- App Attest / DeviceCheck (presence) ---
    aa = _find_all(hay, APPATTEST_MARKERS)
    if aa or app.entitlements.get(ENT_APPATTEST):
        prof.appattest_flag = True
        matched["appattest"] = aa + ([ENT_APPATTEST] if app.entitlements.get(ENT_APPATTEST) else [])
    dc = _find_all(hay, DEVICECHECK_MARKERS)
    if dc:
        prof.devicecheck_flag = True
        matched["devicecheck"] = dc

    # --- Anti-tamper / anti-debug / jailbreak detection ---
    at = _find_all(hay, ANTI_TAMPER_MARKERS)
    if at:
        prof.anti_tamper_hints = True
        matched["anti_tamper"] = at
    ad = _find_all(hay, ANTI_DEBUG_MARKERS)
    if ad:
        prof.anti_debug_hints = True
        matched["anti_debug"] = ad
    jb = _find_all(hay, JAILBREAK_MARKERS)
    if jb:
        prof.jailbreak_detection_hints = True
        matched["jailbreak_detection"] = jb

    # --- Network extension (can VPN around the proxy) ---
    if app.entitlements.get(ENT_NETEXT) or _find_all(hay, ["NEVPNManager", "NETunnelProvider"]):
        prof.networkextension_flag = True
        matched["networkextension"] = ["entitlement/NE"]

    prof.matched_patterns = matched
    return prof


# ---- I/O extraction ---------------------------------------------------------

def _app_dir(unzipped: Path) -> Path | None:
    payload = unzipped / "Payload"
    if not payload.exists():
        return None
    apps = list(payload.glob("*.app"))
    return apps[0] if apps else None


def extract_corpus(ipa_path: str | Path) -> ExtractedApp | None:
    ipa_path = Path(ipa_path)
    work = CONFIG.paths.work_dir / f"static_{ipa_path.stem}"
    if work.exists():
        run_cmd(["rm", "-rf", str(work)])
    work.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(ipa_path) as z:
            z.extractall(work)
    except (zipfile.BadZipFile, OSError) as e:
        log.warning("bad ipa %s: %s", ipa_path, e)
        return None

    app_dir = _app_dir(work)
    if not app_dir:
        log.warning("no .app in %s", ipa_path)
        return None

    info = {}
    info_plist = app_dir / "Info.plist"
    if info_plist.exists():
        try:
            info = plistlib.loads(info_plist.read_bytes())
        except Exception:
            info = {}

    exe_name = info.get("CFBundleExecutable", "")
    main_bin = app_dir / exe_name if exe_name else None
    binaries = [main_bin] if main_bin and main_bin.exists() else []
    fw_dir = app_dir / "Frameworks"
    frameworks = [p.name for p in fw_dir.glob("*")] if fw_dir.exists() else []
    # include framework binaries in the symbol/string sweep (Flutter etc. hide here)
    if fw_dir.exists():
        for fw in fw_dir.glob("*.framework"):
            b = fw / fw.stem
            if b.exists():
                binaries.append(b)
        binaries.extend(fw_dir.glob("*.dylib"))

    symbols, strings_out, libs = [], [], []
    for b in binaries[:12]:  # cap work
        symbols.append(run_cmd(["nm", "-m", str(b)], timeout=60).stdout)
        strings_out.append(run_cmd(["strings", "-a", str(b)], timeout=60).stdout)
        libs.extend(run_cmd(["otool", "-L", str(b)], timeout=30).stdout.splitlines())

    entitlements = {}
    if main_bin and main_bin.exists():
        ent = run_cmd(["codesign", "-d", "--entitlements", ":-", str(main_bin)], timeout=30).stdout
        try:
            if ent.strip().startswith("<"):
                entitlements = plistlib.loads(ent.encode())
        except Exception:
            entitlements = {}

    arch = ""
    if main_bin and main_bin.exists():
        arch = run_cmd(["lipo", "-archs", str(main_bin)], timeout=15).stdout.strip()

    corpus = ExtractedApp(
        symbols="\n".join(symbols), strings="\n".join(strings_out),
        linked_libs=libs, frameworks=frameworks, info_plist=info,
        entitlements=entitlements, arch=arch,
    )
    run_cmd(["rm", "-rf", str(work)])  # clean staging
    return corpus


def analyze_ipa(ipa_path: str | Path) -> tuple[DefenseProfile | None, str]:
    corpus = extract_corpus(ipa_path)
    if corpus is None:
        return None, ""
    return classify(corpus), corpus.arch


def classify_one(db: Database, app_id: str):
    """Classify one acquired app's defenses (pinning, TLS stack, App Attest, anti-
    tamper). Returns the saved DefenseProfile. Raises if not acquired."""
    ac = db.get_acquisition(app_id)
    ipa_path = ac["ipa_path"] if ac else ""
    if not ipa_path or not Path(ipa_path).exists():
        raise RuntimeError("app not acquired (no decrypted IPA)")
    prof, _arch = analyze_ipa(ipa_path)
    if prof is None:
        raise RuntimeError("could not extract IPA for classification")
    db.save_static_profile(app_id, prof)
    db.set_stage(app_id, Stage.STATIC_DONE)
    return prof


def run(db: Database, limit: int | None = None) -> dict[str, int]:
    rows = db.apps_needing(Stage.STATIC_DONE)
    if limit:
        rows = rows[:limit]
    stats = {"analyzed": 0, "pinned": 0, "appattest": 0, "failed": 0}
    for row in rows:
        app_id = row["app_id"]
        with db.connect() as c:
            ac = c.execute("SELECT ipa_path FROM acquisition WHERE app_id=?", (app_id,)).fetchone()
        ipa_path = ac["ipa_path"] if ac else ""
        if not ipa_path or not Path(ipa_path).exists():
            stats["failed"] += 1
            continue
        prof, _arch = analyze_ipa(ipa_path)
        if prof is None:
            stats["failed"] += 1
            continue
        db.save_static_profile(app_id, prof)
        db.set_stage(app_id, Stage.STATIC_DONE)
        stats["analyzed"] += 1
        stats["pinned"] += int(prof.pins_flag)
        stats["appattest"] += int(prof.appattest_flag)
    log.info("static: %s", stats)
    return stats
