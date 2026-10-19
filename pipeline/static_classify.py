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

# Library PRESENCE markers (informational: recorded as matched["tls_libs"]).
# Presence of Alamofire/AFNetworking is NOT pinning: both ship pinning support
# that most apps never configure. pins_flag needs CONFIGURATION evidence (below).
TLS_LIBRARIES: dict[str, list[str]] = {
    "TrustKit": ["TSKPinningValidator", "TrustKit", "kTSKPublicKeyHashes"],
    "AFNetworking": ["AFSecurityPolicy", "AFSSLPinningMode", "AFHTTPSessionManager",
                     "AFNetworking"],
    "Alamofire": ["Alamofire", "ServerTrustManager", "ServerTrustPolicy"],
}

# Pinning CONFIGURATION evidence, i.e. the app wires pinned material into the
# library. Matched against the MAIN binary only (a framework's own binary always
# contains its evaluator classes, used or not).
PIN_CONFIG_ALAMOFIRE = [
    "PinnedCertificatesTrustEvaluator", "PublicKeysTrustEvaluator",   # AF5
    "ServerTrustPolicy.pinCertificates", "ServerTrustPolicy.pinPublicKeys",  # AF4 source form
    "ServerTrustPolicyO15pinCertificates", "ServerTrustPolicyO13pinPublicKeys",  # AF4 mangled
]
PIN_CONFIG_AFNETWORKING = ["AFSSLPinningModeCertificate", "AFSSLPinningModePublicKey"]
# Weaker AFNetworking evidence: a security policy is installed AND the bundle
# ships certificate/key files to pin against.
PIN_CONFIG_AFNETWORKING_SETTER = ["setSecurityPolicy", "policyWithPinningMode",
                                  "setPinnedCertificates", "certificatesInBundle"]

# Pinning-specific plugins/SDKs: shipped only to pin, so presence counts.
PIN_PLUGINS: dict[str, list[str]] = {
    "Cordova": ["CustomURLConnectionDelegate", "isFingerprintTrusted",
                "SSLCertificateChecker"],
    "ReactNativeSSLPinning": ["react-native-ssl-pinning", "RNSslPinning"],
    "Approov": ["ApproovService", "_Approov", "approov"],
    "DataDome": ["DataDomeSDK"],
    # Braintree pins its own gateway with certs compiled into the SDK.
    "Braintree": ["BTAPIPinnedCertificates"],
}
# Hand-rolled pinned material in the main binary; only counted when no general
# TLS library (which carries these property names itself) explains them.
PIN_GENERIC_MATERIAL = ["pinnedCertificates", "pinnedPublicKeys",
                        "certificatePinning", "publicKeyPinning"]

# Backwards-compatible alias (older callers/tests imported this name).
PIN_LIBRARIES = {**TLS_LIBRARIES, **PIN_PLUGINS, "generic-pinned-material": PIN_GENERIC_MATERIAL}

CERT_FILE_EXTS = (".cer", ".der", ".crt", ".pem", ".p12", ".pfx", ".cert", ".pub", ".key")

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
    symbols: str = ""            # nm output (main binary + all frameworks/dylibs)
    strings: str = ""            # strings output (same scope)
    linked_libs: list[str] = field(default_factory=list)  # otool -L
    frameworks: list[str] = field(default_factory=list)   # Frameworks/* names
    info_plist: dict = field(default_factory=dict)
    entitlements: dict = field(default_factory=dict)
    arch: str = ""
    main_symbols: str = ""       # nm output of the MAIN executable only
    main_strings: str = ""       # strings output of the MAIN executable only
    cert_files: list[str] = field(default_factory=list)   # bundled .cer/.der/.pem/... (outside Frameworks/)

    @property
    def haystack(self) -> str:
        return "\n".join([self.symbols, self.strings,
                          "\n".join(self.linked_libs),
                          "\n".join(self.frameworks)])

    @property
    def main_haystack(self) -> str:
        """Evidence from the main executable only. Falls back to the full
        haystack when the corpus was built without the main/framework split
        (hand-built ExtractedApp in tests)."""
        if self.main_symbols or self.main_strings:
            return "\n".join([self.main_symbols, self.main_strings])
        return self.haystack


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

    # --- TLS libraries PRESENT (informational, never pinning by itself) ---
    main_hay = app.main_haystack
    tls_libs: list[str] = []
    for lib, markers in TLS_LIBRARIES.items():
        hits = _find_all(hay, markers)
        if hits:
            tls_libs.append(lib)
            matched[f"tlslib:{lib}"] = hits
    if tls_libs:
        matched["tls_libs"] = tls_libs

    # --- Pinning: library (L3) > native (L4) > delegate (L2) > ATS (L1) ---
    # L3 needs pinning CONFIGURATION, not library presence (audit #9).
    pin_lib = ""
    layer_detail = ""
    if "TrustKit" in tls_libs:
        # TrustKit is config-driven: it is only linked to pin, so presence counts,
        # but it is recorded separately so it can be split out in aggregates.
        pin_lib = "TrustKit"
        layer_detail = "l3_library_trustkit"
        matched["pinlib:TrustKit"] = matched["tlslib:TrustKit"]
    if not pin_lib and "Alamofire" in tls_libs:
        cfg = _find_all(main_hay, PIN_CONFIG_ALAMOFIRE)
        # Dynamically linked (Alamofire.framework shipped): an evaluator name in
        # the MAIN binary is a reference the app itself makes -> configured.
        # Statically linked: the library's evaluator classes land in the main
        # binary whether used or not (Swift metadata survives dead-stripping),
        # so additionally require pinned material in the bundle (the default
        # evaluators load Bundle.main .cer/.der/.crt/.pem files).
        dynamic = (any("alamofire" in f.lower() for f in app.frameworks)
                   or any("Alamofire.framework" in l for l in app.linked_libs))
        if cfg and (dynamic or app.cert_files):
            pin_lib = "Alamofire"
            matched["pinlib:Alamofire"] = cfg + (
                [] if dynamic else [f"cert:{c}" for c in app.cert_files[:4]])
        elif cfg:
            matched["pinlib_candidate:Alamofire"] = cfg + ["static-link, no bundled certs"]
    if not pin_lib and "AFNetworking" in tls_libs:
        cfg = _find_all(main_hay, PIN_CONFIG_AFNETWORKING)
        setter = _find_all(main_hay, PIN_CONFIG_AFNETWORKING_SETTER)
        if cfg or (setter and app.cert_files):
            pin_lib = "AFNetworking"
            matched["pinlib:AFNetworking"] = cfg + setter + (
                [f"cert:{c}" for c in app.cert_files[:4]] if setter else [])
    if not pin_lib:
        for lib, markers in PIN_PLUGINS.items():
            hits = _find_all(hay, markers)
            if hits:
                pin_lib = lib
                matched[f"pinlib:{lib}"] = hits
                break
    if not pin_lib and not ({"Alamofire", "AFNetworking"} & set(tls_libs)):
        hits = _find_all(main_hay, PIN_GENERIC_MATERIAL)
        if hits:
            pin_lib = "generic-pinned-material"
            matched["pinlib:generic-pinned-material"] = hits
    if pin_lib:
        matched["pin_layer_detail"] = [layer_detail or f"l3_library_{pin_lib.lower()}"]

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

    # --- App Attest / DeviceCheck (graded adoption) ---
    # Level grades how strongly the app adopts App Attest, since mere API presence
    # is a soft signal (could be dead code): the entitlement means it is actually
    # provisioned for App Attest, and a 'production' environment means it ships it.
    aa = _find_all(hay, APPATTEST_MARKERS)
    ent_val = app.entitlements.get(ENT_APPATTEST)
    if aa or ent_val:
        prof.appattest_flag = True
        if ent_val and str(ent_val).lower() == "production":
            prof.appattest_level = "production"
        elif ent_val:
            prof.appattest_level = "adopted"       # entitlement present (dev or unspecified env)
        else:
            prof.appattest_level = "referenced"    # API symbols only, no entitlement
        # Combined key kept for compatibility; the split keys let consumers tell
        # "provisioned" (entitlement) from "referenced" (symbols) apart.
        matched["appattest"] = aa + ([f"{ENT_APPATTEST}={ent_val}"] if ent_val else [])
        if aa:
            matched["appattest_symbols"] = aa
        if ent_val:
            matched["appattest_entitlement"] = [f"{ENT_APPATTEST}={ent_val}"]
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

# Generous per-binary cap on nm / strings output (characters). Large app
# binaries produce ~10-50 MB of strings; this keeps a pathological 500 MB
# framework from stalling the sweep while scanning every binary.
_PER_BINARY_CAP = 96 * 1024 * 1024

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
    has_main = bool(main_bin and main_bin.exists())
    fw_dir = app_dir / "Frameworks"
    frameworks = sorted(p.name for p in fw_dir.glob("*")) if fw_dir.exists() else []
    # ALL framework binaries + dylibs, in a deterministic order (Flutter etc.
    # hide here; an unsorted, capped list made coverage nondeterministic).
    fw_bins: list[Path] = []
    if fw_dir.exists():
        for fw in sorted(fw_dir.glob("*.framework")):
            b = fw / fw.stem
            if b.exists():
                fw_bins.append(b)
        fw_bins.extend(sorted(fw_dir.glob("*.dylib")))

    def _sweep(b: Path) -> tuple[str, str, list[str]]:
        sym = run_cmd(["nm", "-m", str(b)], timeout=120).stdout[:_PER_BINARY_CAP]
        st = run_cmd(["strings", "-a", str(b)], timeout=120).stdout[:_PER_BINARY_CAP]
        ll = run_cmd(["otool", "-L", str(b)], timeout=30).stdout.splitlines()
        return sym, st, ll

    main_symbols = main_strings = ""
    symbols, strings_out, libs = [], [], []
    if has_main:
        main_symbols, main_strings, ll = _sweep(main_bin)
        symbols.append(main_symbols); strings_out.append(main_strings); libs.extend(ll)
    for b in fw_bins:
        sym, st, ll = _sweep(b)
        symbols.append(sym); strings_out.append(st); libs.extend(ll)

    # Certificate / key files shipped outside Frameworks/ (pin-by-cert material).
    cert_files = sorted(
        str(p.relative_to(app_dir)) for p in app_dir.rglob("*")
        if p.is_file() and p.name.lower().endswith(CERT_FILE_EXTS)
        and "Frameworks" not in p.relative_to(app_dir).parts)[:60]

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
        main_symbols=main_symbols, main_strings=main_strings, cert_files=cert_files,
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
