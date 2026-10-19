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
import re
import zipfile
from datetime import date, datetime
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
    # Braintree pins its own gateway with certs compiled into the SDK: the APP's
    # backend is not pinned by it. Recorded as matched["pin_scope"]=sdk-gateway.
    "Braintree": ["BTAPIPinnedCertificates"],
}
PIN_PLUGIN_SCOPE = {"Braintree": "sdk-gateway"}
# Hand-rolled pinned material in the main binary; only counted when no general
# TLS library (which carries these property names itself) explains them.
PIN_GENERIC_MATERIAL = ["pinnedCertificates", "pinnedPublicKeys",
                        "certificatePinning", "publicKeyPinning"]

# Backwards-compatible alias (older callers/tests imported this name).
PIN_LIBRARIES = {**TLS_LIBRARIES, **PIN_PLUGINS, "generic-pinned-material": PIN_GENERIC_MATERIAL}

CERT_FILE_EXTS = (".cer", ".der", ".crt", ".pem", ".p12", ".pfx", ".cert", ".pub", ".key")

# Hand-rolled pinning on the Security framework. STRONG tokens pull the served
# chain / key out of the trust object to compare it against pinned material,
# which is what pinning IS. WEAK tokens are the ordinary trust-evaluation calls
# every TLS client (and every networking SDK) makes; they only corroborate. A
# custom BoringSSL verifier is weak for the same reason: a bundled BoringSSL
# (Flutter, gRPC/Firestore) installs one for its DEFAULT validation, and the
# bare word "boringssl" is in every such binary, so it is not a marker at all.
PIN_NATIVE_STRONG = [
    "SecTrustCopyPublicKey", "SecTrustCopyKey", "SecCertificateCopyData",
    "SecKeyCopyExternalRepresentation", "SecTrustCopyCertificateChain",
    "SecTrustGetCertificateAtIndex", "SecTrustSetAnchorCertificates",
    "SecTrustSetAnchorCertificatesOnly",
]
PIN_NATIVE_WEAK = [
    "SecTrustEvaluateWithError", "SecTrustEvaluate", "SecTrustEvaluateAsync",
    "SecTrustEvaluateAsyncWithError", "SecTrustEvaluateFastAsync",
    "SecTrustSetPolicies", "SecPolicyCreateSSL",
    "SSL_set_custom_verify", "SSL_CTX_set_custom_verify",
]
PIN_NATIVE = PIN_NATIVE_STRONG + PIN_NATIVE_WEAK      # compatibility alias
PIN_BORINGSSL = ["SSL_set_custom_verify", "SSL_CTX_set_custom_verify"]  # alias (weak)

# Challenge delegate that inspects the server trust. The selector half is
# matched as a substring (long, unambiguous, survives Swift mangling); the
# trust half must be a bounded token so `NSURLAuthenticationMethodServerTrust`
# does not also count as `serverTrust`.
PIN_DELEGATE_CHALLENGE = [
    "URLSession:didReceiveChallenge:completionHandler:",
    "URLSession:task:didReceiveChallenge:completionHandler:",
    "connection:willSendRequestForAuthenticationChallenge:",
    "didReceiveChallenge", "URLAuthenticationChallenge",
]
PIN_DELEGATE_TRUST = ["NSURLAuthenticationMethodServerTrust", "serverTrust"]
PIN_DELEGATE = PIN_DELEGATE_CHALLENGE + PIN_DELEGATE_TRUST

# Pinned material: a base64 SHA-256 (43 chars + '='), the SPKI-hash form that
# TrustKit, HPKP and OkHttp-style pins use. Corroboration only: keys and other
# digests look identical, so it never flags on its own.
# '/' is allowed before the hash: TrustKit / HPKP write pins as "sha256/<b64>".
_SPKI_RE = re.compile(r"(?<![A-Za-z0-9+=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")

# TrustKit reads its pins from Info.plist (TSKConfiguration) unless configured
# in code. Per domain: TSKEnforcePinning (default YES; NO = report-only) and
# TSKExpirationDate (YYYY-MM-DD; past = pinning disabled).
TSK_CONFIG_KEY = "TSKConfiguration"

TLS_STACK_MARKERS: dict[TlsStack, list[str]] = {
    TlsStack.FLUTTER: ["Flutter.framework", "libflutter", "io.flutter", "flutter_assets"],
    TlsStack.REACT_NATIVE: ["RCTBridge", "libhermes", "React.framework", "jsi::"],
    TlsStack.XAMARIN: ["libmonosgen", "Xamarin", "Mono.framework", "libxamarin"],
    TlsStack.CORDOVA: ["Cordova", "CDVViewController", "Capacitor"],
}

# Attestation / anti-fraud SDKs that call App Attest or DeviceCheck on the
# app's behalf. Adoption through an SDK is a different population from direct
# adoption (the SDK vendor's backend verifies, the app's backend trusts a token).
ATTEST_SDK_MARKERS: dict[str, list[str]] = {
    "FirebaseAppCheck": ["FIRAppCheck", "AppCheckCore", "FirebaseAppCheck"],
    "Approov": ["ApproovService", "approov.io"],
    "reCAPTCHAEnterprise": ["RecaptchaEnterprise", "RecaptchaClient"],
    "ArkoseLabs": ["ArkoseLabs", "ArkoseKit"],
    "HUMAN": ["HUMANSecurity", "PerimeterX", "PXManager"],
    "FingerprintPro": ["FingerprintPro", "FingerprintJS"],
    "DataDome": ["DataDomeSDK"],
    "Kasada": ["KasadaSDK", "KPSDK"],
}
# Which App Check provider the app wires: AppAttest / DeviceCheck / Debug. A
# debug provider in a shipping binary is a finding in itself.
APPCHECK_PROVIDER_MARKERS: dict[str, list[str]] = {
    "app-attest": ["FIRAppAttestProvider", "AppAttestProvider"],
    "device-check": ["FIRDeviceCheckProvider", "DeviceCheckProvider"],
    "debug": ["FIRAppCheckDebugProvider", "AppCheckDebugProvider"],
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


def _find_all(haystack: str, patterns: list[str], *, lowered: bool = False) -> list[str]:
    """Case-insensitive substring presence. Pass `lowered=True` when `haystack`
    is already lower-cased (classify() lowers its multi-hundred-MB corpora once
    instead of once per pattern list)."""
    low = haystack if lowered else haystack.lower()
    return [p for p in patterns if p.lower() in low]


def _find_bounded(haystack: str, patterns: list[str], *, lowered: bool = False) -> list[str]:
    """Like _find_all, but an occurrence must not be glued to a LETTER on either
    side, so `SecTrustEvaluate` is not credited for `SecTrustEvaluateWithError`
    and `serverTrust` not for `NSURLAuthenticationMethodServerTrust`. Digits,
    '_' and '$' remain legal neighbours: nm prints `_SecTrustEvaluate`, ObjC
    class symbols are `_OBJC_CLASS_$_X`, Swift mangling length-prefixes names."""
    low = haystack if lowered else haystack.lower()
    out: list[str] = []
    for p in patterns:
        rx = re.compile(r"(?<![a-z])" + re.escape(p.lower()) + r"(?![a-z])")
        if rx.search(low):
            out.append(p)
    return out


def trustkit_config(info_plist: dict, today: "date | None" = None) -> dict | None:
    """Parse TrustKit's Info.plist configuration. None when TrustKit is configured
    in code (nothing to read). Otherwise the per-domain enforcement split."""
    cfg = (info_plist or {}).get(TSK_CONFIG_KEY)
    if not isinstance(cfg, dict):
        return None
    today = today or date.today()
    doms = cfg.get("TSKPinnedDomains") or {}
    out = {"domains": [], "enforced": [], "report_only": [], "expired": [],
           "swizzle": bool(cfg.get("TSKSwizzleNetworkDelegates", False))}
    for d, c in sorted(doms.items()):
        c = c if isinstance(c, dict) else {}
        out["domains"].append(d)
        enforce = c.get("TSKEnforcePinning", True)
        exp = c.get("TSKExpirationDate")
        expired = False
        if isinstance(exp, datetime):
            expired = exp.date() < today
        elif isinstance(exp, date):
            expired = exp < today
        elif isinstance(exp, str):
            try:
                expired = date.fromisoformat(exp[:10]) < today
            except ValueError:
                pass
        if expired:
            out["expired"].append(d)
        elif enforce is False or str(enforce).lower() in ("0", "false", "no"):
            out["report_only"].append(d)
        else:
            out["enforced"].append(d)
    return out


def classify(app: ExtractedApp) -> DefenseProfile:
    """Pure classification from an extracted corpus. Unit-tested."""
    hay = app.haystack
    hay_l = hay.lower()
    main_hay = app.main_haystack
    main_l = main_hay.lower() if main_hay is not hay else hay_l
    matched: dict[str, list[str]] = {}
    prof = DefenseProfile()

    # --- TLS stack ---
    prof.tls_stack = TlsStack.NATIVE
    fw_l = "\n".join(app.frameworks).lower() + "\n" + hay_l
    for stack, markers in TLS_STACK_MARKERS.items():
        hits = _find_all(fw_l, markers, lowered=True)
        if hits:
            prof.tls_stack = stack
            matched[f"tls:{stack.value}"] = hits
            break

    # --- TLS libraries PRESENT (informational, never pinning by itself) ---
    tls_libs: list[str] = []
    for lib, markers in TLS_LIBRARIES.items():
        hits = _find_all(hay_l, markers, lowered=True)
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
        # Presence says adopted; the plist says whether it ENFORCES. Report-only
        # or expired pins are the adopted-not-enforced case the paper wants.
        tk = trustkit_config(app.info_plist)
        if tk is None:
            hint = "unknown"                       # configured in code
        elif tk["enforced"] and not (tk["report_only"] or tk["expired"]):
            hint = "all"
        elif tk["enforced"]:
            hint = "partial"
        else:
            hint = "none"
            layer_detail = "l3_library_trustkit_report_only"
        matched["trustkit_enforce"] = [hint]
        if tk:
            matched["trustkit_config"] = [
                f"{d}: {'enforced' if d in tk['enforced'] else 'report-only' if d in tk['report_only'] else 'expired'}"
                for d in tk["domains"]][:8]
    if not pin_lib and "Alamofire" in tls_libs:
        cfg = _find_all(main_l, PIN_CONFIG_ALAMOFIRE, lowered=True)
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
        cfg = _find_all(main_l, PIN_CONFIG_AFNETWORKING, lowered=True)
        setter = _find_all(main_l, PIN_CONFIG_AFNETWORKING_SETTER, lowered=True)
        if cfg or (setter and app.cert_files):
            pin_lib = "AFNetworking"
            matched["pinlib:AFNetworking"] = cfg + setter + (
                [f"cert:{c}" for c in app.cert_files[:4]] if setter else [])
    if not pin_lib:
        for lib, markers in PIN_PLUGINS.items():
            hits = _find_all(hay_l, markers, lowered=True)
            if hits:
                pin_lib = lib
                matched[f"pinlib:{lib}"] = hits
                if lib in PIN_PLUGIN_SCOPE:
                    matched["pin_scope"] = [PIN_PLUGIN_SCOPE[lib]]
                break
    if not pin_lib and not ({"Alamofire", "AFNetworking"} & set(tls_libs)):
        hits = _find_all(main_l, PIN_GENERIC_MATERIAL, lowered=True)
        if hits:
            pin_lib = "generic-pinned-material"
            matched["pinlib:generic-pinned-material"] = hits
    if pin_lib:
        matched["pin_layer_detail"] = [layer_detail or f"l3_library_{pin_lib.lower()}"]

    # Pinned material in the MAIN binary / bundle: what a hand-rolled pin
    # compares against. Corroborates the weak layers below.
    spki = sorted(set(_SPKI_RE.findall(app.main_strings or app.strings or "")))
    material = bool(app.cert_files) or bool(spki)
    if spki:
        matched["spki_hashes"] = spki[:4]

    # L4: hand-rolled Security.framework pinning, judged on the MAIN binary: a
    # strong (chain / key extraction) token plus either a second native token
    # or pinned material. Strong tokens only in frameworks are a candidate, not
    # a flag (every TLS SDK imports the weak tokens; an SDK that pins its own
    # gateway is not the app pinning its backend).
    strong_main = _find_bounded(main_l, PIN_NATIVE_STRONG, lowered=True)
    weak_main = _find_bounded(main_l, PIN_NATIVE_WEAK, lowered=True)
    native_main = strong_main + weak_main
    native_pins = bool(strong_main) and (len(native_main) >= 2 or material)
    if not native_pins and not strong_main:
        strong_fw = _find_bounded(hay_l, PIN_NATIVE_STRONG, lowered=True)
        if strong_fw:
            matched["pin_candidate:native_framework"] = strong_fw

    # L2: a challenge delegate that inspects the server trust. The pair alone is
    # also how an app forwards to default handling or does client certificates,
    # so it only counts with pinned material or a strong native token.
    challenge = _find_all(main_l, PIN_DELEGATE_CHALLENGE, lowered=True)
    trust = _find_bounded(main_l, PIN_DELEGATE_TRUST, lowered=True)
    delegate_pair = bool(challenge) and bool(trust)
    delegate_pins = delegate_pair and (material or bool(strong_main))

    # L1: ATS NSPinnedDomains (iOS 14+ declarative, OS-enforced). Ranked above
    # the hand-rolled layers: it is exact and enforced by the OS, not inferred.
    ats = app.info_plist.get("NSAppTransportSecurity", {}) or {}
    pinned_domains = ats.get("NSPinnedDomains") or {}
    ats_pinned = isinstance(pinned_domains, dict) and bool(pinned_domains)

    if pin_lib:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L3_LIBRARY
        prof.pin_library = pin_lib
    elif ats_pinned:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L1_ATS
        matched["pin:ats"] = sorted(str(d) for d in pinned_domains)[:8]
    elif native_pins:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L4_SECTRUST
        matched["pin:native"] = native_main + (
            [f"cert:{c}" for c in app.cert_files[:2]] if len(native_main) < 2 and app.cert_files else [])
    elif delegate_pins:
        prof.pins_flag = True
        prof.pin_layer = PinLayer.L2_DELEGATE
        matched["pin:delegate"] = challenge + trust
    elif delegate_pair:
        matched["pin_candidate:delegate"] = challenge + trust

    # --- App Attest / DeviceCheck (graded adoption) ---
    # Level grades how strongly the app adopts App Attest, since mere API presence
    # is a soft signal (could be dead code): the entitlement means it is actually
    # provisioned for App Attest, and a 'production' environment means it ships it.
    aa = _find_all(hay_l, lowered=True, patterns=APPATTEST_MARKERS)
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
    dc = _find_all(hay_l, lowered=True, patterns=DEVICECHECK_MARKERS)
    if dc:
        prof.devicecheck_flag = True
        matched["devicecheck"] = dc
    sdks = sorted(n for n, toks in ATTEST_SDK_MARKERS.items()
                  if _find_all(hay_l, toks, lowered=True))
    if sdks:
        matched["attest_sdks"] = sdks
    providers = sorted(n for n, toks in APPCHECK_PROVIDER_MARKERS.items()
                       if _find_all(hay_l, toks, lowered=True))
    if providers:
        matched["appcheck_providers"] = providers

    # --- Anti-tamper / anti-debug / jailbreak detection ---
    at = _find_all(hay_l, lowered=True, patterns=ANTI_TAMPER_MARKERS)
    if at:
        prof.anti_tamper_hints = True
        matched["anti_tamper"] = at
    ad = _find_all(hay_l, lowered=True, patterns=ANTI_DEBUG_MARKERS)
    if ad:
        prof.anti_debug_hints = True
        matched["anti_debug"] = ad
    jb = _find_all(hay_l, lowered=True, patterns=JAILBREAK_MARKERS)
    if jb:
        prof.jailbreak_detection_hints = True
        matched["jailbreak_detection"] = jb

    # --- Network extension (can VPN around the proxy) ---
    if app.entitlements.get(ENT_NETEXT) or _find_all(hay_l, lowered=True, patterns=["NEVPNManager", "NETunnelProvider"]):
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
