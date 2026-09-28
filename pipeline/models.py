"""Typed enums and dataclasses shared across the pipeline.

These names are the vocabulary of the whole system: the DB columns, the oracle
output, and the analysis all use them, so they live in one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Stage(str, Enum):
    """Pipeline stages an app row progresses through."""
    CRAWLED = "crawled"
    ACQUIRED = "acquired"
    STATIC_DONE = "static_done"
    DYNAMIC_DONE = "dynamic_done"
    ATTESTATION_DONE = "attestation_done"


class WorkState(int, Enum):
    """Tri-state work queue (adopted from paper 1's `mitm` idiom).

    UNTESTED means retry on the next run; a definitive result or a permanent
    skip moves it off the queue.
    """
    UNTESTED = 0        # not yet processed, retry
    POSITIVE = 1        # definitive positive result
    DONE_NEGATIVE = -1  # tested-and-clean, or permanently skipped


class Outcome(str, Enum):
    """Per-app dynamic result (the success oracle's verdict)."""
    NOT_PINNED = "not_pinned"                # traffic visible at Stage 0
    BYPASSED = "bypassed"                    # invisible at Stage 0, visible after bypass
    PARTIAL = "partial"                      # some endpoints bypassed, some not
    PINNED_UNBYPASSED = "pinned_unbypassed"  # runs, still no traffic after full ladder
    TAMPER_DETECTED = "tamper_detected"      # crashes/exits/refuses after injection
    INCONCLUSIVE = "inconclusive"            # login-walled, region-locked, no traffic, VPN


class CrashClass(str, Enum):
    """Why a re-signed/injected app failed to run (crash-triage output)."""
    NONE = "none"                    # did not crash
    KERNEL_CODESIGN = "kernel_codesign"      # OS killed it: signature/entitlement/provisioning
    APP_SELF_ABORT = "app_self_abort"        # app killed itself: anti-tamper integrity check
    ANTI_DEBUG = "anti_debug"                # ptrace/sysctl anti-debug on injected runtime
    LAUNCH_TIMEOUT = "launch_timeout"        # never came up
    UNKNOWN = "unknown"


class BypassStage(str, Enum):
    """Rungs of the escalation ladder; the cheapest that works = bypass cost."""
    NONE = "none"
    DYLIB = "dylib"                  # SSKS as-is
    RENAMED_DYLIB = "renamed_dylib"  # SSKS renamed/stripped
    FRIDA = "frida"                  # Frida gadget + targeted hooks
    EVASION = "evasion"             # renamed SSKS + detector neutralization
    BINARY_PATCH = "binary_patch"    # manual sample tail


class PinLayer(str, Enum):
    """Where pinning lives (from the article's four-layer model)."""
    NONE = "none"
    L1_ATS = "l1_ats"                # NSAppTransportSecurity
    L2_DELEGATE = "l2_delegate"      # NSURLSession didReceiveChallenge
    L3_LIBRARY = "l3_library"        # TrustKit/AFNetworking/Alamofire/Cordova
    L4_SECTRUST = "l4_sectrust"      # SecTrustEvaluate*
    UNKNOWN = "unknown"


class TlsStack(str, Enum):
    NATIVE = "native"
    FLUTTER = "flutter"              # embedded BoringSSL (hard bucket)
    REACT_NATIVE = "react_native"
    XAMARIN = "xamarin"
    CORDOVA = "cordova"
    UNKNOWN = "unknown"


class BackendBehavior(str, Enum):
    """Attestation differential-test result."""
    FAIL_CLOSED = "fail_closed"      # refuses without valid attestation (real defense)
    FAIL_OPEN = "fail_open"          # serves anyway (adopted but not enforced)
    INCONCLUSIVE = "inconclusive"    # could not reach/observe gated action


@dataclass
class Flow:
    """One captured HTTP flow (header-aware, from HAR)."""
    url: str
    method: str
    status: int
    host: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""


@dataclass
class DefenseProfile:
    """Static classifier output for one app."""
    pins_flag: bool = False
    pin_layer: PinLayer = PinLayer.NONE
    pin_library: str = ""
    tls_stack: TlsStack = TlsStack.UNKNOWN
    anti_tamper_hints: bool = False
    anti_debug_hints: bool = False
    jailbreak_detection_hints: bool = False
    appattest_flag: bool = False
    devicecheck_flag: bool = False
    networkextension_flag: bool = False
    matched_patterns: dict[str, list[str]] = field(default_factory=dict)
