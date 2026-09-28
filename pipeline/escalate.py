"""Crash triage and escalation planning (Stage F).

Pure decision logic, no I/O, so it is testable. Two jobs:
1. Classify why a re-signed/injected app failed to run, from its crash report.
2. Given whether a control re-sign (no bypass dylib) also crashed, decide which
   rungs of the escalation ladder to try next.

The ladder (from the design spec):
  dylib -> (crash) -> control re-sign
    control also crashes  => re-signing itself is detected  => evasion -> binary patch
    control runs clean    => crash was SSKS-specific         => renamed dylib -> frida
"""

from __future__ import annotations

from .models import BypassStage, CrashClass


# Signals in an iOS crash report / device log, matched case-insensitively.
_CODESIGN_MARKERS = (
    "codesigning", "code signature", "cs_invalid", "invalid code signature",
    "amfi", "provisioning profile", "0xbada", "namespace",
)
_SELF_ABORT_MARKERS = ("sigabrt", "abort()", "exc_crash", "__pthread_kill", "terminating with uncaught")
_ANTI_DEBUG_MARKERS = ("ptrace", "pt_deny_attach", "p_traced", "sysctl", "denied attach")


def classify_crash(report: str, launched: bool, produced_network: bool) -> CrashClass:
    """Classify a crash from its report text plus two observed facts.

    launched: the process came up at all.
    produced_network: it reached the network before dying (post-first-TLS canary
    vs launch-time integrity check).
    """
    if not report and not launched:
        return CrashClass.LAUNCH_TIMEOUT
    text = (report or "").lower()

    # Kernel-side codesigning kill takes precedence: it means the re-sign, not the
    # app's own logic, is the problem.
    if any(m in text for m in _CODESIGN_MARKERS):
        return CrashClass.KERNEL_CODESIGN
    if any(m in text for m in _ANTI_DEBUG_MARKERS):
        return CrashClass.ANTI_DEBUG
    if any(m in text for m in _SELF_ABORT_MARKERS):
        return CrashClass.APP_SELF_ABORT
    if not launched:
        return CrashClass.LAUNCH_TIMEOUT
    if not report:
        return CrashClass.NONE
    return CrashClass.UNKNOWN


def plan_ladder(control_crashed: bool) -> list[BypassStage]:
    """Rungs to try after the plain dylib config crashed.

    control_crashed=True  => the app detects re-signing itself; plain Frida (also
      injected + re-signed) would crash the same way, so go straight to evasion,
      then binary patch.
    control_crashed=False => re-signing is fine; the crash was specific to the
      SSKS dylib, so a renamed/stripped dylib or a surgical Frida hook may work.
    """
    if control_crashed:
        return [BypassStage.EVASION, BypassStage.BINARY_PATCH]
    return [BypassStage.RENAMED_DYLIB, BypassStage.FRIDA]


# The full ordered ladder, cheapest first, used to compute bypass cost. The plain
# dylib is always tried first; the tail depends on the control result.
FULL_LADDER: list[BypassStage] = [
    BypassStage.DYLIB,
    BypassStage.RENAMED_DYLIB,
    BypassStage.FRIDA,
    BypassStage.EVASION,
    BypassStage.BINARY_PATCH,
]


def is_manual_tail(stage: BypassStage) -> bool:
    """Binary patching is the only rung that does not fully automate."""
    return stage == BypassStage.BINARY_PATCH
