"""Crash triage and escalation planning (Stage F).

Pure decision logic, no I/O, so it is testable. Two jobs:
1. Classify why a re-signed/injected app failed to run, from its crash report.
2. Given whether a control re-sign (no bypass dylib) also crashed, decide which
   rungs of the escalation ladder to try next.

The ladder (from the design spec):
  dylib -> (crash) -> control re-sign
    control also crashes  => re-signing itself is detected  => evasion -> binary patch
    control runs clean    => crash was SSKS-specific         => renamed dylib -> frida

Crash reports come in two shapes:
  * modern .ips (iOS 15+): line 1 is a JSON header, the rest is a JSON body with
    structured `termination` / `exception` / `asi` fields. We parse those
    fields directly; free-text marker matching on the whole blob is wrong there
    (e.g. EVERY .ips contains `"namespace":"SIGNAL"`).
  * legacy .crash / plain text: fall back to case-insensitive marker matching.
"""

from __future__ import annotations

import json

from .models import BypassStage, CrashClass


# Signals in a LEGACY (non-JSON) iOS crash report, matched case-insensitively.
# NB: "namespace" must never be here: modern .ips always carry a `namespace` key.
_CODESIGN_MARKERS = (
    "codesigning", "code signature", "cs_invalid", "invalid code signature",
    "amfi", "provisioning profile", "0xbada",
)
_SELF_ABORT_MARKERS = ("sigabrt", "abort()", "exc_crash", "__pthread_kill", "terminating with uncaught")
_ANTI_DEBUG_MARKERS = ("ptrace", "pt_deny_attach", "p_traced", "sysctl", "denied attach")


def _load_ips(report: str) -> dict | None:
    """Tolerant .ips parser. Modern reports are a one-line JSON header followed
    by a JSON body; some tools hand us just the body. Returns the BODY dict (the
    header is merged in underneath so bundleID/name from either is reachable)."""
    text = (report or "").strip()
    if not text.startswith("{"):
        return None
    header: dict = {}
    body = None
    try:
        body = json.loads(text)
    except ValueError:
        nl = text.find("\n")
        if nl < 0:
            return None
        try:
            header = json.loads(text[:nl])
        except ValueError:
            header = {}
        # raw_decode: tolerate trailing junk / a second concatenated report
        # (fetch_crash_report joins several hits with blank lines).
        try:
            body, _ = json.JSONDecoder().raw_decode(text[nl + 1:].strip())
        except ValueError:
            return None
    if not isinstance(body, dict):
        return None
    if isinstance(header, dict) and header:
        merged = dict(header)
        merged.update(body)
        return merged
    return body


def _asi_text(body: dict) -> str:
    """Flatten the Additional Scenario Info block ({lib: [lines...]}) to text."""
    asi = body.get("asi")
    if isinstance(asi, dict):
        parts = []
        for v in asi.values():
            if isinstance(v, (list, tuple)):
                parts.extend(str(x) for x in v)
            else:
                parts.append(str(v))
        return " ".join(parts)
    if isinstance(asi, (list, tuple)):
        return " ".join(str(x) for x in asi)
    return str(asi or "")


def parse_ips(report: str) -> dict | None:
    """Parse a modern .ips crash report into the few fields the pipeline cares
    about. Returns None if the text is not a JSON .ips (legacy / free text).

    {bundle_id, proc_name, signal, namespace, indicator}
    """
    body = _load_ips(report)
    if body is None:
        return None
    term = body.get("termination") or {}
    exc = body.get("exception") or {}
    if not isinstance(term, dict):
        term = {}
    if not isinstance(exc, dict):
        exc = {}
    bundle = body.get("bundleID") or body.get("bundle_id") or body.get("coalitionName") or ""
    proc = body.get("procName") or body.get("name") or body.get("app_name") or ""
    signal = exc.get("signal") or ""
    namespace = term.get("namespace") or ""
    indicator = term.get("indicator") or term.get("reason") or ""
    if not isinstance(indicator, str):
        indicator = str(indicator)
    return {
        "bundle_id": str(bundle),
        "proc_name": str(proc),
        "signal": str(signal),
        "namespace": str(namespace),
        "indicator": indicator,
    }


def _classify_ips(body: dict) -> CrashClass:
    """Structured classification from a parsed .ips body."""
    term = body.get("termination") or {}
    exc = body.get("exception") or {}
    if not isinstance(term, dict):
        term = {}
    if not isinstance(exc, dict):
        exc = {}
    namespace = str(term.get("namespace") or "").upper()
    indicator = str(term.get("indicator") or term.get("reason") or "").lower()
    signal = str(exc.get("signal") or "").upper()
    exc_type = str(exc.get("type") or "").upper()
    exc_subtype = str(exc.get("subtype") or "").lower()
    asi = _asi_text(body).lower()
    text_fields = " ".join((indicator, asi, exc_subtype))

    # Kernel-side codesigning kill: the re-sign, not the app's logic, is the problem.
    if namespace == "CODESIGNING" or any(
            m in indicator for m in ("codesign", "amfi", "invalid code signature", "code signature")):
        return CrashClass.KERNEL_CODESIGN

    # Anti-debug: a SIGTRAP / ptrace tripwire, or a termination that names a debugger.
    if (signal == "SIGTRAP" or exc_type == "EXC_BREAKPOINT"
            or any(m in text_fields for m in ("ptrace", "pt_deny_attach", "debugger", "denied attach"))):
        return CrashClass.ANTI_DEBUG

    # Self-abort: SIGABRT with abort()/uncaught exception in ASI or termination.
    if signal == "SIGABRT" and any(
            m in text_fields for m in ("abort() called", "uncaught", "__pthread_kill", "abort()")):
        return CrashClass.APP_SELF_ABORT

    return CrashClass.UNKNOWN


def _classify_legacy(text: str) -> CrashClass | None:
    """Text-marker fallback for non-JSON reports. None = nothing matched."""
    if any(m in text for m in _CODESIGN_MARKERS):
        return CrashClass.KERNEL_CODESIGN
    if any(m in text for m in _ANTI_DEBUG_MARKERS):
        return CrashClass.ANTI_DEBUG
    if any(m in text for m in _SELF_ABORT_MARKERS):
        return CrashClass.APP_SELF_ABORT
    return None


def classify_crash(report: str, launched: bool, produced_network: bool) -> CrashClass:
    """Classify a crash from its report text plus two observed facts.

    launched: the process came up at all.
    produced_network: it reached the network before dying (post-first-TLS canary
    vs launch-time integrity check).
    """
    if not report and not launched:
        return CrashClass.LAUNCH_TIMEOUT
    if not report:
        return CrashClass.NONE

    body = _load_ips(report)
    if body is not None:
        return _classify_ips(body)

    text = report.lower()
    legacy = _classify_legacy(text)
    if legacy is not None:
        return legacy
    if not launched:
        return CrashClass.LAUNCH_TIMEOUT
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
