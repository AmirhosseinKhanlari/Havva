"""Tests for crash triage and escalation planning."""

from pipeline.escalate import classify_crash, plan_ladder
from pipeline.models import BypassStage, CrashClass


def test_kernel_codesign_detected():
    report = "Termination Reason: CODESIGNING 1 Invalid Code Signature"
    assert classify_crash(report, launched=False, produced_network=False) is CrashClass.KERNEL_CODESIGN


def test_app_self_abort_detected():
    report = "Exception Type: EXC_CRASH (SIGABRT)\nTerminating with uncaught integrity check"
    assert classify_crash(report, launched=True, produced_network=False) is CrashClass.APP_SELF_ABORT


def test_anti_debug_detected():
    report = "ptrace PT_DENY_ATTACH detected"
    assert classify_crash(report, launched=True, produced_network=False) is CrashClass.ANTI_DEBUG


def test_launch_timeout_when_no_report_and_not_launched():
    assert classify_crash("", launched=False, produced_network=False) is CrashClass.LAUNCH_TIMEOUT


def test_no_crash_when_launched_clean():
    assert classify_crash("", launched=True, produced_network=True) is CrashClass.NONE


def test_codesign_takes_precedence_over_abort():
    # A report mentioning both: the kernel codesigning kill is the real cause.
    report = "SIGABRT ... CODESIGNING invalid code signature"
    assert classify_crash(report, launched=True, produced_network=False) is CrashClass.KERNEL_CODESIGN


def test_ladder_when_control_crashes_goes_to_evasion_then_patch():
    assert plan_ladder(control_crashed=True) == [BypassStage.EVASION, BypassStage.BINARY_PATCH]


def test_ladder_when_control_clean_goes_to_renamed_then_frida():
    assert plan_ladder(control_crashed=False) == [BypassStage.RENAMED_DYLIB, BypassStage.FRIDA]


# ---- Modern .ips (JSON) reports ---------------------------------------------
# Every modern .ips carries '"namespace":"SIGNAL"' in its termination block, so
# the old free-text "namespace" marker classified EVERY crash as a codesigning
# kill. These pin the structured parser.

import json  # noqa: E402

from pipeline.escalate import parse_ips  # noqa: E402


def _ips(body: dict) -> str:
    header = {"app_name": body.get("procName", "App"), "bug_type": "309",
              "bundleID": body.get("bundleID", ""), "name": body.get("procName", "App"),
              "os_version": "iPhone OS 17.5 (21F79)", "timestamp": "2026-10-18 10:00:00.00 -0400"}
    return json.dumps(header) + "\n" + json.dumps(body)


_ABORT_BODY = {
    "procName": "BankApp", "bundleID": "com.example.bank", "bug_type": "309",
    "exception": {"codes": "0x0000000000000000, 0x0000000000000000", "rawCodes": [0, 0],
                  "type": "EXC_CRASH", "signal": "SIGABRT"},
    "termination": {"flags": 0, "code": 6, "namespace": "SIGNAL",
                    "indicator": "Abort trap: 6", "byProc": "BankApp", "byPid": 1234},
    "asi": {"libsystem_c.dylib": ["abort() called"]},
}

_CODESIGN_BODY = {
    "procName": "BankApp", "bundleID": "com.example.bank", "bug_type": "309",
    "exception": {"codes": "0x0000000000000000, 0x0000000000000000", "rawCodes": [0, 0],
                  "type": "EXC_CRASH", "signal": "SIGKILL"},
    "termination": {"code": 2, "flags": 518, "namespace": "CODESIGNING",
                    "indicator": "Invalid Page"},
}

_SEGV_BODY = {
    "procName": "BankApp", "bundleID": "com.example.bank", "bug_type": "309",
    "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV",
                  "subtype": "KERN_INVALID_ADDRESS at 0x0000000000000010"},
    "termination": {"flags": 0, "code": 11, "namespace": "SIGNAL",
                    "indicator": "Segmentation fault: 11", "byProc": "exc handler", "byPid": 1234},
}

_TRAP_BODY = {
    "procName": "BankApp", "bundleID": "com.example.bank", "bug_type": "309",
    "exception": {"type": "EXC_BREAKPOINT", "signal": "SIGTRAP",
                  "codes": "0x0000000000000001, 0x00000001a1b2c3d4"},
    "termination": {"flags": 0, "code": 5, "namespace": "SIGNAL",
                    "indicator": "Trace/BPT trap: 5", "byProc": "exc handler", "byPid": 1234},
}


def test_ips_sigabrt_abort_called_is_self_abort_not_codesign():
    assert classify_crash(_ips(_ABORT_BODY), launched=True, produced_network=False) \
        is CrashClass.APP_SELF_ABORT


def test_ips_codesigning_namespace_is_kernel_codesign():
    assert classify_crash(_ips(_CODESIGN_BODY), launched=False, produced_network=False) \
        is CrashClass.KERNEL_CODESIGN


def test_ips_plain_sigsegv_is_not_kernel_codesign():
    got = classify_crash(_ips(_SEGV_BODY), launched=True, produced_network=False)
    assert got is not CrashClass.KERNEL_CODESIGN
    assert got is CrashClass.UNKNOWN


def test_ips_sigtrap_is_anti_debug():
    assert classify_crash(_ips(_TRAP_BODY), launched=True, produced_network=False) \
        is CrashClass.ANTI_DEBUG


def test_ips_body_only_without_header_still_parses():
    assert classify_crash(json.dumps(_ABORT_BODY), launched=True, produced_network=False) \
        is CrashClass.APP_SELF_ABORT


def test_ips_concatenated_reports_use_first():
    # fetch_crash_report joins several hits with blank lines.
    text = _ips(_ABORT_BODY) + "\n\n" + _ips(_CODESIGN_BODY)
    assert classify_crash(text, launched=True, produced_network=False) is CrashClass.APP_SELF_ABORT


def test_parse_ips_fields():
    got = parse_ips(_ips(_ABORT_BODY))
    assert got == {"bundle_id": "com.example.bank", "proc_name": "BankApp",
                   "signal": "SIGABRT", "namespace": "SIGNAL", "indicator": "Abort trap: 6"}


def test_parse_ips_returns_none_for_legacy_text():
    assert parse_ips("Termination Reason: CODESIGNING 1 Invalid Code Signature") is None
    assert parse_ips("") is None


def test_legacy_markers_no_longer_include_namespace():
    from pipeline.escalate import _CODESIGN_MARKERS
    assert "namespace" not in _CODESIGN_MARKERS
    # A legacy-looking text that only mentions a namespace must not be codesign.
    assert classify_crash('namespace SIGNAL, Segmentation fault', launched=True,
                          produced_network=False) is CrashClass.UNKNOWN
