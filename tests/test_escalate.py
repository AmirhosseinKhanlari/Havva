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
