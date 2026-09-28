"""Tests for the success oracle. These pin down the measurement's ground truth."""

from pipeline.models import BypassStage, Outcome
from pipeline.oracle import OracleInput, decide


def test_not_pinned_when_baseline_has_traffic():
    r = decide(OracleInput(
        stage0_app_hosts={"api.example.com"},
        per_config_hosts=[(BypassStage.DYLIB, {"api.example.com"})],
        any_config_ran=True, reached_any_network=True,
    ))
    assert r.label is Outcome.NOT_PINNED
    assert r.pinned is False
    assert r.bypass_cost is BypassStage.NONE


def test_bypassed_when_dylib_reveals_hosts():
    r = decide(OracleInput(
        stage0_app_hosts=set(),
        per_config_hosts=[(BypassStage.DYLIB, {"api.example.com"})],
        any_config_ran=True, reached_any_network=True,
    ))
    assert r.label is Outcome.BYPASSED
    assert r.pinned is True
    assert r.bypass_cost is BypassStage.DYLIB


def test_bypass_cost_is_cheapest_working_stage():
    r = decide(OracleInput(
        stage0_app_hosts=set(),
        per_config_hosts=[
            (BypassStage.DYLIB, set()),          # dylib revealed nothing
            (BypassStage.RENAMED_DYLIB, set()),  # renamed revealed nothing
            (BypassStage.FRIDA, {"api.example.com"}),  # frida worked
        ],
        any_config_ran=True, reached_any_network=True,
    ))
    assert r.label is Outcome.BYPASSED
    assert r.bypass_cost is BypassStage.FRIDA


def test_partial_when_baseline_and_new_hosts():
    r = decide(OracleInput(
        stage0_app_hosts={"analytics.example.com"},
        per_config_hosts=[(BypassStage.DYLIB, {"analytics.example.com", "api.example.com"})],
        any_config_ran=True, reached_any_network=True,
    ))
    assert r.label is Outcome.PARTIAL
    assert r.pinned is True
    assert r.bypass_cost is BypassStage.DYLIB


def test_tamper_detected_when_all_crash():
    r = decide(OracleInput(all_configs_crashed=True, any_config_ran=False))
    assert r.label is Outcome.TAMPER_DETECTED


def test_pinned_unbypassed_when_ran_tried_network_but_nothing():
    r = decide(OracleInput(
        stage0_app_hosts=set(),
        per_config_hosts=[(BypassStage.DYLIB, set()), (BypassStage.FRIDA, set())],
        any_config_ran=True, reached_any_network=True,
    ))
    assert r.label is Outcome.PINNED_UNBYPASSED
    assert r.pinned is True


def test_inconclusive_when_login_required_not_completed():
    r = decide(OracleInput(
        stage0_app_hosts=set(),
        per_config_hosts=[(BypassStage.DYLIB, set())],
        any_config_ran=True, reached_any_network=True,
        login_required=True, login_completed=False,
    ))
    assert r.label is Outcome.INCONCLUSIVE


def test_inconclusive_when_app_never_touched_network():
    r = decide(OracleInput(
        stage0_app_hosts=set(),
        per_config_hosts=[(BypassStage.DYLIB, set())],
        any_config_ran=True, reached_any_network=False,
    ))
    assert r.label is Outcome.INCONCLUSIVE
