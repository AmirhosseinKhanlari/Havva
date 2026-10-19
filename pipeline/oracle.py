"""Success oracle (Stage G).

Turns captured traffic into an outcome label. Pure logic, no I/O, so it is fully
testable and is the trustworthy core of the measurement. The rule: success is the
set of app-relevant hosts that were invisible at Stage 0 (own CA, no bypass) but
became visible after a bypass config.

Host sets passed in here are already filtered: Apple/excluded infrastructure and
the Mac's own traffic are removed upstream, so a non-empty set means SOMETHING
on the device talked to a non-Apple host.

Attribution caveat: hosts are collected per device IP, not per process. iOS
gives the proxy no per-app attribution, so background traffic from other
installed apps (push-driven refreshes, widgets, ad SDKs) can land in any
config's host set and, if it only shows up during a bypass run, be mistaken for
a host the bypass revealed. Keep the test device bare and compare against the
Stage-0 baseline taken under the same conditions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import BypassStage, Outcome


@dataclass
class OracleInput:
    # Non-excluded hosts that produced flows in the Stage-0 (no-bypass) run.
    stage0_app_hosts: set[str] = field(default_factory=set)
    # Ordered cheap -> expensive: (stage, hosts that produced flows in that config).
    per_config_hosts: list[tuple[BypassStage, set[str]]] = field(default_factory=list)
    # True only if every attempted bypass config crashed / refused to run.
    all_configs_crashed: bool = False
    # True if at least one config launched and stayed up long enough to observe.
    any_config_ran: bool = False
    # Did the app reach any network at all (even excluded hosts)? Distinguishes a
    # silent app (inconclusive) from a pinned one that tried and got nothing.
    reached_any_network: bool = False
    login_required: bool = False
    login_completed: bool = False


@dataclass
class OracleResult:
    label: Outcome
    pinned: bool
    bypass_cost: BypassStage


def decide(inp: OracleInput) -> OracleResult:
    # Nothing ran: the app actively resisted modification.
    if inp.all_configs_crashed and not inp.any_config_ran:
        return OracleResult(Outcome.TAMPER_DETECTED, pinned=False, bypass_cost=BypassStage.NONE)

    baseline = inp.stage0_app_hosts

    # Cheapest config that reveals a host Stage 0 did not show.
    cheapest: BypassStage | None = None
    for stage, hosts in inp.per_config_hosts:
        if hosts - baseline:
            cheapest = stage
            break

    if baseline and cheapest is None:
        # App talked without any bypass: it does not pin (those hosts).
        return OracleResult(Outcome.NOT_PINNED, pinned=False, bypass_cost=BypassStage.NONE)

    if not baseline and cheapest is not None:
        # Silent at baseline, revealed by bypass: pinned and bypassed.
        return OracleResult(Outcome.BYPASSED, pinned=True, bypass_cost=cheapest)

    if baseline and cheapest is not None:
        # Some traffic at baseline plus more revealed by bypass: mixed layers.
        return OracleResult(Outcome.PARTIAL, pinned=True, bypass_cost=cheapest)

    # Neither baseline traffic nor any newly revealed host.
    if not inp.any_config_ran:
        return OracleResult(Outcome.INCONCLUSIVE, pinned=False, bypass_cost=BypassStage.NONE)
    if inp.login_required and not inp.login_completed:
        return OracleResult(Outcome.INCONCLUSIVE, pinned=False, bypass_cost=BypassStage.NONE)
    if not inp.reached_any_network:
        # App ran but never tried to talk: we did not trigger it.
        return OracleResult(Outcome.INCONCLUSIVE, pinned=False, bypass_cost=BypassStage.NONE)
    # App ran, tried the network, still nothing visible after the full ladder.
    return OracleResult(Outcome.PINNED_UNBYPASSED, pinned=True, bypass_cost=BypassStage.NONE)
