"""Stage I: aggregation. Compute the paper's headline metrics from the DB.

Pure reads. Produces a metrics dict, writes JSON + a Markdown summary to results/.
Denominators are explicit and exclusions are counted so numbers stay honest.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import CONFIG
from .db import Database
from .util import get_logger

log = get_logger("aggregate", CONFIG.paths.log_dir)


def _pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def compute(db: Database) -> dict:
    with db.connect() as c:
        def scalar(sql, args=()):
            r = c.execute(sql, args).fetchone()
            return r[0] if r else 0

        total_apps = scalar("SELECT COUNT(*) FROM apps")
        static_done = scalar("SELECT COUNT(*) FROM static_profile WHERE static_state=1")
        pinned = scalar("SELECT COUNT(*) FROM static_profile WHERE pins_flag=1")

        # Pin layer / library / TLS-stack distributions (static).
        pin_layers = {r["pin_layer"]: r["n"] for r in c.execute(
            "SELECT pin_layer, COUNT(*) n FROM static_profile WHERE pins_flag=1 GROUP BY pin_layer")}
        pin_libs = {r["pin_library"]: r["n"] for r in c.execute(
            "SELECT pin_library, COUNT(*) n FROM static_profile "
            "WHERE pins_flag=1 AND pin_library!='' GROUP BY pin_library")}
        tls_stacks = {r["tls_stack"]: r["n"] for r in c.execute(
            "SELECT tls_stack, COUNT(*) n FROM static_profile GROUP BY tls_stack")}

        # Prevalence by category (static).
        by_cat = {r["primary_category"]: {"apps": r["t"], "pinned": r["p"]} for r in c.execute(
            "SELECT a.primary_category, COUNT(*) t, "
            "  SUM(CASE WHEN s.pins_flag=1 THEN 1 ELSE 0 END) p "
            "FROM apps a JOIN static_profile s ON s.app_id=a.app_id "
            "WHERE s.static_state=1 GROUP BY a.primary_category")}

        # Dynamic outcomes.
        outcomes = {r["label"]: r["n"] for r in c.execute(
            "SELECT label, COUNT(*) n FROM outcome WHERE work_state!=0 GROUP BY label")}
        bypass_cost = {r["bypass_cost"]: r["n"] for r in c.execute(
            "SELECT bypass_cost, COUNT(*) n FROM outcome WHERE pinned=1 GROUP BY bypass_cost")}
        dyn_evaluated = sum(outcomes.values())
        bypassed = outcomes.get("bypassed", 0) + outcomes.get("partial", 0)
        dyn_pinned = scalar("SELECT COUNT(*) FROM outcome WHERE pinned=1")

        # Attestation adoption vs enforcement (the headline).
        appattest = scalar("SELECT COUNT(*) FROM static_profile WHERE appattest_flag=1")
        att_tested = scalar("SELECT COUNT(*) FROM attestation WHERE work_state!=0")
        fail_open = scalar("SELECT COUNT(*) FROM attestation WHERE backend_behavior='fail_open'")
        fail_closed = scalar("SELECT COUNT(*) FROM attestation WHERE backend_behavior='fail_closed'")
        # Graded enforcement verdicts (added by the probe battery; may be absent).
        verdicts: dict[str, int] = {}
        try:
            verdicts = {r["verdict"]: r["n"] for r in c.execute(
                "SELECT verdict, COUNT(*) n FROM attestation WHERE verdict IS NOT NULL "
                "GROUP BY verdict")}
        except Exception:
            verdicts = {}

    return {
        "corpus": {"total_apps": total_apps, "static_analyzed": static_done},
        "prevalence": {
            "pinned": pinned, "pinned_pct_of_analyzed": _pct(pinned, static_done),
            "by_pin_layer": pin_layers, "by_pin_library": pin_libs,
            "by_tls_stack": tls_stacks, "by_category": by_cat,
        },
        "bypass": {
            "dynamic_evaluated": dyn_evaluated, "outcomes": outcomes,
            "bypassed": bypassed,
            "bypass_rate_pct_of_pinned_evaluated": _pct(bypassed, dyn_pinned) if dyn_pinned else 0.0,
            "bypass_cost_distribution": bypass_cost,
        },
        "attestation": {
            "adopted": appattest, "adopted_pct_of_analyzed": _pct(appattest, static_done),
            "tested": att_tested, "fail_open": fail_open, "fail_closed": fail_closed,
            "enforced_pct_of_tested": _pct(fail_closed, att_tested),
            "not_enforced_pct_of_tested": _pct(fail_open, att_tested),
            "enforcement_verdicts": verdicts,
        },
    }


def _markdown(m: dict) -> str:
    p, b, a = m["prevalence"], m["bypass"], m["attestation"]
    lines = [
        "# Pinning and client-integrity measurement results", "",
        f"- Corpus: {m['corpus']['total_apps']} apps, "
        f"{m['corpus']['static_analyzed']} statically analyzed",
        f"- Pinning prevalence: {p['pinned']} ({p['pinned_pct_of_analyzed']}% of analyzed)",
        f"- Dynamic evaluated: {b['dynamic_evaluated']}; bypassed: {b['bypassed']} "
        f"({b['bypass_rate_pct_of_pinned_evaluated']}% of pinned evaluated)",
        f"- App Attest adopted: {a['adopted']} ({a['adopted_pct_of_analyzed']}% of analyzed)",
        f"- Attestation enforcement (of {a['tested']} tested): "
        f"{a['enforced_pct_of_tested']}% enforced, {a['not_enforced_pct_of_tested']}% theater",
        "", "## Outcome distribution",
    ]
    for k, v in sorted(b["outcomes"].items()):
        lines.append(f"- {k}: {v}")
    lines.append("\n## Bypass cost (cheapest working technique)")
    for k, v in sorted(b["bypass_cost_distribution"].items()):
        lines.append(f"- {k}: {v}")
    lines.append("\n## Pin layer")
    for k, v in sorted(p["by_pin_layer"].items()):
        lines.append(f"- {k}: {v}")
    lines.append("\n## TLS stack")
    for k, v in sorted(p["by_tls_stack"].items()):
        lines.append(f"- {k}: {v}")
    return "\n".join(lines)


def report(db: Database) -> dict:
    m = compute(db)
    CONFIG.paths.results_dir.mkdir(parents=True, exist_ok=True)
    (CONFIG.paths.results_dir / "metrics.json").write_text(json.dumps(m, indent=2))
    (CONFIG.paths.results_dir / "summary.md").write_text(_markdown(m))
    log.info("wrote metrics.json and summary.md")
    return m
