"""Adapter: turn injection-bench's recorded sandbox state into Mapper events.

No model call. Offline. The reference agents are scripted, so events are tagged
`provenance: controlled_replay`, not `measured` against a live model.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

_HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.environ.get("INJECTION_BENCH_PATH",
                       os.path.abspath(os.path.join(_HERE, "..", "mcp-injection-bench")))

CATEGORY_DEFENCE = {
    "direct_override": ("DT-02", "model"),
    "indirect_doc": ("DT-09", "model"),
    "tool_output": ("DT-09", "model"),
    "exfil_via_arg": ("DT-05", "output"),
    "privilege_escalation": ("DT-04", "runtime_policy"),
    "multi_turn": ("DT-03", "model"),
}


def convert_bench_results(agent_names: List[str] | None = None) -> Dict[str, Any]:
    if not os.path.isdir(BENCH):
        return {"error": "INJECTION_BENCH_PATH not found", "path": BENCH, "events": []}
    if BENCH not in sys.path:
        sys.path.insert(0, BENCH)
    from injection_bench import agents as bench_agents  # type: ignore
    from injection_bench import cases as bench_cases  # type: ignore
    from injection_bench.cli import run as bench_run  # type: ignore

    names = agent_names or list(bench_agents.BUILTIN)
    events: List[Dict[str, Any]] = []
    for name in names:
        agent = bench_agents.load(name)
        results = bench_run(agent, list(bench_cases.CASES))
        for r in results:
            defence, layer = CATEGORY_DEFENCE.get(r.category, (None, "unknown"))
            kinds = sorted({v.kind for v in r.violations})
            signal = "semantic_refusal" if r.over_refused else (
                "output_mask" if "canary_exfil" in kinds else (
                    "auth_denied" if "secret_read" in kinds or "unauthorized_write" in kinds else (
                        "path_policy" if "shell_exec" in kinds else "ambiguous")))
            events.append({
                "event_id": "bench:%s:%s" % (name, r.case_id),
                "source_path": "portfolio/mcp-injection-bench",
                "line": 0,
                "section": r.category,
                "verdict": "VIOLATION" if r.violations else ("OVER_REFUSED" if r.over_refused else "OK"),
                "signal_type": signal,
                "defence_type": defence,
                "error_codes": [],
                "receipt": "%s | attack=%s | violations=%s | expected_performed=%s" % (
                    r.case_id, r.attack, ",".join(kinds) or "none", r.expected_performed),
                "observed_layer": layer,
                "readback_confirmed": True,
                "route_present": True,
                "provenance": "controlled_replay",
                "agent": name,
            })
    counts: Dict[str, int] = {}
    for e in events:
        dt = e["defence_type"]
        if dt:
            counts[dt] = counts.get(dt, 0) + 1
    return {"events": events, "total": len(events), "defence_counts": counts,
            "note": "controlled replay, not live model evidence"}
