"""Mode B: condition-to-method mapping.

Deterministic, offline, stateless. No model call, no API key, no invented number.
Condition is a hard filter. Text is searched only inside the condition's method list.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "condition_map.json"), encoding="utf-8") as _fh:
    TABLE = __import__("json").load(_fh)

BANDS = ("unknown", "low", "medium", "high")
CREDITED_POLICIES = {"allowed", "allowed_with_review"}


def _normal(s: str) -> str:
    return " ".join(str(s).lower().split())


def _resolve_condition(condition: str) -> Optional[str]:
    target = _normal(condition)
    for c in TABLE["condition_vocabulary"]:
        if _normal(c) == target:
            return c
    return None


def _confidence(method: Dict[str, Any]) -> Dict[str, Any]:
    measured = method.get("measured_evidence", [])
    atoms = {(m.get("event_id"), m.get("signal_type")) for m in measured}
    n_atoms = len(atoms)
    refs = [r for r in method.get("standard_refs", []) if r.get("policy") in CREDITED_POLICIES]
    frameworks = {r.get("framework") for r in refs}
    n_frameworks = len(frameworks)

    if not measured and not refs:
        band, rule = "unknown", "no measured evidence and no credited standard ref"
    elif (not measured or not refs) and n_atoms < 2:
        band, rule = "low", "one evidence channel only, or fewer than two structurally different events"
    elif n_atoms >= 2 and n_frameworks >= 2:
        band, rule = "high", "two or more distinct events and two or more credited frameworks"
    else:
        band, rule = "medium", "at least one measured event and one credited standard ref"
    return {
        "band": band,
        "rule": rule,
        "measured_atoms": n_atoms,
        "credited_frameworks": n_frameworks,
        "authoritative": False,
        "note": "band fallback; numeric confidence deferred until calibration clears",
    }


def map_condition_to_methods(text: str, condition: str) -> Dict[str, Any]:
    if not text or not text.strip():
        return {"no_mapping": True, "reason": "empty_text", "condition": condition, "matches": []}
    canonical = _resolve_condition(condition)
    if canonical is None:
        return {"no_mapping": True, "reason": "unknown_condition", "condition": condition,
                "condition_vocabulary": list(TABLE["condition_vocabulary"]), "matches": []}
    haystack = _normal(text)
    matches: List[Dict[str, Any]] = []
    for method in TABLE["methods"].get(canonical, []):
        hits = [a for a in method.get("attributes", []) if _normal(a) in haystack]
        if not hits:
            continue
        matches.append({
            "method_id": method["method_id"],
            "method_name": method["method_name"],
            "lens": method["lens"],
            "defence_target": method["defence_target"],
            "matched_attributes": hits,
            "standard_refs": method.get("standard_refs", []),
            "measured_evidence": method.get("measured_evidence", []),
            "confidence": _confidence(method),
            "falsifier": method.get("falsifier"),
        })
    if not matches:
        return {"no_mapping": True, "reason": "no_attribute_match", "condition": canonical,
                "methods_considered": len(TABLE["methods"].get(canonical, [])), "matches": []}
    return {"no_mapping": False, "condition": canonical, "matches": matches}
