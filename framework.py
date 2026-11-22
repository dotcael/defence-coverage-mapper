"""Framework-to-method mapping from verified security frameworks.

Deterministic, offline. No model call. Rows come from GPT-6 round 15, with DISCOURAGED CWE ids
kept as background only. A row matches only when its attribute phrase is present in the text.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "framework_map.json"), encoding="utf-8") as _fh:
    MAP = json.load(_fh)

POLICY = MAP["policy"]
BACKGROUND = set(POLICY["background_only"])


def _normal(s: str) -> str:
    return " ".join(str(s).lower().replace("-", " ").split())


def map_framework(text: str) -> Dict[str, Any]:
    if not text or not text.strip():
        return {"no_mapping": True, "reason": "empty_text", "matches": []}
    hay = _normal(text)
    matches: List[Dict[str, Any]] = []
    for row in MAP["rows"]:
        attr = _normal(row["attribute"])
        if attr not in hay:
            continue
        refs = []
        for ref in row.get("refs", []):
            refs.append({"id": ref,
                         "status": "background_only" if ref in BACKGROUND else "conditional"})
        matches.append({
            "id": row["id"],
            "method": row["method"],
            "matched_attribute": row["attribute"],
            "refs": refs,
            "conditional_ref": row.get("conditional_ref"),
            "falsifier": row["falsifier"],
        })
    if not matches:
        return {"no_mapping": True, "reason": "no_attribute_match",
                "rows_considered": len(MAP["rows"]), "matches": []}
    return {"no_mapping": False, "matches": matches,
            "unreachable": POLICY["unreachable"]}
