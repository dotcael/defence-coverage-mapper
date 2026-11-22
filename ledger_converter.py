"""Convert the 12 NEGATIVE-RESULTS.md ledgers into normalised coverage events.

Deterministic. Reads only. No target traffic, no model calls, no credentials.
Outputs JSONL-compatible dicts with source path, line number, exact receipt and verdict.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

VERDICT_RE = re.compile(
    r"\b(REFUTED|NOT REPRODUCED|UNREACHABLE|UNTESTED|BOUNDARY HOLDS|CLOSED|"
    r"NOT A FINDING|N/A|OUT OF SCOPE|NOT APPLICABLE|DEAD)\b", re.I)
ERR_RE = re.compile(r"\b(ERR_[A-Z_]+)\b")
STATUS_RE = re.compile(r"\b([1-5]\d\d)\b")
SIGNAL_RULES = [
    ("path_policy", re.compile(r"denied by command policy|protected path|command policy", re.I)),
    ("move_out_of_bounds", re.compile(r"out of bounds|move protected", re.I)),
    ("output_mask", re.compile(r"mask(ed|ing)?|partial fragments", re.I)),
    ("semantic_refusal", re.compile(r"refus|won't do|not allow|can't verify|named the|flagged as", re.I)),
    ("auth_denied", re.compile(r"err_access_|err_auth_|unauthorized|403|401|insufficient access|blocked|denied|not allowed|forbidden|permission denied", re.I)),
    ("rate_signal", re.compile(r"429|rate limit|too many requests|quota", re.I)),
    ("route_absent", re.compile(r"\b404\b|no route|route absent|empty namespace|not found|timed out|timeout|nxdomain|\b000\b", re.I)),
    ("entitlement_absent", re.compile(r"entitlement|not enabled|not granted|disabled", re.I)),
    ("out_of_scope", re.compile(r"out of scope|not eligible|worth \$0", re.I)),
]
DEFENCE_HINTS = [
    ("DT-04", re.compile(r"command policy|tool|mutation|write|push|folder create", re.I)),
    ("DT-06", re.compile(r"authorization|owner|access|403|401|scope|tenant|cross", re.I)),
    ("DT-01", re.compile(r"input|prompt|filter|validation|extension", re.I)),
    ("DT-05", re.compile(r"output|mask|redact|disclosure|email|avatar", re.I)),
    ("DT-03", re.compile(r"refus|intent|named|flagged|decoy", re.I)),
    ("DT-07", re.compile(r"rate|limit|quota|429", re.I)),
    ("DT-08", re.compile(r"log|audit|receipt|record", re.I)),
]


def _signal(text: str) -> str:
    for name, rx in SIGNAL_RULES:
        if rx.search(text):
            return name
    return "ambiguous"


def _defence(text: str) -> Optional[str]:
    for dtype, rx in DEFENCE_HINTS:
        if rx.search(text):
            return dtype
    return None


def _verdict(text: str) -> str:
    m = VERDICT_RE.search(text)
    if m:
        return m.group(1).upper()
    s = STATUS_RE.search(text)
    return "STATUS_" + s.group(1) if s else "UNLABELLED"


def _clean(cell: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"\*\*|`", "", cell)).strip()


def _columns(line: str) -> List[str]:
    return [_clean(c) for c in line.strip().strip("|").split("|")]


def convert_ledgers(root: Optional[str] = None) -> Dict[str, Any]:
    base = root or ROOT
    paths = []
    for dp, dn, fn in os.walk(os.path.join(base, "platforms")):
        dn[:] = [d for d in dn if d != ".git"]
        for f in fn:
            if f == "NEGATIVE-RESULTS.md":
                paths.append(os.path.join(dp, f))
    paths.sort()

    events: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for path in paths:
        rel = os.path.relpath(path, base)
        with open(path, errors="replace") as fh:
            lines = fh.read().splitlines()
        heading = ""
        n = 0
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") and not stripped.startswith("#####"):
                heading = stripped.lstrip("# ").strip()
                continue
            if not stripped or stripped.startswith("| ---") or stripped.startswith("|---"):
                continue
            if stripped.startswith(">"):
                continue
            raw = ""
            if stripped.startswith("|"):
                cols = _columns(stripped)
                if len(cols) < 2 or re.match(r"^(class|id|#|target|host|request|move|mutation|target class)\b", cols[0], re.I):
                    continue
                joined = " ".join(cols)
                if not (VERDICT_RE.search(joined) or ERR_RE.search(joined) or STATUS_RE.search(joined)):
                    continue
                raw = joined
            elif stripped.startswith(("-", "*")):
                candidate = stripped.lstrip("-* ").strip()
                head = candidate[:80]
                if not (VERDICT_RE.search(head) or ERR_RE.search(candidate) or STATUS_RE.search(candidate)):
                    continue
                raw = candidate
            elif ERR_RE.search(stripped) or (VERDICT_RE.search(stripped[:80]) and len(stripped) > 20):
                raw = stripped
            if not raw:
                continue
            codes = sorted(set(ERR_RE.findall(raw)))
            verdict = _verdict(raw)
            event = {
                "event_id": "%s:%d" % (rel, i),
                "source_path": rel,
                "line": i,
                "section": heading[:120],
                "verdict": verdict,
                "signal_type": _signal(raw),
                "defence_type": _defence(raw),
                "error_codes": codes,
                "receipt": raw[:600],
                "observed_layer": "unknown",
                "readback_confirmed": False,
                "route_present": True,
                "provenance": "direct",
            }
            events.append(event)
            counts[rel] = counts.get(rel, 0) + 1
            n += 1
    return {"ledgers": len(paths), "events": events, "counts": counts,
            "total": len(events)}


def _provisional_band(event: Dict[str, Any]) -> str:
    """Structural band for a converted event. Not a calibrated probability."""
    if not event.get("defence_type"):
        return "unknown"
    if event.get("error_codes"):
        return "medium"
    if event.get("verdict") not in ("UNLABELLED", "UNTESTED"):
        return "low"
    return "unknown"


def _truth_value(v: Any) -> Optional[bool]:
    if v is True or (isinstance(v, str) and v.strip().lower() in ("blocked", "true", "yes", "1")):
        return True
    if v is False or (isinstance(v, str) and v.strip().lower() in ("bypassed", "false", "no", "0")):
        return False
    return None


def calibrate_bands(data: Optional[Dict[str, Any]], labels: Dict[str, Any],
                    min_per_bin: int = 10) -> Dict[str, Any]:
    """Band-vs-truth contingency. Returns 'unknown' when a bin is too small."""
    d = data or convert_ledgers()
    bins: Dict[str, Dict[str, int]] = {}
    for e in d.get("events", []):
        eid = e.get("event_id")
        truth = _truth_value(labels.get(eid)) if labels and eid in labels else None
        if truth is None:
            continue
        band = _provisional_band(e)
        b = bins.setdefault(band, {"n": 0, "positive": 0})
        b["n"] += 1
        if truth:
            b["positive"] += 1
    if not bins or any(b["n"] < min_per_bin for b in bins.values()):
        return {"confidence": "unknown", "reason": "bin below minimum",
                "min_per_bin": min_per_bin,
                "bins": {k: v for k, v in bins.items()}}
    contingency = {}
    for band, b in bins.items():
        contingency[band] = {"n": b["n"], "p_truth_given_band": round(b["positive"] / b["n"], 4)}
    return {"confidence": "computed", "provisional": True,
            "min_per_bin": min_per_bin, "bins": contingency,
            "note": "provisional band definition; not claude's calibrated scale"}


def calibration_report(data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Count mapped events per defence type and report calibration readiness."""
    d = data or convert_ledgers()
    types = ["DT-%02d" % i for i in range(1, 10)]
    counts = {t: 0 for t in types}
    for e in d.get("events", []):
        dt = e.get("defence_type")
        if dt in counts:
            counts[dt] += 1
    ready = {t: counts[t] >= 10 for t in types}
    return {
        "total_events": d.get("total", 0),
        "unmapped_events": sum(1 for e in d.get("events", []) if not e.get("defence_type")),
        "counts": counts,
        "ready": ready,
        "eligible_types": [t for t, ok in ready.items() if ok],
        "ineligible_types": [t for t, ok in ready.items() if not ok],
        "minimum_per_type": 10,
        "calibration_status": "deferred" if not all(ready.values()) else "active",
    }
