"""Blind labelling protocol and calibration gate.

Built from claude's round-16 design and GLM-5.3-Flash's provenance guards.
No file I/O except reading the operator-ratified threshold config.
All thresholds default to None and the gate fails closed until ratified.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "thresholds.json"), encoding="utf-8") as _fh:
    THRESHOLDS = json.load(_fh)

VALID_LABELS = ("blocked", "bypassed", "partial", "indeterminate")
ALL_TYPES = ["DT-%02d" % i for i in range(1, 10)]
RECEIPT_FIELDS = ("receipt_id", "event_id", "signal_text", "receipt_hash")
META_LEAK = re.compile(r"(verdict|band\b|defence type|DT-\d\d|score|source path|\.md\b)", re.I)


def make_event_id(source_path: str, row_index: int) -> str:
    return hashlib.sha256(("%s:%s" % (source_path, row_index)).encode()).hexdigest()[:12]


def build_receipt(event: Dict[str, Any], salt: str = "") -> Dict[str, str]:
    """Reviewer sees only these four fields. Never verdict, band, type or path."""
    receipt_id = "RC-" + hashlib.sha1((str(event.get("event_id")) + salt).encode()).hexdigest()[:8]
    r = {"receipt_id": receipt_id, "event_id": str(event.get("event_id")),
         "signal_text": str(event.get("observed_signal_raw") or "")}
    r["receipt_hash"] = hashlib.sha1(json.dumps(r, sort_keys=True).encode()).hexdigest()[:16]
    return {k: r[k] for k in RECEIPT_FIELDS}


def lint_receipt(receipt: Dict[str, str]) -> List[str]:
    return META_LEAK.findall(receipt.get("signal_text", ""))


def verify_raw_provenance(event: Dict[str, Any], raw_ledger_line: str) -> bool:
    sig = str(event.get("observed_signal_raw") or "")
    return bool(sig) and sig in raw_ledger_line


def validate_label_record(rec: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    required = ("event_id", "reviewer_id", "label", "rationale", "labelled_at")
    for f in required:
        if f not in rec:
            errors.append("missing field: " + f)
    if isinstance(rec.get("event_id"), str) and not re.fullmatch(r"[0-9a-f]{12}", rec["event_id"]):
        errors.append("event_id must be 12-char hex")
    if rec.get("label") not in VALID_LABELS:
        errors.append("label must be one of %s" % (", ".join(VALID_LABELS),))
    if not (10 <= len(str(rec.get("rationale", ""))) <= 280):
        errors.append("rationale must be 10-280 chars")
    if rec.get("labelled_at"):
        try:
            datetime.fromisoformat(str(rec["labelled_at"]).replace("Z", "+00:00"))
        except ValueError:
            errors.append("labelled_at must be ISO 8601")
    extra = set(rec) - set(required)
    if extra:
        errors.append("unexpected fields: %s" % sorted(extra))
    return errors


def stratified_sample(events: List[Dict[str, Any]], target: int = 50,
                      seed: int = 42) -> List[Dict[str, Any]]:
    """Proportional allocation with largest-remainder top-up, floored at 3."""
    by_type: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        dt = e.get("defence_type")
        if dt:
            by_type[dt].append(e)
    typed = sum(len(v) for v in by_type.values())
    if typed < target:
        raise ValueError("only %d typed events, cannot sample %d" % (typed, target))
    alloc = {dt: min(3, len(v)) for dt, v in by_type.items()}
    rem = target - sum(alloc.values())
    raw = {dt: rem * len(v) / typed for dt, v in by_type.items()}
    base = {dt: int(raw[dt]) for dt in by_type}
    for dt in by_type:
        alloc[dt] += base[dt]
    rem -= sum(base.values())
    order = sorted(by_type, key=lambda dt: raw[dt] - base[dt], reverse=True)
    while rem > 0:
        progressed = False
        for dt in order:
            if rem == 0:
                break
            if alloc[dt] < len(by_type[dt]):
                alloc[dt] += 1; rem -= 1; progressed = True
        if not progressed:
            break
    rng = random.Random(seed)
    out: List[Dict[str, Any]] = []
    for dt, n in alloc.items():
        out.extend(rng.sample(sorted(by_type[dt], key=lambda e: str(e.get("event_id"))), n))
    rng.shuffle(out)
    return out


def sampling_report(events: List[Dict[str, Any]], sample: List[Dict[str, Any]]) -> Dict[str, Any]:
    all_c = Counter(e["defence_type"] for e in events if e.get("defence_type"))
    smp_c = Counter(e["defence_type"] for e in sample if e.get("defence_type"))
    return {"total_typed": sum(all_c.values()), "total_sampled": len(sample),
            "per_type": {dt: {"available": all_c.get(dt, 0), "sampled": smp_c.get(dt, 0)}
                         for dt in ALL_TYPES}}


def cohens_kappa(labels_a: List[str], labels_b: List[str]) -> float:
    if len(labels_a) != len(labels_b) or not labels_a:
        raise ValueError("label lists must be equal length and non-empty")
    n = len(labels_a)
    po = sum(a == b for a, b in zip(labels_a, labels_b)) / n
    pe = sum((labels_a.count(c) / n) * (labels_b.count(c) / n) for c in VALID_LABELS)
    return 1.0 if pe >= 1.0 else (po - pe) / (1 - pe)


def fleiss_kappa(units: List[List[str]]) -> float:
    if not units:
        raise ValueError("no units")
    n = len(units[0])
    if any(len(u) != n for u in units):
        raise ValueError("incomplete design: use a statistic that handles missing raters")
    col = Counter()
    p_sum = 0.0
    for u in units:
        c = Counter(u); col.update(c)
        p_sum += (sum(v * v for v in c.values()) - n) / (n * (n - 1))
    p_bar = p_sum / len(units)
    tot = sum(col.values())
    pe = sum((v / tot) ** 2 for v in col.values())
    return 1.0 if pe >= 1.0 else (p_bar - pe) / (1 - pe)


def disagreement_matrix(a: List[str], b: List[str]) -> Dict[str, Dict[str, int]]:
    m = {x: {y: 0 for y in VALID_LABELS} for x in VALID_LABELS}
    for x, y in zip(a, b):
        m[x][y] += 1
    return m


def agreed_labels(records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    errors = [e for r in records for e in validate_label_record(r)]
    if errors:
        raise ValueError("; ".join(errors[:5]))
    by_event: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_event[r["event_id"]].append(r)
    agreed, discarded = [], []
    for eid, rs in by_event.items():
        if len(rs) != 2 or rs[0]["label"] != rs[1]["label"]:
            discarded.append(eid)
        else:
            agreed.append({"event_id": eid, "label": rs[0]["label"],
                           "reviewers": [rs[0]["reviewer_id"], rs[1]["reviewer_id"]]})
    return agreed, discarded


def proxy_label(event: Dict[str, Any], rule: str = "status") -> Dict[str, str]:
    """Automated label from receipt features. NOT an independent human review.

    GLM's four-label vocabulary is used verbatim. Two deterministic rules exist so a
    pipeline can be exercised without pretending a human reviewed the receipts.
    """
    receipt = str(event.get("observed_signal_raw") or event.get("receipt") or "")
    low = receipt.lower()
    if rule == "status":
        if any(x in low for x in ("403", "401", "denied", "refused", "blocked", "not allowed")):
            label = "blocked"
        elif "200" in low and any(x in low for x in ("data", "body", "returned", "ok")):
            label = "bypassed"
        elif any(x in low for x in ("partial", "limited", "some")):
            label = "partial"
        else:
            label = "indeterminate"
    elif rule == "signal":
        sig = str(event.get("signal_type") or "ambiguous")
        label = {
            "auth_denied": "blocked", "route_absent": "blocked",
            "path_policy": "blocked", "rate_signal": "blocked",
            "output_mask": "partial", "semantic_refusal": "blocked",
            "entitlement_absent": "blocked", "out_of_scope": "indeterminate",
            "ambiguous": "indeterminate",
        }.get(sig, "indeterminate")
    else:
        raise ValueError("unknown proxy rule: %r" % rule)
    return {"label": label, "rule": rule, "independent": False,
            "note": "automated proxy from receipt features, not human review"}


def calibration_decision(agreed_live_counts: Dict[str, int], kappa: Optional[float],
                         contingency_ok: Dict[str, bool],
                         disagreement_rate: Dict[str, float]) -> Dict[str, Any]:
    """Fails closed while any operator threshold is null."""
    bars = ("kappa_bar", "high_band_precision_bar", "disagreement_rate_bar")
    if any(THRESHOLDS.get(k) is None for k in bars):
        return {"CALIBRATION_STATUS": "deferred",
                "reason": "threshold_unratified: operator ratifies before labels are unblinded",
                "thresholds": THRESHOLDS}
    if kappa is None or kappa < THRESHOLDS["kappa_bar"]:
        return {"CALIBRATION_STATUS": "deferred", "reason": "kappa below ratified bar",
                "kappa": kappa}
    out = {}
    for dt in ALL_TYPES:
        reasons = []
        if agreed_live_counts.get(dt, 0) < THRESHOLDS["min_events_per_type"]:
            reasons.append("short_bin")
        if not contingency_ok.get(dt, False):
            reasons.append("contingency_unknown")
        if disagreement_rate.get(dt, 1.0) > THRESHOLDS["disagreement_rate_bar"]:
            reasons.append("disagreement_above_bar")
        out[dt] = {"status": "deferred" if reasons else "active", "reasons": reasons}
    any_active = any(v["status"] == "active" for v in out.values())
    return {"CALIBRATION_STATUS": "active" if any_active else "deferred",
            "kappa": kappa, "per_type": out, "thresholds": THRESHOLDS}
