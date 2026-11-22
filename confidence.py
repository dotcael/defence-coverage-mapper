"""Confidence with a hard evidence floor. Numeric output is deferred by default.

Structural weights from claude round 15, minimum-evidence and anti-double-count rules from the
round 15b reviewers. A caller gets a number only with emit_numeric=True and still sees the
deferred flag on every number.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

CALIBRATION_STATUS = "deferred"
WEIGHTS = {
    "read_back_confirmed": 0.30,
    "layer_known": 0.20,
    "standard_ref": 0.05,
    "distinct_probe": 0.025,
    "measured_event": 0.10,
    "clean_provenance": 0.05,
}
REF_CAP = 0.15
PROBE_CAP = 0.10
EVENT_CAP = 0.20


def minimum_evidence_gate(report: Dict[str, Any], ledger_event_ids: set) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    pointer = report.get("pointer")
    p_ok = isinstance(pointer, str) and pointer.strip() in ledger_event_ids
    events = [e for e in (report.get("measured_event_ids") or [])
              if e in ledger_event_ids and e != pointer]
    if not (p_ok or events):
        reasons.append("no primary evidence: pointer does not resolve and no distinct measured event")
    if report.get("read_back_confirmed") and not p_ok:
        reasons.append("read-back asserted but pointer missing or unresolved")
    return (not reasons), reasons


def compute_confidence(signals: Dict[str, Any], *, emit_numeric: bool = False,
                       ledger_event_ids: Optional[set] = None) -> Dict[str, Any]:
    required = ("read_back_confirmed", "layer_agreement", "independent_standard_refs",
                "structurally_distinct_probes", "matching_measured_events",
                "provenance_clean")
    for key in required:
        if signals.get(key) is None:
            return {"confidence": "unknown", "reason": f"missing input {key}"}

    components = {
        "read_back": WEIGHTS["read_back_confirmed"] if signals["read_back_confirmed"] else 0.0,
        "layer": WEIGHTS["layer_known"] if signals["layer_agreement"] is True else 0.0,
        "refs": min(int(signals["independent_standard_refs"]) * WEIGHTS["standard_ref"], REF_CAP),
        "probes": min(int(signals["structurally_distinct_probes"]) * WEIGHTS["distinct_probe"], PROBE_CAP),
        "events": min(int(signals["matching_measured_events"]) * WEIGHTS["measured_event"], EVENT_CAP),
        "provenance": WEIGHTS["clean_provenance"] if signals["provenance_clean"] else 0.0,
    }
    raw = round(sum(components.values()), 4)
    caps: List[str] = []

    if not signals["read_back_confirmed"] and signals["matching_measured_events"] == 0:
        raw = min(raw, 0.40); caps.append("C1 no readback and no events -> 0.40")
    if signals["layer_agreement"] is not True:
        raw = min(raw, 0.30); caps.append("C2 layer not validated by ingest -> 0.30")
    if not signals["provenance_clean"]:
        raw = min(raw, 0.35); caps.append("C3 confounded -> 0.35")
    if signals["matching_measured_events"] == 0 and raw > 0.50:
        raw = 0.50; caps.append("M1 no measured events -> 0.50")
    if CALIBRATION_STATUS == "deferred" and raw > 0.70:
        raw = 0.70; caps.append("M4 calibration deferred -> 0.70")

    if ledger_event_ids is not None:
        ok, reasons = minimum_evidence_gate(signals, ledger_event_ids)
        if not ok:
            return {"confidence": "unknown", "reason": "; ".join(reasons),
                    "components": components, "caps": caps}

    if not emit_numeric:
        return {"confidence": "withheld", "reason": "emit_numeric=False; CALIBRATION_STATUS=deferred",
                "raw_capped_if_emitted": raw, "components": components, "caps": caps,
                "calibration_status": CALIBRATION_STATUS}
    return {"confidence": raw, "components": components, "caps": caps,
            "calibration_status": CALIBRATION_STATUS, "provisional": True}
