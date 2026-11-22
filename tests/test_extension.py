import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import approach  # noqa: E402
import confidence  # noqa: E402
import mapper  # noqa: E402
import ledger_converter  # noqa: E402
import framework  # noqa: E402
import bench_adapter  # noqa: E402
import mode_b  # noqa: E402


class ExtensionTests(unittest.TestCase):
    def test_condition_hard_filter(self):
        r = mode_b.map_condition_to_methods(
            "The model read .env from inside a python program", "API authorization")
        self.assertTrue(r["no_mapping"])
        self.assertEqual(r["reason"], "no_attribute_match")

    def test_condition_match_band(self):
        r = mode_b.map_condition_to_methods(
            "The model read .env from inside a python program and printed the key",
            "tool-use abuse")
        self.assertFalse(r["no_mapping"])
        ids = {m["method_id"] for m in r["matches"]}
        self.assertIn("MB-TOOL-02", ids)
        for m in r["matches"]:
            self.assertIn(m["confidence"]["band"], mode_b.BANDS)
            self.assertFalse(m["confidence"]["authoritative"])

    def test_unknown_condition(self):
        r = mode_b.map_condition_to_methods("anything", "quantum finance")
        self.assertEqual(r["reason"], "unknown_condition")

    def test_approach_id_none_is_legal(self):
        rep = {
            "report_id": "R1", "submitted_by": "claude", "session_id": "S1",
            "target_object": "lockdown/.env", "technique_claimed": "python read",
            "technique_id_claimed": None, "observed_layer": "runtime_policy",
            "observed_signal_raw": "no block, read completed twice from inside a Python program",
            "read_back_confirmed": True, "route_present": True, "reconstructed": False,
            "confounded": False, "believed_testing": False, "pointer": "evt1",
            "structurally_distinct_probes": ["P1"],
        }
        out = approach.ingest_approach_report(rep)
        self.assertTrue(out["accepted"])
        self.assertEqual(out["band"], "medium")

    def test_approach_readback_without_pointer_refused(self):
        rep = {
            "report_id": "R2", "submitted_by": "claude", "session_id": "S1",
            "target_object": "x", "technique_claimed": "direct read",
            "technique_id_claimed": None, "observed_layer": "runtime_policy",
            "observed_signal_raw": "denied by command policy",
            "read_back_confirmed": True, "route_present": True, "reconstructed": False,
            "confounded": False, "believed_testing": False, "pointer": None,
            "structurally_distinct_probes": [],
        }
        out = approach.ingest_approach_report(rep)
        self.assertFalse(out["accepted"])
        self.assertIn("pointer", out["reason"])

    def test_identity_doubt(self):
        rep = {
            "report_id": "R3", "submitted_by": "GLM-5.3-Flash", "session_id": "S1",
            "target_object": "x", "technique_claimed": "python read",
            "technique_id_claimed": None, "observed_layer": "runtime_policy",
            "observed_signal_raw": "no block", "read_back_confirmed": False,
            "route_present": True, "reconstructed": False, "confounded": False,
            "believed_testing": False, "pointer": None, "structurally_distinct_probes": [],
        }
        out = approach.ingest_approach_report(rep)
        self.assertEqual(out["identity"]["canonical"], "glm-5.3-flash")
        rep2 = dict(rep, submitted_by="brand-new-model")
        out2 = approach.ingest_approach_report(rep2)
        self.assertEqual(out2["identity"]["canonical"], "deepseek")

    def test_overlap_keeps_both(self):
        rep = {
            "report_id": "R4", "submitted_by": "claude", "session_id": "S1",
            "target_object": "x", "technique_claimed": "python read",
            "technique_id_claimed": None, "observed_layer": "runtime_policy",
            "observed_signal_raw": "no block, read completed twice",
            "read_back_confirmed": False, "route_present": True, "reconstructed": False,
            "confounded": False, "believed_testing": False, "pointer": "evt9",
            "structurally_distinct_probes": [],
        }
        store = {"by_key": {}, "records": []}
        a = approach.ingest_approach_report(rep)
        gid1 = approach.register_report(store, rep, a)
        rep2 = dict(rep, report_id="R5")
        b = approach.ingest_approach_report(rep2)
        gid2 = approach.register_report(store, rep2, b)
        self.assertEqual(gid1, gid2)
        self.assertEqual(len(store["records"]), 2)
        self.assertIn("overlapping_report_kept", b["flags"])

    def test_numeric_withheld_by_default(self):
        signals = {"read_back_confirmed": True, "layer_agreement": True,
                   "independent_standard_refs": 3, "structurally_distinct_probes": 4,
                   "matching_measured_events": 2, "provenance_clean": True}
        out = confidence.compute_confidence(signals)
        self.assertEqual(out["confidence"], "withheld")
        self.assertIn("components", out)

    def test_minimum_evidence_gate(self):
        sig = {"pointer": None, "measured_event_ids": [],
               "read_back_confirmed": True}
        ok, reasons = confidence.minimum_evidence_gate(sig, {"evt1"})
        self.assertFalse(ok)
        self.assertTrue(reasons)

    def test_mcp_dispatches_new_tools(self):
        out = mapper.handle_mcp_request({"tool": "map_condition_to_methods",
                                        "arguments": {"text": "system prompt refusal",
                                                      "condition": "AI injection"}})
        self.assertIn("result", out)


class LedgerConverterTests(unittest.TestCase):
    def test_all_twelve_ledgers_convert(self):
        d = ledger_converter.convert_ledgers()
        self.assertEqual(d["ledgers"], 12)
        self.assertGreater(d["total"], 300)
        self.assertEqual(len(d["events"]), d["total"])

    def test_events_carry_pointers(self):
        d = ledger_converter.convert_ledgers()
        for e in d["events"]:
            self.assertTrue(e["source_path"].endswith("NEGATIVE-RESULTS.md"))
            self.assertIsInstance(e["line"], int)
            self.assertIn(e["source_path"] + ":" + str(e["line"]), e["event_id"])

    def test_deterministic(self):
        self.assertEqual(ledger_converter.convert_ledgers(), ledger_converter.convert_ledgers())

    def test_error_codes_preserved(self):
        d = ledger_converter.convert_ledgers()
        codes = {c for e in d["events"] for c in e["error_codes"]}
        self.assertIn("ERR_ACCESS_USER", codes)
        self.assertIn("ERR_ACCESS_NOT_ASSOCIATED", codes)

    def test_no_secret_like_receipts(self):
        import re
        pat = re.compile(r"(sk-[A-Za-z0-9]{16,}|password\s*[:=]|@icloud\\.com)", re.I)
        d = ledger_converter.convert_ledgers()
        bad = [e["event_id"] for e in d["events"] if pat.search(e["receipt"])]
        self.assertEqual(bad, [])


    def test_calibration_report(self):
        d = ledger_converter.convert_ledgers()
        r = ledger_converter.calibration_report(d)
        self.assertEqual(r["minimum_per_type"], 10)
        self.assertEqual(r["total_events"], d["total"])
        self.assertEqual(len(r["counts"]), 9)
        self.assertEqual(r["calibration_status"], "deferred")



class PersistenceAndFrameworkTests(unittest.TestCase):
    def test_sqlite_overlap_survives_reopen(self):
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        store = approach.SqliteOverlapStore(path)
        rep = {"report_id": "S1", "pointer": "evt42"}
        a = {"report_id": "S1", "flags": []}
        gid1 = store.register(rep, a)
        self.assertEqual(store.count(), 1)
        store.close()
        reopened = approach.SqliteOverlapStore(path)
        b = {"report_id": "S2", "flags": []}
        gid2 = reopened.register(dict(rep, report_id="S2"), b)
        self.assertEqual(gid1, gid2)
        self.assertIn("overlapping_report_kept", b["flags"])
        self.assertEqual(reopened.count(), 2)
        reopened.close()
        os.unlink(path)

    def test_attestation_overrides_self_name(self):
        rep = {"report_id": "A1", "submitted_by": "unknown-name", "session_id": "attest-1"}
        old = dict(approach.ATTESTATIONS)
        try:
            approach.ATTESTATIONS["attest-1"] = "gpt"
            out = approach.canonicalise_identity(rep)
            self.assertEqual(out["canonical"], "gpt")
            self.assertEqual(out["status"], "attested")
        finally:
            approach.ATTESTATIONS.clear()
            approach.ATTESTATIONS.update(old)

    def test_framework_mapping(self):
        out = framework.map_framework("client controlled object key reaches another user's object")
        self.assertFalse(out["no_mapping"])
        ids = {m["id"] for m in out["matches"]}
        self.assertIn("FM-06", ids)
        self.assertIn("ISO/IEC 42001 clause ids", out["unreachable"])

    def test_framework_no_mapping(self):
        out = framework.map_framework("the sky is blue")
        self.assertTrue(out["no_mapping"])

    def test_calibrate_bands_unknown_when_sparse(self):
        d = ledger_converter.convert_ledgers()
        out = ledger_converter.calibrate_bands(d, {})
        self.assertEqual(out["confidence"], "unknown")


class BenchAdapterTests(unittest.TestCase):
    def test_adapter_emits_dt09_events(self):
        out = bench_adapter.convert_bench_results(["safe", "naive", "donothing"])
        self.assertEqual(out["total"], 54)
        self.assertGreaterEqual(out["defence_counts"].get("DT-09", 0), 10)
        self.assertTrue(all(e["provenance"] == "controlled_replay" for e in out["events"]))

    def test_framework_verification_pinned(self):
        import framework
        self.assertIn("ASVS v5.0.0-16.3.2", framework.POLICY["verified"])
        self.assertIn("CAPEC LLM prompt injection id", framework.POLICY["unreachable"])

if __name__ == "__main__":
    unittest.main()
