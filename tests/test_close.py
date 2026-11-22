import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import labelling  # noqa: E402
import mcp_client  # noqa: E402
import probes  # noqa: E402


class CloseGapTests(unittest.TestCase):
    def _typed_events(self):
        counts = {"DT-01": 11, "DT-03": 17, "DT-04": 23, "DT-05": 10,
                  "DT-06": 89, "DT-07": 3, "DT-08": 12}
        out = []
        n = 0
        for dt, c in counts.items():
            for i in range(c):
                n += 1
                out.append({"event_id": "%s:%d" % (dt, i), "defence_type": dt,
                            "observed_signal_raw": "receipt %s %d" % (dt, i)})
        return out

    def test_stratified_sample(self):
        events = self._typed_events()
        sample = labelling.stratified_sample(events, target=50, seed=42)
        self.assertEqual(len(sample), 50)
        rep = labelling.sampling_report(events, sample)
        self.assertEqual(rep["total_typed"], 165)
        self.assertEqual(rep["per_type"]["DT-07"]["sampled"], 3)
        self.assertEqual(rep["per_type"]["DT-06"]["sampled"], 19)

    def test_kappa(self):
        self.assertEqual(labelling.cohens_kappa(["blocked"] * 5, ["blocked"] * 5), 1.0)
        self.assertLess(labelling.cohens_kappa(["blocked", "blocked", "bypassed"], ["bypassed", "bypassed", "blocked"]), 0)

    def test_calibration_fails_closed(self):
        out = labelling.calibration_decision({"DT-06": 50}, 0.9, {"DT-06": True}, {"DT-06": 0.1})
        self.assertEqual(out["CALIBRATION_STATUS"], "deferred")
        self.assertIn("threshold_unratified", out["reason"])

    def test_receipt_blinding(self):
        event = {"event_id": "abc", "observed_signal_raw": "403 forbidden no data",
                 "verdict": "REFUTED", "defence_type": "DT-06"}
        r = labelling.build_receipt(event)
        self.assertEqual(set(r), set(labelling.RECEIPT_FIELDS))
        self.assertNotIn("verdict", r)
        self.assertEqual(labelling.lint_receipt(r), [])
        bad = dict(r, signal_text="verdict REFUTED band high DT-06")
        self.assertTrue(labelling.lint_receipt(bad))
        self.assertTrue(labelling.verify_raw_provenance(event, "prefix 403 forbidden no data suffix"))

    def test_probe_counts(self):
        self.assertEqual(len(probes.DT02_PROBES), 10)
        self.assertEqual(len(probes.DT07_PROBES), 7)

    def test_dt02_guard(self):
        ok, reasons = probes.accept_dt02_event(
            {"canary_matched": True, "pointer": "p", "kind": "live"}, {"canary_surfaced": False})
        self.assertTrue(ok)
        bad, reasons2 = probes.accept_dt02_event(
            {"canary_matched": False, "pointer": None, "kind": "controlled_replay"},
            {"canary_surfaced": True})
        self.assertFalse(bad)
        self.assertGreaterEqual(len(reasons2), 4)

    def test_dt07_guard(self):
        ok, _ = probes.accept_dt07_event(
            {"kind": "live", "firings": 2, "header_evidence": False},
            {"liveness_ping_ok": True, "requests_sent": 13, "budget": 13})
        self.assertTrue(ok)
        bad, _ = probes.accept_dt07_event(
            {"kind": "live", "firings": 1, "header_evidence": False},
            {"liveness_ping_ok": False, "requests_sent": 20, "budget": 13})
        self.assertFalse(bad)

    def test_live_mcp_and_negative_control(self):
        result = mcp_client.self_test()
        self.assertTrue(result["ok"])
        self.assertEqual(result["real"]["verdict"], "PASS")
        self.assertEqual(result["stub"]["verdict"], "SIMULATION DETECTED")


    def test_proxy_labels_use_glm_vocabulary(self):
        e = {"observed_signal_raw": "403 forbidden", "signal_type": "auth_denied"}
        self.assertEqual(labelling.proxy_label(e, "status")["label"], "blocked")
        self.assertEqual(labelling.proxy_label(e, "signal")["label"], "blocked")
        self.assertFalse(labelling.proxy_label(e, "status")["independent"])
        e2 = {"observed_signal_raw": "no signal", "signal_type": "ambiguous"}
        self.assertEqual(labelling.proxy_label(e2, "signal")["label"], "indeterminate")

if __name__ == "__main__":
    unittest.main()
