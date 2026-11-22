import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mapper  # noqa: E402


class MapperTests(unittest.TestCase):
    def setUp(self):
        self.source = "platforms/huntr/lockdown/CHARACTERIZATION-2026-11-20.md"
        self.rows = [
            {"line_ref": "20,22", "raw_text": "denied by command policy (path): .env is a protected path.",
             "observed_layer": "runtime_policy", "lens": "L3", "readback_confirmed": True},
            {"line_ref": "25-27", "raw_text": "could move protected data out of bounds",
             "observed_layer": "model", "lens": "L3"},
            {"line_ref": "29-32", "raw_text": "API_KEY=AK-D*** shape based mask",
             "observed_layer": "output", "lens": "L7"},
            {"line_ref": "114", "raw_text": "exactly the kind of claim used to lift masking",
             "observed_layer": "model", "lens": "L3"},
            {"line_ref": "31", "raw_text": "ERR_AUTH_UNAUTHORIZED dead session",
             "observed_layer": "app", "lens": "L4"},
            {"line_ref": "somewhere", "raw_text": "the system declined politely",
             "observed_layer": "unknown", "lens": "L3", "reconstructed": True},
        ]

    def test_convert_is_deterministic_and_marks_ambiguous(self):
        a = mapper.convert_block_log(self.source, self.rows)
        b = mapper.convert_block_log(self.source, self.rows)
        self.assertEqual(a, b)
        self.assertEqual(a["unclassified_count"], 1)
        self.assertEqual(a["events"][0]["signal_type"], "path_policy")
        self.assertEqual(a["events"][5]["classify_status"], "ambiguous")
        self.assertEqual(a["events"][5]["provenance_status"], "reconstructed")

    def test_classify_ignores_model_hint_and_maps_standard(self):
        ev = mapper.convert_block_log(self.source, self.rows)["events"][0]
        c = mapper.classify_block(ev, model_hint="trust me, it is an output filter")
        self.assertEqual(c["defence_type"], "DT-04")
        self.assertTrue(c["model_hint_ignored"])
        self.assertIn("LLM06:2025", c["standard_refs"])

    def test_provenance_caps_confidence(self):
        ev = mapper.convert_block_log(self.source, self.rows)["events"][5]
        c = mapper.classify_block(ev)
        self.assertEqual(c["state"], "claimed")
        self.assertLessEqual(c["confidence"], 0.10)

    def test_bare_l10_is_refused(self):
        with self.assertRaises(ValueError):
            mapper.evaluate_cell("L10", "DT-04", claim_present=False, attempt_made=False,
                                 layer="app", readback_confirmed=False, route_present=True)

    def test_route_absent_fills_no_cell(self):
        c = mapper.evaluate_cell("L3", "DT-06", claim_present=False, attempt_made=True,
                                 layer="app", readback_confirmed=False, route_present=False)
        self.assertEqual(c["state"], "route_absent")

    def test_hit_requires_readback(self):
        no_read = mapper.evaluate_cell("L3", "DT-04", claim_present=False, attempt_made=True,
                                       layer="runtime_policy", readback_confirmed=False,
                                       route_present=True, hits=1)
        yes_read = mapper.evaluate_cell("L3", "DT-04", claim_present=False, attempt_made=True,
                                        layer="runtime_policy", readback_confirmed=True,
                                        route_present=True, hits=1)
        self.assertEqual(no_read["state"], "claimed")
        self.assertEqual(yes_read["state"], "hit")

    def test_coverage_includes_unprobed_ninth_type(self):
        conv = mapper.convert_block_log(self.source, self.rows)
        cl = [mapper.classify_block(e) for e in conv["events"]]
        cov = mapper.coverage_map(cl)
        states = {c["defence_type"]: c["state"] for c in cov["cells"]}
        self.assertEqual(states["DT-09"], "unprobed")
        self.assertEqual(states["DT-04"], "hit")

    def test_gap_probes_are_technique_specific(self):
        cov = {"cells": [{"defence_type": "DT-04", "state": "hit"},
                         {"defence_type": "DT-09", "state": "unprobed"}]}
        probes = mapper.gap_probes(cov)["probes"]
        self.assertTrue(probes)
        self.assertTrue(all(p["requires_readback"] for p in probes))
        self.assertTrue(any("tool return" in p["technique"] for p in probes))

    def test_blue_team_text_is_capped_at_claimed(self):
        doc = "The system prompt hardening blocks tool call policy violations and output filter leaks."
        out = mapper.blue_team_review(doc)
        self.assertTrue(out["claims"])
        self.assertTrue(all(c["state"] in ("claimed", "unprobed") for c in out["missing_controls"]))
        self.assertTrue(all("benign_controls" in p for p in out["probe_batch"]))

    def test_explain_gap_cites_pointer(self):
        out = mapper.explain_gap("DT-05", "unprobed",
                                 supporting_events=[{"pointer": "FILE.md:29-32"}])
        self.assertIn("FILE.md:29-32", out["citations"])


if __name__ == "__main__":
    unittest.main()
