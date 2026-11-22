import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mcp_server  # noqa: E402


class MCPTests(unittest.TestCase):
    def test_tools_list(self):
        r = mcp_server.dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [t["name"] for t in r["result"]["tools"]]
        self.assertEqual(len(names), 14)
        self.assertIn("blue_team_review", names)

    def test_unknown_tool_is_error_result(self):
        r = mcp_server.dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                 "params": {"name": "nope", "arguments": {}}})
        self.assertIn("unknown tool", r["error"]["message"])

    def test_convert_over_stdio_wire(self):
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "convert_block_log", "arguments": {
                   "source_path": "seed",
                   "raw_entries": [{"line_ref": "20", "raw_text": "policy refusal on a protected path"}]}}}
        inp = io.StringIO(json.dumps(req) + "\n")
        out = io.StringIO()
        mcp_server.serve(stdin=inp, stdout=out)
        line = out.getvalue().strip().splitlines()[0]
        resp = json.loads(line)
        text = resp["result"]["content"][0]["text"]
        self.assertIn("path_policy", text)
        self.assertFalse(resp["result"]["isError"])

    def test_bad_input_returns_tool_error_not_crash(self):
        req = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
               "params": {"name": "coverage_map", "arguments": {}}}
        r = mcp_server.dispatch(req)
        self.assertTrue(r["result"]["isError"])
        self.assertIn("ERROR", r["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
