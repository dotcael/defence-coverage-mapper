"""Live MCP stdio client test with a negative control.

No model provider involved. The 'live' part is a real spawned server process driven by a
stdlib JSON-RPC client. A canned stub that mimics happy paths must be detected via error paths.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict, List

_HERE = os.path.dirname(os.path.abspath(__file__))


class McpStdioClient:
    def __init__(self, cmd: List[str]):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, bufsize=1)
        self.frames: List[Any] = []
        self._id = 0
        self.stderr_text = ""

    def _send(self, method: str, params=None, notify: bool = False) -> Any:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        self.frames.append(("->", msg))
        return msg.get("id")

    def _recv(self, want_id):
        for _ in range(300):
            line = self.p.stdout.readline()
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                self.frames.append(("<-raw", line))
                continue
            self.frames.append(("<-", obj))
            if obj.get("id") == want_id:
                return obj
        return None

    def rpc(self, method: str, params=None):
        return self._recv(self._send(method, params))

    def notify(self, method: str, params=None):
        self._send(method, params, notify=True)

    def close(self):
        try:
            self.p.stdin.close()
        except Exception:
            pass
        try:
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()
        self.stderr_text = self.p.stderr.read()


def local_expected_counts() -> Dict[str, int]:
    sys.path.insert(0, _HERE)
    import ledger_converter  # noqa: E402
    r = ledger_converter.calibration_report(ledger_converter.convert_ledgers())
    return dict(r["counts"])


def live_mcp_test(cmd: List[str], expect_server: str = "defence-coverage-mapper",
                  expect_counts: Dict[str, int] | None = None) -> Dict[str, Any]:
    expect_counts = expect_counts or local_expected_counts()
    c = McpStdioClient(cmd)
    init = c.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                "clientInfo": {"name": "hive-live-probe", "version": "0.1"}})
    name = (((init or {}).get("result") or {}).get("serverInfo") or {}).get("name")
    a_init = init is not None and "error" not in init and name == expect_server
    c.notify("notifications/initialized")
    tl = c.rpc("tools/list", {})
    tools = [t.get("name") for t in (((tl or {}).get("result") or {}).get("tools") or [])]
    a_list = "calibration_report" in tools
    call = c.rpc("tools/call", {"name": "calibration_report", "arguments": {}})
    text = ((((call or {}).get("result") or {}).get("content") or [{}])[0] or {}).get("text", "")
    try:
        counts = json.loads(text).get("counts")
    except Exception:
        counts = None
    a_content = counts == expect_counts
    bad_tool = c.rpc("tools/call", {"name": "nonexistent_tool_xyz", "arguments": {}})
    bad_method = c.rpc("nonexistent/method_xyz", {})
    a_err = bool((bad_tool or {}).get("error")) and bool((bad_method or {}).get("error"))
    c.close()
    a_nonce = "CALL nonce=" in c.stderr_text
    assertions = {"server_identity": a_init, "tool_listed": a_list,
                  "content_matches_local": a_content, "error_paths": a_err,
                  "stderr_nonce": a_nonce}
    if all(assertions.values()):
        verdict = "PASS"
    elif a_init and a_list and a_content and a_nonce and not a_err:
        verdict = "SIMULATION DETECTED"
    else:
        verdict = "FAIL"
    return {"verdict": verdict, "assertions": assertions,
            "frames_recorded": len(c.frames)}


STUB_SOURCE = r'''
import json,sys
for line in sys.stdin:
    try: m=json.loads(line)
    except: continue
    mid=m.get("id"); method=m.get("method")
    print("CALL nonce=%s method=%s"%(mid,method),file=sys.stderr)
    if method=="initialize": r={"serverInfo":{"name":"defence-coverage-mapper"},"capabilities":{}}
    elif method=="tools/list": r={"tools":[{"name":"calibration_report"}]}
    elif method=="tools/call" and m.get("params",{}).get("name")=="calibration_report":
        r={"content":[{"type":"text","text":__import__("json").dumps({"counts":COUNTS})}]}
    else: r={}
    sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":mid,"result":r})+"\n"); sys.stdout.flush()
'''.replace("COUNTS", "__COUNTS__")


def negative_control(counts: Dict[str, int]) -> Dict[str, Any]:
    """Canned stub: mimics identity, list, content and stderr, but never errors."""
    import tempfile
    src = STUB_SOURCE.replace("__COUNTS__", repr(counts))
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    with open(path, "w") as fh:
        fh.write(src)
    try:
        return live_mcp_test([sys.executable, path], expect_counts=counts)
    finally:
        os.unlink(path)


def self_test() -> Dict[str, Any]:
    real = live_mcp_test([sys.executable, os.path.join(_HERE, "mcp_server.py")])
    stub = negative_control(local_expected_counts())
    return {"real": real, "stub": stub,
            "ok": real["verdict"] == "PASS" and stub["verdict"] == "SIMULATION DETECTED"}


if __name__ == "__main__":
    print(json.dumps(self_test(), indent=2))
