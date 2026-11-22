#!/usr/bin/env python3
"""Minimal MCP (Model Context Protocol) stdio server for the defence coverage mapper.

Line-delimited JSON-RPC on stdin/stdout. Logs go to stderr so the wire stays clean.
No API keys, no network, no model calls. A client can call any tool in tool_schemas.json.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mapper  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "tool_schemas.json"), encoding="utf-8") as _fh:
    SCHEMAS = json.load(_fh)
TOOLS = {t["name"]: t for t in SCHEMAS["tools"]}


def dispatch(msg: Dict[str, Any]) -> Dict[str, Any]:
    # A per-call nonce on stderr lets a live client prove a real process answered.
    print("CALL nonce=%s method=%s" % (msg.get("id"), msg.get("method")), file=sys.stderr)
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "defence-coverage-mapper", "version": "0.1.0"},
            "capabilities": {"tools": {}},
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "tools": [{"name": t["name"], "description": t["description"],
                       "inputSchema": t["input_schema"]} for t in SCHEMAS["tools"]]
        }}
    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        arguments = params.get("arguments", {})
        if name not in TOOLS:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32602, "message": "unknown tool: %r" % name}}
        try:
            result = mapper.handle_mcp_request({"tool": name, "arguments": arguments})["result"]
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}],
                "isError": False,
            }}
        except Exception as exc:  # a bad input is a tool error, not a protocol crash
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "ERROR: %s" % exc}], "isError": True}}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}


def serve(stdin=None, stdout=None) -> None:
    src = stdin or sys.stdin
    out = stdout or sys.stdout
    for raw in src:
        line = raw.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            out.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32700, "message": str(exc)}}) + "\n")
            out.flush()
            continue
        out.write(json.dumps(dispatch(msg), ensure_ascii=False) + "\n")
        out.flush()


if __name__ == "__main__":
    serve()
