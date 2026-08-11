#!/usr/bin/env python3
"""REDCELL MCP server — expose the security surfaces as tools any agent can call.

Zero-dependency stdio JSON-RPC (MCP) server. It makes REDCELL *infrastructure*:
Claude Desktop, Cursor, or any MCP client can call these tools to defend or test
another agent. The four tools are 0-API (pure static analysis / regex),
so they run instantly with no keys and no quota.

Tools
-----
  firewall_check {input}            → runtime injection verdict (allow/flag/block, matches)
  scan_prompt   {system_prompt}     → static resilience score vs the OWASP LLM Top 10
  tool_check    {name, arguments}   → risk of a proposed agent tool/function call
  agent_check   {system_prompt?, input?, tool_call?} → unified verdict across all three

Wire it into an MCP client (e.g. Claude Desktop `mcpServers`):
    { "redcell": { "command": "python3", "args": ["/home/furkan/redcell/redcell_mcp.py"] } }

Protocol: newline-delimited JSON-RPC 2.0 over stdio (MCP 2024-11-05). Diagnostics
go to stderr; only JSON-RPC frames go to stdout.
"""
from __future__ import annotations

import json
import sys

from redcell_firewall import inspect as fw_inspect
from redcell_static import analyze as static_analyze
from redcell_toolcheck import check as tool_check

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "redcell", "version": "1.0.0"}

TOOLS = [
    {
        "name": "firewall_check",
        "description": ("Inspect an UNTRUSTED input (a user message, retrieved document, or tool result) for "
                        "prompt-injection / jailbreak / data-exfiltration attempts BEFORE it reaches your agent's "
                        "model. 34 detectors plus deobfuscation of base64, leetspeak, homoglyphs, zero-width and "
                        "invisible Unicode-tag smuggling. Returns a verdict: allow | flag | block, a risk score, and "
                        "the matched attack rules. 0 API, microsecond latency. Use as an input firewall for any LLM agent."),
        "inputSchema": {
            "type": "object",
            "properties": {"input": {"type": "string", "description": "the untrusted text to inspect"}},
            "required": ["input"],
        },
    },
    {
        "name": "scan_prompt",
        "description": ("Score an AI agent's SYSTEM PROMPT for defensive resilience against the OWASP LLM Top 10 "
                        "(22 detectors: missing instruction hierarchy, no confidentiality, excessive agency, "
                        "hardcoded secrets, etc.). Returns a 0-100 resilience score, grade, and the findings. Use "
                        "before shipping or in CI to catch a weak/regressed agent prompt. 0 API."),
        "inputSchema": {
            "type": "object",
            "properties": {"system_prompt": {"type": "string", "description": "the agent system prompt to score"}},
            "required": ["system_prompt"],
        },
    },
    {
        "name": "tool_check",
        "description": ("Assess a proposed agent TOOL/FUNCTION CALL before you run it. Given the tool name and "
                        "its arguments, returns allow | flag | block so you can gate irreversible or exfiltrating "
                        "actions — destructive names (delete_all/wipe/drop), privilege escalation (grant_admin/sudo), "
                        "exec/shell, SSRF/local-file, sending secrets to an external recipient, unbounded financial "
                        "transfers. Checks the name + argument values. 0 API. Use as a tool-call firewall for any agent."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "the tool/function name being called"},
                "arguments": {"type": "object", "description": "the arguments the agent wants to pass"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "agent_check",
        "description": ("Unified 0-API check across all three surfaces in one call. Provide any of a system "
                        "prompt to score, an untrusted input to firewall, and a proposed tool call to assess; "
                        "returns the worst verdict (allow | flag | block) plus each surface's result under "
                        "'parts'. Use this as the single guard in an agent loop."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "system_prompt": {"type": "string", "description": "an agent system prompt to score (optional)"},
                "input": {"type": "string", "description": "an untrusted input to firewall (optional)"},
                "tool_call": {"type": "object", "description": "a proposed tool call {name, arguments} to assess (optional)"},
            },
        },
    },
]


def _agent_check(args):
    rank = {"allow": 0, "flag": 1, "block": 2}
    parts, verdict = {}, "allow"
    sp = args.get("system_prompt")
    inp = args.get("input")
    tc = args.get("tool_call")
    if sp:
        r = static_analyze(sp)
        parts["scan"] = {"score": r.score, "grade": r.grade, "has_critical": r.has_critical,
                         "findings": [{"id": f.id, "severity": f.sev, "title": f.title} for f in r.findings]}
    if inp:
        v = fw_inspect(inp)
        parts["firewall"] = v.to_dict()
        if rank[v.action] > rank[verdict]:
            verdict = v.action
    if isinstance(tc, dict) and tc.get("name"):
        t = tool_check(tc.get("name", "") or "", tc.get("arguments") or {})
        parts["tool"] = t
        if rank[t["action"]] > rank[verdict]:
            verdict = t["action"]
    return {"ok": verdict == "allow", "verdict": verdict, "parts": parts}


def _tool_text(name, args):
    if name == "firewall_check":
        v = fw_inspect(args.get("input", "") or "")
        return json.dumps(v.to_dict(), ensure_ascii=False)
    if name == "scan_prompt":
        r = static_analyze(args.get("system_prompt", "") or "")
        return json.dumps({"score": r.score, "grade": r.grade, "has_critical": r.has_critical,
                           "findings": [{"id": f.id, "severity": f.sev, "title": f.title} for f in r.findings]},
                          ensure_ascii=False)
    if name == "tool_check":
        return json.dumps(tool_check(args.get("name", "") or "", args.get("arguments") or {}), ensure_ascii=False)
    if name == "agent_check":
        return json.dumps(_agent_check(args), ensure_ascii=False)
    raise KeyError(f"unknown tool: {name}")


def handle(msg):
    """Return a JSON-RPC response dict, or None for notifications."""
    mid = msg.get("id")
    method = msg.get("method")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }}
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            text = _tool_text(name, args)
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}}
        except KeyError as e:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": str(e)}}
        except Exception as e:  # tool failure → isError content, not a protocol error
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}}

    if mid is not None:  # unknown request
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None  # unknown notification


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
