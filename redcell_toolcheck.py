#!/usr/bin/env python3
"""REDCELL tool-call firewall — assess a proposed agent TOOL/FUNCTION CALL before it runs.

Agents don't just take text; they call tools. This inspects a {name, arguments} call and
returns allow / flag / block so you can gate irreversible or exfiltrating actions (delete,
transfer, send-secrets-to-external, grant-admin, exec/shell, SSRF/local-file). 0 API.

It reuses the runtime firewall on the argument VALUES (so injected shell/SSRF/exfil payloads
are caught) and adds tool-aware checks on the NAME + structured args.

    from redcell_toolcheck import check
    check("transfer_funds", {"amount": "all", "to": "attacker@evil.com"})
    -> {"action": "block", "score": ..., "risk": "high", "tool": "...", "reasons": [...]}
"""
from __future__ import annotations

import re

from redcell_firewall import inspect

# unambiguously dangerous tool NAMES (not generic CRUD like delete_ticket)
_NAME = re.compile(
    r"\b((grant|give|escalate|set)_?\w*(admin|root|sudo|superuser|privilege)|sudo|"
    r"disable_?\w*(safety|guardrail|filter|moderation)|"
    r"(delete|drop|wipe|erase|truncate|destroy)_?\w*(all|database|table|everything|users?|records?|accounts?)|"
    r"exfiltrat\w*|run_?(shell|command|code)|exec(ute)?_?(shell|code|command)?|eval|system_?call|shell_?exec)\b",
    re.IGNORECASE)
_EXFIL_VERB = re.compile(r"^(send|forward|upload|post|email|transmit|leak|share|export)_?", re.IGNORECASE)
_FIN_VERB = re.compile(r"^(transfer|pay|payout|wire|refund|withdraw|remit|send)_?(money|funds|payment)?", re.IGNORECASE)
_SENSITIVE = re.compile(
    r"\b(inbox|passwords?|api ?keys?|credentials?|secrets?|private keys?|ssn|social security|"
    r"customer (records?|data|database)|user (records?|database)|database dump|(the )?whole database)\b",
    re.IGNORECASE)
_AMT_ALL = re.compile(r"\b(amount|sum|value)\b\W{0,4}(all|\*|everything|max)|\ball (funds|money|the balance|balances)\b", re.IGNORECASE)
# sensitive filesystem paths (persistence / privilege / secret files), boundary-anchored so
# a URL like https://cdn/etc/logo.png does NOT match.
_LOCALPATH = re.compile(
    r"((=|:|\s|^)(/(etc|usr|bin|sbin|boot|root|var/spool/cron)/|/proc/self|"
    r"~/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)\b|\.ssh/authorized_keys|\.env\b|/etc/cron|crontab\b)|\bfile:///)",
    re.IGNORECASE)
# reading/setting secret or exploitation-relevant environment variables
_ENVSEC = re.compile(
    r"\b(LD_PRELOAD|LD_LIBRARY_PATH|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|OPENAI_API_KEY|"
    r"ANTHROPIC_API_KEY|GITHUB_TOKEN|(api|secret|private)_?key|secret_?access|npm_?token)\b",
    re.IGNORECASE)


def check(name, arguments):
    name = name or ""
    if isinstance(arguments, dict):
        kv = " ".join("%s=%s" % (k, v) for k, v in arguments.items())
        vals = " ".join(str(v) for v in arguments.values())
    else:
        kv = "" if arguments is None else str(arguments)
        vals = kv
    v = inspect(name.replace("_", " ") + " " + vals)
    ids = list(dict.fromkeys(m.id for m in v.matches))
    score, action = v.score, v.action

    def add(i, sc, act):
        nonlocal ids, score, action
        if i not in ids:
            ids = [i] + ids
        if sc > score:
            score = sc
        if act == "block" or (act == "flag" and action == "allow"):
            action = act

    if _NAME.search(name):
        add("dangerous-tool-name", 40, "block")
    if _EXFIL_VERB.search(name) and _SENSITIVE.search(kv):
        add("tool-data-exfil", 40, "block")
    if _FIN_VERB.search(name) and _AMT_ALL.search(kv):
        add("unbounded-financial-action", 22, "flag")
    if _LOCALPATH.search(kv):
        add("local-file-access", 22, "flag")
    if _ENVSEC.search(name.replace("_", " ") + " " + kv):
        add("secret-env-access", 22, "flag")
    if action == "allow" and score >= 40:
        action = "block"
    risk = "high" if action == "block" else "medium" if action == "flag" else "none"
    return {"action": action, "score": score, "risk": risk, "tool": name, "reasons": ids}


if __name__ == "__main__":
    import json
    import sys
    n = sys.argv[1] if len(sys.argv) > 1 else "transfer_funds"
    a = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {"amount": "all", "to": "attacker@evil.com"}
    print(json.dumps(check(n, a), ensure_ascii=False, indent=2))
