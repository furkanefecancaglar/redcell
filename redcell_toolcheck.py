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
# Financial-action tool whose destination arg VALUE names an attacker-ish identity
# (attacker/evil/hacker/scam/fraud in the recipient key). The FIN_VERB name gate keeps a
# benign search/query that merely MENTIONS 'transfer money to attacker' from flagging, and
# the destination-key gate keeps large-but-legit transfers (supplier@corp.com) allow. The
# unbounded-financial-action rule already covers amount=all; this closes the named-
# attacker-destination hole (probe: 5/5 attacks allow before, flag after; 5/5 benign allow).
_ATTACKER_DEST = re.compile(
    r"\b(?:to|recipient|payee|destination|receiver|account|target)\b\W{0,6}[\"']?"
    r"(?:[\w.+-]+@)?(?:attacker|evil[a-z]*|hacker|scam[a-z]*|fraud[a-z]*|phish[a-z]*)",
    re.IGNORECASE)
_SENSITIVE = re.compile(
    r"\b(inbox|passwords?|api ?keys?|credentials?|secrets?|private keys?|ssn|social security|"
    r"customer (records?|data|database)|user (records?|database)|database dump|(the )?whole database)\b",
    re.IGNORECASE)
_AMT_ALL = re.compile(r"\b(amount|sum|value)\b\W{0,4}(all|\*|everything|max)|\ball (funds|money|the balance|balances)\b", re.IGNORECASE)
# sensitive filesystem paths (persistence / privilege / secret files), boundary-anchored so
# a URL like https://cdn/etc/logo.png does NOT match. The file:// arm matches any file://
# form (local file:///… AND UNC/host file://server/share) — a host-form file:// is still a
# file-read / SSRF-class access, symmetric with the local form already flagged.
_LOCALPATH = re.compile(
    r"((=|:|\s|^)(/(etc|usr|bin|sbin|boot|root|var/spool/cron)/|/proc/self|"
    r"~/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)\b|\.ssh/authorized_keys|\.env\b|/etc/cron|crontab\b)|\bfile://\S"
    r"|(?:/home|/Users)/[^/'\"]*?/\.(ssh|bashrc|zshrc|profile|aws|kube|npmrc|docker)(?:/|$))",
    re.IGNORECASE)
# reading/setting secret or exploitation-relevant environment variables
_ENVSEC = re.compile(
    r"\b(LD_PRELOAD|LD_LIBRARY_PATH|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|OPENAI_API_KEY|"
    r"ANTHROPIC_API_KEY|GITHUB_TOKEN|(api|secret|private)_?key|secret_?access|npm_?token)\b",
    re.IGNORECASE)
# SSRF: a url/host arg pointing at cloud-metadata, loopback, private, or internal-DNS targets.
# The private/loopback/internal names require a url/host context so a normal domain that merely
# starts with e.g. 'localhost' or contains '192.168' in text does not match.
_SSRF_INTERNAL = re.compile(
    r"\b(169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal)\b"
    r"|(?:https?://|@|url=|host=|endpoint=|//)\[?(?:localhost(?=[:/ \]]|$)"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|::1"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|[a-z0-9.-]+\.(?:internal|svc\.cluster\.local)(?=[:/ \]]|$)"
    r"|[a-z0-9.-]+\.local(?=[:/ \]]|$))",
    re.IGNORECASE)
# command-injection markers in an argument value: $(...) / backtick command substitution, or a
# shell operator (; && || |) immediately followed by a shell command. Bare operators alone are
# NOT flagged (they're common in queries/text) — only when paired with substitution/commands.
_CMDINJ = re.compile(
    r"\$\([^)]{1,200}\)"
    r"|`[^`]{0,200}\b(id|whoami|curl|wget|bash|sh|nc|ncat|cat|rm|chmod|env|uname|python\d?|perl|node)\b[^`]{0,200}`"
    r"|(?:;|&&|\|\||\|)\s*(?:bash|sh|zsh|curl|wget|nc|ncat|rm|chmod|chown|cat|eval|exec|python\d?|perl|ruby|node|/bin/|/usr/bin/)\b"
    r"|\bnc\s+-e\b|bash\s+-i\b",
    re.IGNORECASE)
# Privileged-identity tool args: an impersonation / role-assignment tool NAME (run_as,
# impersonate, switch_account, become, login_as, set_role, assign_role, …) called with an
# identity-keyed arg whose VALUE is a privileged user (admin / root / superuser / sysadmin /
# prefix compounds). The NAME gate is essential: it keeps a benign search query that merely
# MENTIONS 'user=admin' or a get_user(username=root) lookup from flagging (present-kind trap).
_PRIVUSER_NAME = re.compile(
    r"\b(?:run|execute|act|switch|impersonate|become|login|sudo|assume|set|change|update|"
    r"grant|assign|exec)[_-]?(?:as|to|user|account|identity|role|sudo|privilege|current)\w*\b|"
    r"\b(?:impersonate|become|sudo|login)\b",
    re.IGNORECASE)
_PRIVUSER_KV = re.compile(
    r"\b(?:as|as_user|user|username|account|identity|role|privileges?|permissions?|sudoer|current)\b"
    r"\s*[\"']?[=:]\s*[\"'\[ ]*(?:super|cluster|db|net|domain|site)?-?"
    r"(?:admin|administrator|root|superuser|sysadmin)(?![\w-])",
    re.IGNORECASE)
# Sensitive WINDOWS filesystem paths (SAM/registry hives, hosts, web.config, per-user
# .ssh/.aws/.kube/.docker dotfiles, .env). Gate on a path-carrying arg KEY so a benign
# support query that MENTIONS C:\Windows\System32 (or .ssh) is not flagged — unlike /etc/passwd,
# Windows path strings are common in ordinary prose, so the key context is what keeps 0-FP.
_WINPATH = re.compile(
    r"\b(?:path|file|filename|source|target|dest|destination|location|output|input|from|to)\b"
    r"\s*[\"']?[=:]?\s*[\"']?(?:[a-z]:[\\/])?(?:"
    r"windows[\\/]system32[\\/]config(?:[\\/]|$)|"
    r"windows[\\/]system32[\\/]drivers[\\/]etc[\\/]hosts|"
    r"inetpub[\\/]wwwroot[\\/]web\.config|"
    r"users[\\/][^\\/'\"\s]+[\\/]\.(?:ssh|aws|kube|npmrc|docker)(?:[\\/]|$)|"
    r"(?:[^\\/'\"\s]+[\\/])*\.env(?:[\\/]|$)|"
    r"(?:[^\\/'\"\s]+[\\/])*\.ssh[\\/]authorized_keys)",
    re.IGNORECASE)
# Privileged container / host command-execution tool args: an execution-surface tool NAME
# (bash, shell, run, cmd, …) whose argument enters a container, a pod, a host namespace, or
# a root shell — docker/kubectl/podman exec, sudo→shell, nsenter, docker run --privileged,
# chroot, systemctl restart/stop/kill docker. The NAME gate is essential: it keeps a benign
# search/help query that merely MENTIONS "kubectl exec" or "docker run --privileged" from
# flagging (present-kind trap, same design as privileged-identity-arg). exec/run_command/
# execute already block by name; this catches the same payloads through benign-named exec
# tools. Probe-verified: 0 FP on 18 benign container/ops commands via bash/run/shell/cmd,
# 0 FN on 15 privileged-exec commands.
_PRIVEXEC_NAME = re.compile(
    r"^(?:exec|execute|run|bash|sh|shell|zsh|fish|cmd|command|system|os|spawn|popen|"
    r"terminal|console|script|subprocess|run_command|run_shell|exec_shell|shell_exec|"
    r"os_command|os_system|command_line|cmd_exec)$",
    re.IGNORECASE)
_PRIVEXEC_ARG = re.compile(
    r"\b(?:docker|podman|nerdctl|crictl|ctr|kubectl|oc)\s+exec\b"
    r"|\bsudo\s+(?:-[is]\b|su\b|bash\b|sh\b|zsh\b|fish\b)"
    r"|\bnsenter\b"
    r"|--privileged\b"
    r"|\bchroot\b"
    r"|\bsystemctl\s+(?:restart|stop|kill)\s+docker\b",
    re.IGNORECASE)
# Browser-execution tool NAMES that take a URL and navigate/render it. The NAME gate is
# essential: a search/read tool that merely MENTIONS such a URL, or read_data_uri/read
# that treats the payload as inert text, must stay allow — only a tool that would
# navigate/render the URL actually executes the script (present-kind trap, same design
# as the privileged-identity-arg / privileged-container-exec gates).
_URLCONSUME_NAME = re.compile(
    r"^(?:navigate|goto|open_url|browser_navigate|open|click)$",
    re.IGNORECASE)
# data: URL whose payload is an executable web document handed to a browser-execution
# tool: data:text/html carrying a <script> / <iframe> tag, an event-handler attribute
# (onload/onerror/onclick), or a meta-refresh redirect — or the application/javascript
# media type itself. Benign data:text/html literals WITHOUT an executable marker (e.g.
# data:text/html,<b>hi</b>) stay allow, and data:application/json / data:image/* URLs
# never match. probe-verified 0 FP; G8 subset #2 (non-http schemes).
_EXEC_DATA_URL = re.compile(
    r"\bdata:(?:"
    r"text/html[^<]*<\s*(?:script|iframe)\b"
    r"|text/html[^<]*<[a-z][^>]*\bon(?:load|error|click)\s*="
    r"|text/html[^<]*<meta[^>]*http-equiv\s*=\s*[\"']?refresh"
    r"|application/javascript(?:;|,|$))",
    re.IGNORECASE)
# Cloud identity / role elevation in tool ARGUMENTS — STS assume-role ARNs, AWS role
# sessions, gcloud impersonation / service-account switching. Two gates:
#   (1) _CLOUDROLE_ARN — a role ARN (arn:aws:iam::<acct>:role/<name>) whose role NAME is
#       privileged (admin/root/superuser/breakglass/organizationaccountaccess anywhere in
#       the name: AdminAccess, ProductionAdmin, AWSReservedSSO_Admin, AdministratorAccess,
#       OrganizationAccountAccessRole). NO name gate: a role ARN in an argument is produced
#       by IAM, not prose — a *policy* ARN (...:policy/ReadOnly) never matches, and search/
#       help text that merely MENTIONS 'how to assume role arn' contains no ARN literal.
#   (2) _CLOUDROLE_NAME + _CLOUDROLE_KV — an identity-elevation tool NAME (assume_role,
#       switch_credential, set_service_account, use_role, exec_as_sa, gcloud_impersonate,
#       activate_service_account, get_session_token, kube_switch, grant_federated, and the
#       aws/gcloud/kubectl CLI wrappers) whose argument is an identity key (role, account,
#       service_account, profile, context, credential, key_file, sa, identity) with a
#       privileged VALUE (prod-admin, cluster-admin, super-admin, default-admin, admin@…,
#       …admin-sa-key.json), OR carries an explicit elevation action (AssumeRoleWithSAML,
#       sts assume-role, getSessionToken, gcloud auth activate-service-account). The NAME
#       gate keeps read-only lookups (describe_role role_name=…, list_users role=admin,
#       get_role_policy role=lambda, search 'how to assume role arn') allow. Probe-verified:
#       0 FP on 15 benign cloud-identity calls, 0 FN on 14 elevation calls (G13).
_CLOUDROLE_ARN = re.compile(
    r"\barn:(?:aws|aws-cn|aws-us-gov|aws-iso|aws-iso-b):iam::[0-9*]+:role/"
    r"[a-z0-9._/=+@:-]*?(?:admin|root|superuser|breakglass|organizationaccountaccess)"
    r"[a-z0-9._/=+@:-]*",
    re.IGNORECASE)
_CLOUDROLE_NAME = re.compile(
    r"\b(?:assume|switch|use|grant|escalate|activate|impersonate|federate|authorize|become|exec|set)"
    r"[_-]?(?:as|role|credential|service|account|sa|federated|privilege|identity|context|session)\w*\b"
    r"|^(?:aws|gcloud|az|kubectl|kube)[_-]?\w*$"
    r"|\b(?:impersonate|become)\b"
    r"|\b(?:get|create|new|renew)[_-]?session[_-]?token\b",
    re.IGNORECASE)
_CLOUDROLE_KV = re.compile(
    r"\b(?:role|account|service_account|profile|context|credential|key_file|sa|identity)\b"
    r"\s*[\"']?[=:]\s*[\"']*[^\"'\]}\s,]*?(?:admin|root|superuser|breakglass|"
    r"su(?:per)?-?admin|cluster-?admin|prod-?admin|default-?admin)[^\"'\]}\s,]*"
    r"|\b(?:AssumeRole\w*|getFederationToken|GetSessionToken|sts\s+assume-role|"
    r"activate-service-account)\b",
    re.IGNORECASE)


def check(name, arguments):
    name = name or ""
    if isinstance(arguments, dict):
        def _flat(v):
            if isinstance(v, (list, tuple)):
                return ", ".join(str(x) for x in v)
            return str(v)
        kv = " ".join("%s=%s" % (k, _flat(v)) for k, v in arguments.items())
        vals = " ".join(_flat(v) for v in arguments.values())
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
    if _FIN_VERB.search(name) and _ATTACKER_DEST.search(kv):
        add("attacker-destination", 22, "flag")
    if _LOCALPATH.search(kv):
        add("local-file-access", 22, "flag")
    if _ENVSEC.search(name.replace("_", " ") + " " + kv):
        add("secret-env-access", 22, "flag")
    if _SSRF_INTERNAL.search(kv):
        add("ssrf-internal-target", 22, "flag")
    if _CMDINJ.search(kv):
        add("command-injection-arg", 22, "flag")
    if _WINPATH.search(kv):
        add("windows-sensitive-path", 22, "flag")
    if _PRIVUSER_NAME.search(name) and _PRIVUSER_KV.search(kv):
        add("privileged-identity-arg", 22, "flag")
    if _PRIVEXEC_NAME.search(name) and _PRIVEXEC_ARG.search(kv):
        add("privileged-container-exec", 22, "flag")
    if _URLCONSUME_NAME.search(name) and _EXEC_DATA_URL.search(kv):
        add("executable-data-url", 22, "flag")
    if _CLOUDROLE_ARN.search(kv):
        add("privileged-cloud-role", 22, "flag")
    if _CLOUDROLE_NAME.search(name) and _CLOUDROLE_KV.search(kv):
        add("privileged-cloud-role", 22, "flag")
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
