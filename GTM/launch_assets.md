# REDCELL — Launch Assets (ready to fire)
URL: https://redcell.redcellv1.workers.dev  ·  Deterministic surfaces are free, 0-API, no signup.
Owner action = post / send these. Drafted end-to-end. Never post as anyone but yourself.

**Accuracy note:** every number in this file is checked against /health and the test suite by
`tools/doc_check.mjs`, which now sweeps GTM/. It did not before, which is why this file
previously claimed 37 detectors and 188 tests for weeks after both were fixed elsewhere. Re-run
`./tools/verify.sh` before posting any of it.

**Since this was first drafted, three things are worth leading with and were missing:**
- **MCP over HTTP** — adding REDCELL to an agent is now a URL, not a vendored file plus a config
  path: POST https://redcell.redcellv1.workers.dev/mcp, JSON-RPC 2.0, protocol 2024-11-05, five tools.
- **A CI gate** — POST /gate returns HTTP 422 when a prompt scores below `min_score` and 200 when
  it passes, so the HTTP status alone fails a build. One curl, no SDK.
- **A paid tier at $39/mo** — scan history, SARIF export and the live red-team engine. Everything
  deterministic stays free and unauthenticated. Say this plainly; do not imply the whole thing is free.
Lead angle: **prompt injection is the entry, tool abuse is the impact.** The differentiator
vs prompt-only tools = the agent-native tool-call firewall + one unified /agentcheck.

---
## 0) Elevator pitch (3 lines)
REDCELL is the security layer for AI agents. A chatbot that's jailbroken says something bad;
an agent that's jailbroken *does* something bad — it has tools. REDCELL is a 0-API,
deterministic firewall that guards all three stages: the system prompt, the untrusted input,
and the tool call itself — one call, at the edge, no key.

---
## 1) Show HN
Title: Show HN: REDCELL – a 0-API firewall for AI agents (guards the tool call, not just the prompt)

Text:
Most prompt-injection tools stop at the input. But the damage from a jailbroken *agent* happens one step later — when it calls a tool: transfer funds, delete records, email secrets out, fetch an internal metadata URL, grant itself admin. REDCELL guards all three stages, 0-API, at the edge, no signup:

- Input firewall (POST /firewall) — 51 detectors across the OWASP LLM Top 10, plus deobfuscation: de-leetspeaks, base64/url-safe/nested-decodes, folds Cyrillic/Greek homoglyphs, strips zero-width, decodes invisible Unicode-tag "ASCII smuggling". Optional 0-API semantic layer catches paraphrases with no keyword overlap.
- Prompt scanner (POST /scan-config) — score a system prompt 0–100 against 22 checks; get a copy-paste hardened-prompt kit + projected score.
- Tool-call firewall (POST /toolcheck) — the agent-native part: give it {name, arguments} and it returns allow/flag/block across 13 tool-aware reason classes: destructive tool names, secret/record exfil, unbounded money transfers, sensitive-file writes (~/.ssh, /etc, .env), secret-env reads (AWS/OPENAI keys), SSRF to internal/metadata hosts (169.254.169.254, localhost, 10.x, *.svc.cluster.local), command injection, privileged identities (run_as/impersonate → root/admin), Windows sensitive paths (SAM/hosts/web.config/.ssh/.aws), and privileged container exec (docker/kubectl exec, nsenter, --privileged, chroot). `delete_all_users()` → block; `run_as({user:"root"})` → flag [privileged-identity-arg]; `bash({command:"docker exec -it web bash"})` → flag [privileged-container-exec]; `read_file({path:"C:\Windows\System32\config\SAM"})` → flag [windows-sensitive-path]; `fetch({url:"http://169.254.169.254/..."})` → flag; `get_balance({account_id})` → allow. Measured on a held-out benign corpus: 5% flag rate, no blocks.
- One middleware for all of it (POST /agentcheck) — wrap your agent loop once: firewall every input, check every proposed tool call, get one verdict. Copy-paste JS in /quickstart. Quick browser tests: GET /toolcheck?name=…&args=… and GET /agentcheck?system_prompt=…&input=….
- One call for all three: POST /agentcheck {system_prompt?, input?, tool_call?} → worst verdict + per-surface breakdown.

Deterministic (regex/policy, not a model) → fast, private (text never leaves the edge), explainable (every verdict names the rule). Python↔JS engines are byte-for-byte identical, locked by an automated parity test; 220 tests incl. fuzz + a self-regression suite that runs the firewall on a real-attack corpus. Vendorable as single 0-dependency files, a 5-tool MCP server, a GitHub Action; reports export as JSON / Markdown / SARIF (/r/<id> and /r/<id>.sarif).

Honest about limits: it's the fast deterministic layer, not a replacement for a model-based classifier or human red-teaming — /methodology and /vs say so plainly. The *live* red-team engine (the paid one) is separately caveated: re-running one identical prompt has produced scores 49 to 80, a 31-point spread, so the report ships that spread alongside the number and the deterministic surfaces are where the reproducible value is. Lead with the deterministic engines; do not sell the score as precise.

Live: https://redcell.redcellv1.workers.dev  ·  Attack chain + how each stage is defended: /agents  ·  Worked example (real engine output): /example  ·  16-archetype resilience leaderboard: /benchmark

Happy to talk detection approach, the deobfuscation pre-pass, or the tool-call risk model.

---
## 2) Reddit — r/LocalLLaMA
Title: I built a 0-API firewall for AI agents that also checks the *tool call*, not just the prompt

Body:
If you're giving a local agent real tools (delete, transfer, send, fetch, shell), the risky moment isn't the prompt — it's the tool call the jailbroken agent makes. REDCELL is a free, no-signup firewall that guards three stages: input (51 detectors + deobfuscation of base64/leetspeak/homoglyph/zero-width/bidi/unicode-tag, and an optional semantic layer for paraphrases), the system prompt (22-check scanner + hardened-prompt kit), and the tool call itself — POST /toolcheck {name, arguments} → allow/flag/block. `delete_all_users()` → block; `run_as({user:"root"})` → flag [privileged-identity-arg]; `bash({command:"docker exec -it web bash"})` → flag [privileged-container-exec]; `read_file({path:"C:\Windows\System32\config\SAM"})` → flag [windows-sensitive-path]; `transfer_funds({amount:"all"})` → flag; `get_balance` → allow.
Runs at Cloudflare's edge, deterministic, vendorable as single 0-dep files + a 5-tool MCP server. Try it: https://redcell.redcellv1.workers.dev  ·  Threat model: /agents
Feedback on false-positives/negatives very welcome — there's a Breach game to try to beat it.

---
## 3) Reddit — r/netsec
Title: REDCELL: deterministic 0-API firewall for LLM agents — input deobfuscation + a tool-call risk layer

Body:
For the agent-security angle:
- Input firewall with a deobfuscation pre-pass: normalizes into multiple views (leet fold, homoglyph fold, zero-width strip, base64 std/url-safe/one-nested decode, Unicode-tag U+E0000–E007F decode) and re-runs the rule set, so obfuscated injections with no literal keyword overlap are still caught. Optional 0-API lexical semantic layer for paraphrase escalation.
- Tool-call firewall (/toolcheck): assesses {name, arguments} across 13 tool-aware reason classes — destructive names, privileged identities (run_as/impersonate → root/admin), exec/shell, privileged container exec (docker/kubectl exec, nsenter, --privileged, chroot), SSRF/local-file, Windows sensitive paths (SAM/hosts/web.config/.ssh/.aws), secret-env reads, command injection, secret-exfil, unbounded financial transfers — probed to 0 FP on a benign tool-call corpus.
- Unified /agentcheck runs all three surfaces in one call.
- ReDoS-audited (bounded quantifiers, 16 KB cap). Python↔JS engines byte-for-byte identical, enforced by an automated parity test; 220 tests incl. fuzz + self-regression corpus. SARIF export for code-scanning (/r/<id>.sarif). 0-API, edge-hosted, vendorable, 5-tool MCP server (firewall_check, thread_check, scan_prompt, tool_check, agent_check).
Honest scope: deterministic layer, complements a model classifier — /methodology + /vs.
Live: https://redcell.redcellv1.workers.dev

---
## 4) X / Twitter thread
1/ A jailbroken chatbot says something bad. A jailbroken *agent* does something bad — it has tools.
REDCELL is a 0-API firewall that guards the tool call, not just the prompt. Free, edge, no signup: https://redcell.redcellv1.workers.dev

2/ The dangerous moment is the tool call. Give REDCELL {name, arguments}:
• delete_all_users() → BLOCK
• run_as({user:"root"}) → FLAG [privileged-identity-arg]
• bash({command:"docker exec -it web bash"}) → FLAG [privileged-container-exec]
• read_file({path:"C:\Windows\System32\config\SAM"}) → FLAG [windows-sensitive-path]
• transfer_funds({amount:"all"}) → FLAG
• fetch(url: http://169.254.169.254/...) → FLAG (SSRF to metadata)
• read_env(AWS_SECRET_ACCESS_KEY) → FLAG
• get_balance({account_id}) → ALLOW
Measured on a held-out benign corpus: 5% flag rate, no blocks.

3/ It also firewalls the input (51 detectors + deobfuscation: base64/leetspeak/homoglyph/zero-width/bidi/invisible-unicode, + optional semantic for paraphrases) and scores your system prompt (22 checks + a hardened-prompt kit).

4/ One call for all three: POST /agentcheck {system_prompt?, input?, tool_call?} → one verdict. Deterministic, private (text never leaves the edge), explainable. Also a 5-tool MCP server + GitHub Action + SARIF export.

5/ Prompt injection is the entry. Tool abuse is the impact. See the attack chain mapped to each defense: /agents
Honest about limits (/methodology, /vs). Beat it: /breach

---
## 5) Product Hunt
Tagline (≤60 chars): The security layer for AI agents — guard the tool call
Alt tagline: Firewall your agent's prompt, input, AND tool calls. 0-API.
Description:
REDCELL is a 0-API, deterministic firewall for LLM agents. Prompt-only tools stop at the input; REDCELL also checks the tool call — transfer, delete, send-secrets, fetch-internal-URL, grant-admin — and returns allow/flag/block before it runs. It firewalls untrusted input (51 detectors + deobfuscation of base64/leetspeak/homoglyph/zero-width/bidi/unicode-tag, + optional semantic), scores your system prompt (22 checks + a hardened-prompt kit), and unifies all three in one /agentcheck call. New: a joined-history pass (/firewall-thread + MCP thread_check) catches a directive split across a conversation's turns. Runs at the edge, no signup, no key. Vendorable single files + a 5-tool MCP server + GitHub Action; SARIF/JSON/Markdown export. Fast, private, explainable — the deterministic layer that complements a model classifier.
First comment (maker): Built this because giving agents real tools is the new attack surface — prompt injection is the entry, tool abuse is the impact. Everything's free and 0-API; would love feedback on the tool-call risk model.

---
## 6) REDCELL vs prompt-only firewalls (honest comparison paragraph)
Most LLM-security tools focus on the input: detect the prompt injection or jailbreak before it reaches the model. That's necessary but not sufficient for agents. An agent's blast radius is its tools, and an injection that slips through (novel phrasing, a trusted-looking retrieved doc) only matters if the resulting tool call does damage. REDCELL adds that missing layer — a deterministic check on the tool call itself ({name, arguments} → allow/flag/block) — and unifies prompt-scan + input-firewall + tool-check in one call. The tool-check spans 13 tool-aware reason classes — destructive actions, secret/record exfil, unbounded transfers, sensitive-file writes, secret-env reads, SSRF to internal/metadata hosts, command injection, privileged identities (run_as/impersonate → root/admin), Windows sensitive paths (SAM/hosts/web.config/.ssh/.aws), and privileged container exec (docker/kubectl exec, nsenter, --privileged, chroot). It's deterministic and 0-API by design (fast, private, explainable, free), which makes it a complement to, not a replacement for, model-based classifiers: run REDCELL as the cheap first pass and CI gate, add a model layer for the semantic long tail. (No claims here about any specific competitor's internals — this is about the category.)

---
## 7) Cold email — design partner (AI-agent teams)
Subject: free tool-call firewall for <company>'s agent (0-API, 5-min setup)

Hi <name>,
You're shipping <product/agent> — which means it can take real actions via tools. The risky moment isn't the prompt, it's the tool call a jailbroken agent makes (transfer, delete, send-data-out). I built REDCELL: a 0-API firewall that checks the input, the system prompt, AND the tool call, returning allow/flag/block before anything runs. No signup: https://redcell.redcellv1.workers.dev/quickstart
I'm onboarding a few design partners — I'll run a free review against your agent (prompt + a sample of its tool calls) and hand you a report + hardened-prompt kit, for feedback. 15 minutes?
— Furkan

## 8) Cold email — pre-seed investor (only when there's real early traction)
Subject: REDCELL — the security layer for AI agents (agent-native, early traction)

Hi <name>,
Agents are getting production tool access; prompt injection is the new RCE and the damage lands at the tool call. REDCELL is a deterministic, 0-API firewall + scanner for LLM agents — live and free — that most tools don't cover: it checks the tool call, not just the prompt, and unifies prompt/input/tool in one /agentcheck. Vendorable + a 5-tool MCP server; every Breach-game attempt compounds a proprietary attack dataset.
<one line of REAL traction: N users / M firewall+tool checks / K reports — leave blank until real>
Raising a pre-seed to turn the free developer wedge into an agent-runtime security platform. 20 minutes?
— Furkan
