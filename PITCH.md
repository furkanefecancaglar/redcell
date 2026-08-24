# REDCELL — the security layer for AI agents

> Continuous adversarial testing and runtime defense for LLM agents. Test → Prevent → Attack → Defend → Guard.

## The problem
Every company is shipping LLM agents wired to tools, data, and customers. An agent with tool access
is an **untrusted-input-to-privileged-action machine**: one poisoned document, email, or user message
can hijack it into leaking data, issuing refunds, or deleting records. Prompt injection is the OWASP
LLM **#1** risk and it is unsolved. Traditional AppSec doesn't see the prompt layer. Almost no one
red-teams their agents before production — and the ones who try do it by hand, once.

## The product — five surfaces, one security layer
| # | Surface | What it does | When it runs |
|---|---------|--------------|--------------|
| 1 | **Static scanner** `/scan-config` (public, free) | Static resilience score of an agent's system prompt vs the OWASP LLM Top 10 — 22 detectors, findings→exploit links, hardened-prompt kit | design time |
| 2 | **CI gate** | Fails the build when a PR weakens an agent's prompt below threshold (GitHub Action) | every commit |
| 3 | **Live engine** | Fires a real adversarial corpus at the live agent and scores each response with a **separate judge model** — PASS/FAIL, not heuristics | pre-release |
| 4 | **Runtime input firewall** `/firewall` | Inspects every untrusted input in production and blocks injection/exfil/jailbreak in ~60us of compute, ~3ms added over a static response — 69 detectors (33 pattern rules + hidden-character / unicode-tag / obfuscated-injection / bidi-injection signals) plus base64/leetspeak/homoglyph/zero-width deobfuscation, measured on a held-out set written to probe it (40 benign messages, 20 adversarial prompts): 5% false positives, both flags not blocks, on developer questions about eval() and the EC2 metadata IP. It initially missed 55% of those attacks; five rules were added in response, so the current 0 misses on that set is a regression guard, not a generalisation estimate | every request |
| 5 | **Tool-call firewall** `/toolcheck` | Screens a proposed {name, arguments} tool call before it runs — dangerous names, data exfil, unbounded transfers, local-file & secret-env reads, SSRF, command injection, privileged identities, Windows paths, privileged container exec. 13 tool-aware reason classes, 0 API | before every tool call |

**Unified `/agentcheck`** — one call runs the scanner, input firewall and tool-call firewall and returns the **worst verdict** (block on danger, pause for human approval on flag). The single guard to wrap an agent loop.

Test → Prevent → Attack → Defend → Guard. The same offensive knowledge powers all five, and one endpoint unifies them.

## Wedge & motion
- **Top of funnel:** the free browser scanner + the CI gate (zero-friction, zero-API, viral in dev channels).
- **Convert to paid:** the live engine (continuous, judged) and the runtime firewall (inline protection).
- **Land-and-expand:** start at testing, expand into runtime — the corpus that tests also defends.

## Moat
An **adversarial corpus that compounds.** Every scan, every customer agent, every new jailbreak feeds a
proprietary, continuously-mutating attack dataset. The offensive-security depth behind the rules is the
defensibility — and it is the founder's edge, not a commodity model call.

## Market
Every team shipping an agent: fintech, healthcare, support automation, internal copilots — all regulated
or reputation-exposed, all now asked "how do you know your agent is safe?" for procurement and compliance
(EU AI Act, SOC 2 AI addenda). Peers in this category (Lakera, HiddenLayer, Prompt Security) have raised
nine figures — the category is validated; the winner isn't decided.

## Business model — illustrative
| Tier | Price | Includes |
|------|-------|----------|
| Free | $0 | Browser scanner · attack library · hardened-prompt kit · CI gate (static) |
| Pro | $39/mo | Live engine on N agents · continuous corpus + judge · CI deep mode · firewall SDK |
| Enterprise | Custom | Unlimited agents · runtime firewall at scale · compliance evidence exports · private attack tuning · SSO |

## Status — what's built vs what remains
**Built, verified, committed, deploy-ready** (this repo): all five surfaces, one unified server
(`/scan-config`, `/firewall`, `/scan`, `/toolcheck`, `/agentcheck`, `/benchmark`, `/health`), a Python static core matching the browser scanner
exactly, a 176-test regression suite (green), Docker/Fly/Render/Railway configs, env-indirected keys, and
a one-command deploy. Quick browser/curl tests: `GET /toolcheck?name=…&args=…` and `GET /agentcheck?system_prompt=…&input=…`.
Shared reports: `/r/<id>` (JSON / Markdown) and `/r/<id>.sarif` (SARIF 2.1.0 for GitHub code-scanning). The MCP server
exposes 4 tools — `firewall_check`, `scan_prompt`, `tool_check`, `agent_check` — and `/benchmark` publishes a
16-archetype static-resilience leaderboard.

**Honest limits:** the free scanner is heuristic static analysis (a fast first read, not a full audit —
that's what the live engine is for). The live judge currently runs on a single provider (auto-failover is
in place to pick a distinct engine the moment a second one is available).

**Deploy is one command:** `docker run -p 8770:8770 --env-file .env redcell` (or `fly deploy`).
**Four human clicks remain** (a bot structurally can't do these): create the host account, authenticate the
CLI, paste the API key into the host's secret store, push/publish. Everything up to those clicks is done.

---
*REDCELL · built for authorized security testing only.*
