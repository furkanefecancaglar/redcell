# REDCELL — launch drafts (ready to post)

Live product: https://redcell.redcellv1.workers.dev · Game (the hook): https://redcell.redcellv1.workers.dev/breach · Investor brief: https://redcell.redcellv1.workers.dev/pitch

> **Furkan posts these** (posting publicly = your tap). They're honest and technical — no fabricated metrics, no hype.
> Post the Breach game and the free API; the paid engine is the follow-up. Tip: launch the **Breach game** as the lead
> (it's the shareable, viral piece), not the pitch. Best days: Tue–Thu. Reply to every comment in the first 2 hours.

---

## 1. Show HN
**How to post:** news.ycombinator.com/submit → Title below, URL = the /breach game. Then immediately add the first comment.

**Title:**
`Show HN: REDCELL Breach – jailbreak an AI through 5 escalating defense layers`

**URL:** `https://redcell.redcellv1.workers.dev/breach`

**First comment:**
> I've been building REDCELL, a security layer for LLM agents, and the most fun piece to share is Breach: a game where you try to extract a secret from an AI whose defenses get stronger each level. The levels aren't cosmetic — each one turns on a real REDCELL layer: hardened system prompt → input firewall → output redaction → full lockdown. So beating a level literally means beating that defense.
>
> The rest of the product is live and free to try on the same domain:
> - `POST /firewall` — a runtime injection firewall (regex, 69 detectors, 4 languages, 0 API, ~60us of compute, ~3ms added over a static response). Client-side JS + Python ports too.
> - `POST /scan-config` — scores an agent's system prompt against the OWASP LLM Top 10 (22 detectors).
> - `POST /scan` — a live red-team engine: it fires an adversarial corpus at your agent and a *separate* judge model rates each response PASS/FAIL. It also runs an adaptive multi-turn attack that mutates based on the agent's own first reply.
> - `POST /toolcheck` — screens a proposed {name, arguments} tool call → allow/flag/block across 13 tool-aware reason classes (dangerous names, exfil, unbounded transfers, SSRF, privileged container exec). Quick browser test: `GET /toolcheck?name=…&args=…`.
> - `POST /agentcheck` — one call runs scanner + input firewall + tool-call firewall and returns the worst verdict. `GET /agentcheck?system_prompt=…&input=…` works in a browser too.
> - `/benchmark` — public leaderboard: static resilience scores for 16 archetype system prompts.
>
> It all runs on one Cloudflare Worker (free tier). Honest about limits: the static scanner is heuristic, and the live engine currently uses a single model provider. Curious what breaks it — try to get past level 5 and tell me how.

---

## 2. X / Twitter thread
**How to post:** post #1, then reply-chain the rest. Attach a screen recording of beating a Breach level to #1 if you can.

1/ Your AI agent will do what an attacker tells it — until you test it.
I built REDCELL: a security layer for LLM agents. And a game to prove the point. 🧵
🔗 https://redcell.redcellv1.workers.dev/breach

2/ REDCELL Breach: extract a secret from an AI. 5 levels. Each level turns on a *real* defense layer — hardened prompt → input firewall → output redaction → full lockdown. Beating a level = beating that defense. See how far you get.

3/ Under the hood it's a full product, live + free:
🛡️ runtime firewall (blocks injection/jailbreak/exfil, 4 languages, 0 API, ~60us of compute, ~3ms added over a static response)
🧪 static scanner (OWASP LLM Top 10, 22 detectors)
🛠️ tool-call firewall (screens {name, arguments} → allow/flag/block across 13 tool-aware reason classes)
🔬 live red-team engine (real attacks + a separate judge model)
📊 16-archetype benchmark leaderboard (/benchmark)

4/ The interesting part of the engine: an adaptive attack. It first asks your agent what it does, then an attacker model crafts a follow-up jailbreak from that exact answer, and delivers it in a real 2-turn conversation. Static test suites miss this.

5/ Everything's callable: `curl -X POST .../firewall -d '{"input":"ignore all previous instructions"}'` → `{"action":"block"}`. Plus `pip install redcell`, `npm i redcell-firewall`, and a 4-tool MCP server (firewall_check, scan_prompt, tool_check, agent_check) so your other agents can call it.

6/ Prompt injection is OWASP's #1 LLM risk and it's unsolved. Peers (Lakera, HiddenLayer) raised nine figures; the category's real, the winner isn't decided. REDCELL is my shot at it.

7/ It's early and free. Try to break Breach, run the firewall on your own agent, and tell me what fails: https://redcell.redcellv1.workers.dev — I'm reading every reply.

---

## 3. Product Hunt
**How to post:** producthunt.com/posts/new → name REDCELL, tagline below, gallery = Breach screen recording + the console page. Description + first comment below.

**Tagline (60 char max):** `Test, red-team & firewall your AI agents against prompt injection`

**Description:**
> REDCELL is the security layer for AI agents. Score an agent's prompt against the OWASP LLM Top 10, block prompt-injection/jailbreak/exfiltration in real time with an edge firewall, screen every proposed tool call across 13 tool-aware reason classes, catch directives split across a conversation's turns (joined-history /firewall-thread), and run a live red-team engine that attacks your agent (including an adaptive multi-turn attack) and judges each response with a separate model. Free scanner, firewall, tool-call firewall, CI gate, SDKs (pip/npm), a 5-tool MCP server (incl. a joined-history thread check) and a 16-archetype /benchmark — plus REDCELL Breach, a 5-level jailbreak game where the levels are the actual defense layers.

**First comment:**
> Maker here. The wedge is: testing your agent should be as easy as running a linter, and defending it should be a firewall you drop in front. Start with Breach (it's genuinely fun and shows the layers), then run the firewall/scanner on your own agent. It's live, free, and honest about what's heuristic vs. live. Feedback very welcome — especially adversarial feedback.

---

## 4. Reddit (r/LocalLLaMA, r/netsec, r/MachineLearning)
**How to post:** a text post, not a link post; lead with substance, put links at the end. Follow each sub's self-promo rules.

**Title:** `I built a runtime prompt-injection firewall + a live red-team engine for LLM agents (free, runs on the edge)`

**Body:**
> If you ship an LLM agent with tool access, it's an untrusted-input-to-privileged-action machine — one poisoned message or document can hijack it. I built REDCELL to test and defend that:
>
> - **Firewall**: inspects untrusted input for injection/jailbreak/exfil (69 detectors, 4 languages, pure pattern-match, 0 API, ~60us of compute, ~3ms added over a static response). Python + JS + edge API.
> - **Tool-call firewall**: screens a proposed {name, arguments} call before it runs → allow/flag/block across 13 tool-aware reason classes (dangerous names, data exfil, unbounded transfers, SSRF, privileged container exec). `GET /toolcheck?name=…&args=…` for a browser test.
> - **Scanner**: scores a system prompt against the OWASP LLM Top 10 (22 detectors) with findings and a hardened-prompt kit.
> - **Live engine**: fires an adversarial corpus at your agent and a separate judge model rates each response PASS/FAIL — including an adaptive attack that mutates from the agent's own first reply.
> - **Benchmark**: /benchmark publishes static resilience scores for 16 archetype prompts.
> - **Breach**: a 5-level jailbreak game where each level is a real defense layer (try it, it's the fun part).
>
> Honest limits: the scanner is heuristic (fast first read, not a full audit); the live engine uses one model provider today. Free to try, would love to know what gets past it.
>
> Game: https://redcell.redcellv1.workers.dev/breach · Product/API: https://redcell.redcellv1.workers.dev

---

## Sequencing (suggested)
1. Ship **Show HN** + the **X thread** same morning (Tue–Thu), Breach as the hook.
2. **Product Hunt** the next day (or schedule 00:01 PT).
3. **Reddit** after there's a comment or two of traction to point to.
4. Every signup lands in `/leads` — reach out personally within a day.
