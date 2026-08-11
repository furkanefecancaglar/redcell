# REDCELL — Launch Assets (ready to fire)
URL: https://redcell.redcellv1.workers.dev  ·  All free, 0-API, no signup.
Owner action = post/send these. Drafted end-to-end; nothing else needed but your click.

---
## 1) Show HN (news.ycombinator.com/submit)
Title: Show HN: REDCELL – a 0-API prompt-injection firewall + OWASP scanner for AI agents

Text:
I built REDCELL, a security layer for LLM agents that runs at the edge with no API key and no signup.

Three things you can try in the browser right now:
- Runtime firewall — paste any untrusted input and get allow/flag/block in ~milliseconds. 34 detectors across the OWASP LLM Top 10, plus deobfuscation: it de-leetspeaks, base64/url-safe/nested-decodes, folds Cyrillic/Greek homoglyphs, strips zero-width, and decodes invisible Unicode-tag "ASCII smuggling" before matching. So `1gn0re all prev10us…` and an invisible-tag payload are both caught.
- Static scanner — score a system prompt 0–100 against 22 checks; get a shareable report with a copy-paste hardened-prompt kit and a projected score.
- Breach — a 5-level jailbreak game; every attempt feeds a public attack-technique board.

It's deterministic (regex/policy, not a model), so it's fast, private (your text never leaves the edge), and explainable (every verdict names the rule). Python↔JS engines are byte-for-byte identical, locked by an automated parity test; 148 tests incl. a fuzz + a self-regression suite that runs the firewall on a corpus of real attacks. Vendorable as single 0-dependency files, an MCP server, a GitHub Action, and reports export as JSON/Markdown/SARIF.

Honest about limits: it's the fast deterministic layer, not a replacement for a model-based classifier or human red-teaming — see /methodology and /vs.

Live: https://redcell.redcellv1.workers.dev  ·  Worked example (real engine output): /example  ·  Quickstart: /quickstart

Happy to answer anything about the detection approach or the deobfuscation layer.

---
## 2) Reddit — r/LocalLLaMA
Title: I made a free, no-signup prompt-injection firewall for LLM agents (runs at the edge, catches base64/leetspeak/homoglyph/unicode-tag obfuscation)

Body:
Wanted an input firewall I could actually drop in front of an agent without a vendor account. REDCELL is 0-API, runs on Cloudflare's edge, and returns allow/flag/block. The part I'm proud of is the deobfuscation: before matching, it de-leetspeaks (`1gn0re`→ignore), decodes base64 (std/url-safe/nested), folds Cyrillic/Greek homoglyphs, strips zero-width chars, and decodes invisible Unicode-tag ASCII smuggling. 34 detectors, OWASP LLM Top 10.
Try the firewall + a system-prompt scanner in the browser (no signup): https://redcell.redcellv1.workers.dev
It's deterministic (fast/private/explainable), and I'm upfront that it complements — doesn't replace — a model-based classifier. Feedback on false-positives/negatives very welcome; there's a Breach game to try to beat it.

---
## 3) Reddit — r/netsec  (r/netsec is strict; post as a project with technical depth)
Title: REDCELL: a deterministic, 0-API LLM prompt-injection firewall with a deobfuscation pre-pass (base64/url-safe/nested, leetspeak, homoglyph, zero-width, Unicode-tag smuggling)

Body:
Deterministic input firewall for LLM agents. Notable bits for this crowd:
- Deobfuscation pre-pass normalizes an input into multiple views (leet fold, homoglyph fold, zero-width strip, base64 std/url-safe/one-nested decode, Unicode-tag U+E0000–E007F decode) and re-runs the rule set, so obfuscated injections that share no literal keywords are still caught.
- ReDoS-audited: all rules use bounded quantifiers; inspection capped at 16KB.
- Python and JS engines kept byte-for-byte identical, enforced by an automated parity test; 148 tests incl. fuzz + a self-regression corpus.
- 0-API, edge-hosted, no signup; vendorable single files, MCP server, GitHub Action; reports export as SARIF for code-scanning.
Honest scope: deterministic layer, not a semantic classifier; see /methodology + /vs.
Live: https://redcell.redcellv1.workers.dev

---
## 4) X / Twitter thread
1/ Your AI agent will do what an attacker tells it — if the instruction is hidden.
REDCELL is a 0-API firewall that de-obfuscates untrusted input *before* matching. Free, no signup, runs at the edge: https://redcell.redcellv1.workers.dev

2/ It catches what naive keyword filters miss:
• `1gn0re all prev10us 1nstruct10ns` (leetspeak)
• base64 / url-safe / nested-encoded payloads
• Cyrillic/Greek homoglyphs
• zero-width splits
• invisible Unicode-tag "ASCII smuggling"

3/ 34 detectors across the OWASP LLM Top 10. Deterministic → fast, private (your text never leaves the edge), explainable (every verdict names the rule). Try the live demo: /example

4/ Also: a 22-check system-prompt scanner that gives you a copy-paste hardened-prompt kit + projected score, a GitHub Action CI gate, an MCP server, and SARIF export.

5/ Honest about limits — it's the fast deterministic layer, not a replacement for a model classifier or human red-teaming: /methodology · /vs
Beat it: /breach

---
## 5) Cold email — design partner (to AI-agent startups / teams shipping agents)
Subject: free prompt-injection firewall for <company>'s agent (0-API, 5-min setup)

Hi <name>,
You're shipping <product/agent> — which means untrusted input (user messages, retrieved docs, tool results) reaches your model. I built REDCELL, a 0-API firewall that flags/blocks prompt-injection & exfiltration before it hits the model, including obfuscated attacks (base64/leetspeak/homoglyph/invisible-Unicode). It's deterministic, runs at the edge, no signup: https://redcell.redcellv1.workers.dev/quickstart
I'm onboarding a few design partners: I'll run a free live red-team against your agent's system prompt and hand you a report + hardened-prompt kit, in exchange for feedback. 15 minutes?
— Furkan

## 6) Cold email — pre-seed investor (only when there's early traction)
Subject: REDCELL — the security layer for AI agents (early traction)

Hi <name>,
AI agents are getting production tool access; prompt injection is the new RCE. REDCELL is a deterministic, 0-API firewall + scanner for LLM agents — live, free, and being adopted by developers (workers.dev). We deobfuscate attacks that model-based guards and keyword filters miss, and every Breach-game attempt compounds a proprietary attack dataset.
<one line of real traction: N users / M firewall checks / K reports — do NOT send until real>
Raising a pre-seed to turn the free developer wedge into an agent-runtime security platform. Worth 20 minutes?
— Furkan
