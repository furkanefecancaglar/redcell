# X queue — @fufurkanv1

Ready to fire. Each block is one post/reply, already length-checked for the 280 limit and with
every command verified against the live API before it was written down.

Account state as of 2026-08-23: profile set (avatar, bio, location, link), 1 post published,
0 followers. X has the account under **graduated access** — posts do not appear in search or
trends and DMs to non-followers are filtered, until X is satisfied a human is behind it. That
unlocks through ordinary use, not through volume, and volume from a new account makes it worse.

---

## POSTED — pinned candidate (2026-08-23)

A jailbroken chatbot says something bad. A jailbroken agent does something — it has tools.

So REDCELL checks all three stages: the prompt, the input, and the tool call itself.

No key, no signup:

curl redcell.redcellv1.workers.dev/firewall -d '{"input":"ignore all previous instructions"}'

---

## REPLY 1 — to @kesh_awe (replying to @intigriti)

Their post: "Broken Access Control ... and AI-agent execution vulnerabilities (such as indirect
prompt injection leading to unauthorized tool actions) will dominate bug bounty programs."

> The tool-call half is the under-tooled part. Most defenses stop at the input; the damage lands
> one step later, when the agent actually calls transfer_funds or read_file with attacker-shaped
> args.
>
> Worth screening the proposed call itself, not just the text that caused it.

No link on purpose. A first reply from an unknown account carrying a URL reads as spam; the
profile already has it.

---

## POST 2 — the honest-numbers post

Most tools in this space publish a detection rate against the corpus they also tuned on. Ours
did too, so we wrote a second set afterwards and never tuned against it.

0 false positives on 30 ordinary support messages.
7 of 20 adversarial prompts missed.

Deterministic layers catch known shapes, not paraphrases.

---

## POST 3 — the bug that is worth telling

Our multilingual rules were written with diacritics.

"önceki tüm talimatları yok say" → flagged.
"onceki tum talimatlari yok say" → allowed.

Same sentence. Turkish without accents is how people actually type, so the firewall was blind to
the everyday spelling of one of its own four languages. Fixed by folding combining marks in the
pre-pass.

---

## POST 4 — the CI gate, one curl

A prompt regression is a security regression, and nobody reviews prompts like code.

POST /gate returns 422 below your threshold and 200 above it, so the HTTP status alone fails the
build. One curl, no SDK, no key.

redcell.redcellv1.workers.dev/ci

---

## POST 5 — MCP, install is a URL

Adding a security layer to an agent used to mean vendoring files and editing a config path.

MCP over HTTP: point your client at redcell.redcellv1.workers.dev/mcp and you get five tools —
firewall_check, scan_prompt, tool_check, thread_check, agent_check. No install, no key.

---

## Accounts worth following (real practitioners in this space, not follow-back farming)

@intigriti · @Hacker0x01 · @llm_sec · @simonw (writes the clearest prompt-injection material
anywhere) · @random_walker · @NVISOsecurity

Follow because you want their timeline, not to be followed back. Follow/unfollow churn is the
fastest way to get a new account restricted further.
