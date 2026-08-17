# REDCELL v1 — live adversarial engine

Fires a real adversarial attack corpus at a live model wearing your agent's system
prompt, then scores every response with a **separate judge model**. Not heuristics —
actual attack + actual judge.

## What it does
1. **Simulate** the target agent: `chat(system=your_prompt, user=attack_payload)`.
2. **Attack** with the OWASP LLM Top 10 corpus (injection, prompt-extraction, persona
   hijack, excessive agency, data exfil, authority spoof, encoding smuggle, output injection).
3. **Judge** each response with a different model → `PASS` (held) / `FAIL` (broken) + reason.
4. **Score** 0–100 (severity-weighted) + grade.

## Security model
- Uses the NVIDIA NIM keys already in `~/nvidia-test/engines.py` — **one source of truth**,
  keys never duplicated.
- The server binds `127.0.0.1` only. **The key never leaves the machine and never touches
  the browser.** This is exactly why the public artifact scanner can't do live calls (its CSP
  blocks external APIs and would leak an embedded key) — the live engine must run locally / on
  your own backend.

## Run it
CLI:
```bash
cd ~/redcell
python3 redcell_engine.py --example weak        # demo target
python3 redcell_engine.py --prompt-file my.txt  # your agent
echo "You are a support bot..." | python3 redcell_engine.py --stdin
python3 redcell_engine.py --example hard --json  # machine-readable
```

Local console (browser UI):
```bash
cd ~/redcell
python3 server.py            # → http://127.0.0.1:8770
```

## Request-time surfaces
Local `server.py` on `127.0.0.1`:
- `POST /scan-config` `{system_prompt}` → static resilience score (22 detectors, **0 API**). Shared core: `redcell_static.py`.
- `POST /firewall` `{input}` → runtime injection verdict allow/flag/block (37 detectors, **0 API**). Core: `redcell_firewall.py`. Beyond keyword rules it **deobfuscates** each input — base64 (standard/url-safe/nested), leetspeak, Cyrillic/Greek homoglyphs, zero-width splits, **bidi control characters** (U+202A-202E, U+2066-2069), and invisible **Unicode-tag ASCII smuggling** (U+E0000–E007F) — then re-runs the rule set, so an injection hidden as `1gn0re…` or an invisible tag string is still caught.
- `POST /scan` `{system_prompt}` → live adversarial engine (real attacks + judge, **uses model quota**).
- `GET /health` → advertises the request-time surfaces.

The live public worker (https://redcell.redcellv1.workers.dev) adds the agent-native surfaces:
- `POST /toolcheck` `{name, arguments}` → screens a proposed tool call before it runs → allow/flag/block across **13 tool-aware reason classes**. Core: `redcell_toolcheck.py`. Quick browser/curl test: `GET /toolcheck?name=…&args=…`.
- `POST /agentcheck` `{system_prompt?, input?, tool_call?}` → one call runs scanner + input firewall + tool-call firewall and returns the worst verdict. `GET /agentcheck?system_prompt=…&input=…` also works.
- `GET /benchmark` → public leaderboard: static resilience scores for **16 archetype** system prompts.
- Shared security reports: `GET /r/<id>` (JSON / Markdown) and `GET /r/<id>.sarif` (SARIF 2.1.0, GitHub code-scanning ready).

CI gate (0 API): `python3 redcell_ci.py prompts/*.txt --min-score 60` (exit 1 on fail; an unmatched glob is a clean pass). Action: `.github/workflows/redcell.yml`. Copy-paste setup + YAML: <https://redcell.redcellv1.workers.dev/ci>.

MCP server (0 API): `python3 redcell_mcp.py` exposes four tools — `firewall_check`, `scan_prompt`, `tool_check`, `agent_check` — any MCP client
(Claude Desktop, Cursor, …) can call. Config: `{ "redcell": { "command": "python3", "args": ["/abs/path/redcell_mcp.py"] } }`.

## Deploy
```bash
./run.sh                                   # local (127.0.0.1, keys from ~/nvidia-test/engines.py)
docker build -t redcell . && \
  docker run -p 8770:8770 --env-file .env redcell   # hosted (keys from env, binds 0.0.0.0)
```
Keys are **env-indirected** (`nim_client.py`): set `REDCELL_NIM_KEYS` (JSON) for a hosted deploy — nothing hardcoded,
nothing committed (`.gitignore`/`.dockerignore` exclude `.env`). With no env set it falls back to the local
`~/nvidia-test/engines.py` so dev is zero-config. See `.env.example`. **Put auth/a proxy in front when hosting** —
`/scan` holds provider keys.

## Config (env vars)
- `REDCELL_NIM_KEYS`      — JSON engine table for hosted deploys; unset → local `~/nvidia-test/engines.py`.
- `REDCELL_TARGET_ENGINE` (default `nemotron`) — model that plays the target agent.
- `REDCELL_JUDGE_ENGINE`  (default `nemotron`) — model that scores responses (only `nemotron` usable as of 2026-08-08).
- `REDCELL_WORKERS`       (default `2`)        — attack concurrency.
- `REDCELL_AUTOFAILOVER`  (default off)        — probe engines once and auto-pick a live judge distinct from the
  target (judge independence without a 2nd provider). Inspect with `python3 redcell_engine.py --probe`.
- `REDCELL_HOST`/`REDCELL_PORT` (default `127.0.0.1`/`8770`) — bind address/port.

## Cost note
Each attack = 2 model calls (simulate + judge). Full corpus (8 attacks) ≈ 16 calls per scan.

## Relationship to the public scanner
- **v0 (published artifact):** free browser scanner, heuristic static analysis, zero backend,
  top-of-funnel lead-gen. → https://claude.ai/code/artifact/a8f77cef-3be3-44fe-b182-b15d2fe9d09a
- **v1 (this):** the paid engine — live attacks + judge. Runs where the key can stay secret.
