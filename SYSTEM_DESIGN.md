# REDCELL — system architecture (after the System Design Primer)

Applied-from: donnemartin/system-design-primer (reviewed 2026-08-17).
Each section maps a primer topic → what REDCELL does today → what we learned
and changed → what stays a documented trade-off.

## 0. The product in one diagram

```
browser/agent ──▶ Cloudflare edge (free tier, no card)
                    │  worker.js (this repo — logic + pages at the edge)
                    │
      ┌─────────────┼────────────────────────────────┐
      │ 0-API surfaces (no key, no quota, edge)      │  quota surfaces (NIM)
      │   /firewall  /firewall-thread  /toolcheck    │    /scan  /breach
      │   /scan-config  /agentcheck  /review  /r/*   │    (token-gated,
      │                                              │     rate-limited)
      └─────────────┬────────────────────────────────┘
                    ▼
         Cloudflare KV (eventually consistent)
         BREACH_LOG + LEADS namespaces: stats, breach attempts,
         techniques, leads, reports (30-day TTL), rate-limit buckets
```

Everything except `/scan` and `/breach` runs with **zero API calls** — that is
the wedge: a security product that costs nothing to run and explains every
verdict (deterministic patterns, not a black box).

## 1. Performance vs scalability (primer §Performance vs scalability)

Lesson: **a system is "scalable" only if perf doesn't collapse under load; start
by bounding worst cases.** REDCELL's two hot paths are regex engines, so we bound
them explicitly:

- `inspect()` caps at `_MAX_INSPECT = 16 KB` (firewall) — a 1 MB input runs in
  ~44 ms instead of seconds. The cap is documented in /methodology; large blobs
  should be chunked (each chunk inspected independently).
- ReDoS audit: every rule was checked for catastrophic backtracking; none are
  exponential (bounded quantifiers). Pathological 80–200 KB inputs: all < 320 ms.
- `analyze()` (scanner) also caps at 16 KB (`_MAX_ANALYZE`).
- Threads cap: `/firewall-thread` rejects > 50 turns; each turn sliced to 8 KB.

Changed this round: added the cap note for the new thread endpoint.

## 2. Latency vs throughput (primer §Latency vs throughput)

Lesson: know your budget. The 0-API surfaces are the low-latency tier; the web
round-trip from a browser near a PoP is the floor (~50–300 ms). Server-side CPU
per verdict is sub-millisecond (pattern match on ≤16 KB). We do NOT fake this:
landing + dashboard show **client-measured** round-trip ms (`performance.now()`)
and /methodology distinguishes "microsecond server CPU" from "observed
round-trip" — no fabricated numbers (Cloudflare freezes `Date.now()` server-side
without I/O, so server timing would be misleading).

## 3. Availability vs consistency (primer §CAP, §Consistency patterns)

Lesson: **Cloudflare KV is AP / eventually consistent.** We accept that and make
the product correct *despite* it:

- Funnel counters (`stat:*`) use read-modify-write in `ctx.waitUntil` — a burst
  can *undercount* (never over). Fine for marketing numbers.
- `/selfcheck` probes KV with a fixed probe key + prompt-equality read-back, and
  tolerates eventual consistency (does not claim strong-read guarantees).
- Breach stats / techniques: same RMW pattern, best-effort, never fabricated
  ("no data yet" renders instead of zeros when the KV is empty).
- Report store `/r/<id>`: single-key writes, 30-day TTL, unguessable ids.
  Eventual consistency is fine: the writer returns the URL after `put()` and the
  reader retries; a just-written report may 404 for a second on a far PoP.

Changed this round: rate-limit buckets are KV; see §7 for the trade-off.

## 4. Availability patterns (primer §Availability)

Lesson: components in **parallel** multiply availability; in **sequence** they
reduce it. The worker is deliberately a single deployed unit with every surface
behind one URL, so availability is one component, not a chain — plus KV
namespaces are separate services in parallel (losing LEADS doesn't kill
BREACH_LOG and vice versa; every handler fail-open when its KV is missing).

Constant factors we can state honestly:
- Deployed surface is behind Cloudflare (multi-region PoPs). We measured live
  external fetches; no downtime observed since the fly.io pivot.
- Every KV read/write is wrapped in try/catch and fail-open where the feature is
  protective rather than critical (rate limiting, §7).

## 5. Cache (primer §Cache)

Lesson: cache aggressively at the edge what never changes; never cache what can
carry user data. Applied:

| Route | Cache-Control | Why |
|---|---|---|
| `/`, `/pitch`, `/dashboard`, static pages | `public, max-age=1800` | pure product copy |
| `/og.svg`, `/robots.txt`, `/sitemap.xml` | `public, max-age=86400` | immutable-ish, shared |
| `/src/<file>.py` | `1h` | vendorable source, rarely changes |
| `/r/<id>` + `.json/.md/.sarif/og.svg` | `noindex` (+1h for per-report og) | private-ish, unguessable id; never `public` |
| `GET /firewall?input=`, `/toolcheck`, `/agentcheck` | `no-store` | **user data can sit in the URL** |
| `/firewall-thread`, POST APIs | (default, no cache) | request bodies are user data |

Changed this round: new GET surfaces got `no-store`; audit table drove the choice.

## 6. Asynchronism (primer §Asynchronism) & back pressure

Lesson: move slow side-effects out of the request path; when load exceeds a
queue's ability to drain, apply **back pressure** (client gets 429/503 and
retries, ideally exponential backoff).

- KV increments (funnel, breach logging, techniques) all run in
  `ctx.waitUntil(...)` — the response never waits on KV.
- The live engine already serializes attack batches to stay inside NIM RPM
  limits (comment in `liveScan`: "so the extra attacker calls don't spike
  concurrency into rate limits").

**Changed this round (the practical win):** added `rateLimit()` — a KV
fixed-window bucket keyed by client IP on the three endpoints that spend money
or write lots:
- `POST /review` → 10/min/IP (each writes a KV record)
- `POST /scan` → 5/min/IP (each burns NIM quota)
- `POST /breach` → 5/min/IP (each burns NIM quota)

On exceed: `429` + `Retry-After` seconds. Fail-open on KV errors (a rate limiter
must never take the product down). Verified live: burst of 12 → 429 after the
bucket fills, Retry-After present.

Documented trade-off (primer: "everything is a trade-off"): KV is
eventually-consistent, so the bucket undercounts under a racing burst — a few
requests may slip past the limit. A *strict* limiter would need a
strongly-consistent counter (Durable Objects / single-flight). We chose the free
0-ops tier + best-effort protection; when paid hosting arrives, swap the KV
bucket for a DO counter with the same interface. (/openapi.json notes the same
deferral honestly.)

## 7. Database (primer §Database, §Key-value store)

Lesson: pick the store by access pattern. REDCELL has no relational joins — it
has key-shaped data (report by id, stat by name, lead by id, breach record by
timestamp, bucket by ip). KV is the correct shape; TTLs do the expiry work
(reports 30 days, breach 120 days, rate buckets window+60s). No sharding needed
at this scale; the free KV limits (100k reads/day) are the next ceiling — the
rate limiter and caches exist partly to protect that.

Pastebin-style design (primer solution): REDCELL's `/r/<id>` is exactly the
pastebin pattern — unguessable random id, write-once, TTL expiry, read-mostly
with `Cache-Control: noindex`. The primer's design questions (expiry default?,
analytics?, delete-expired?) map cleanly onto what we shipped.

## 8. Communication (primer §Communication)

- REST over JSON for all surfaces; OpenAPI 3.1 spec at `/openapi.json`
  (machine-discoverable, 14 paths, live counts).
- MCP (stdio JSON-RPC) for agent/IDE clients: `firewall_check`, `scan_prompt`,
  `tool_check`, `agent_check` — 0-API, vendorable.
- Tool-call surface (`/toolcheck`, `/agentcheck`) is the agent-native
  communication layer: gate the *action*, not just the text.

## 9. Security (primer §Security)

Lesson: encrypt in transit, sanitize all inputs, least privilege.

- Transit: everything is HTTPS via Cloudflare (no plaintext endpoints).
- Input sanitizing: the product IS an input sanitizer — and the pages that echo
  stored prompts (`/r/<id>`) HTML-escape everything server-side (verified with
  an XSS payload in a stored report).
- Least privilege: the worker only holds the KV namespaces it needs; the live
  engine key is a Worker secret (`REDCELL_NIM_KEYS`) and `/scan` is additionally
  gated by `X-REDCELL-Token` when `REDCELL_SCAN_TOKEN` is set; `/leads` export
  requires the token (PII, 401 without).
- No PII in aggregates: breach "techniques" stores counts only, never raw
  messages; /stats stores aggregate counts; report prompts live under
  unguessable ids, never in query strings.
- Repo secret hygiene: `.scan_token` and key patterns are git-ignored; a
  secret-grep gate runs in CI and before every deploy.

## 10. Numbers we can defend (primer §Back-of-the-envelope)

| Bound | Value | Basis |
|---|---|---|
| Firewall verdict CPU | ≤ ~44 ms worst (1 MB), sub-ms typical | fuzz suite, 16 KB cap |
| Scalar scan (system prompt) | ~2 ms for 16 KB | benchmark run |
| Free-tier request ceiling | whatever the CF free plan gives; KV 100k reads/day is the tightest coupling | dashboard/selfcheck monitor it honestly |

## Always-on safeguards (continuous, not one-off)

- `pytest` suite (182 tests): static-score fidelity, firewall 0-FP/FN corpus,
  Py↔JS byte-parity gate (shared corpus via node subprocess), fuzz, obfuscation,
  bidi, toolcheck, multi-turn, CI fixtures. No test calls a live model.
- `node --check` + `wrangler deploy --dry-run` before every deploy (the .py
  text-imports only resolve under wrangler's esbuild, not plain node).
- `GET /selfcheck` live probes all surfaces from inside the worker and the
  dashboard renders the result — the site reports its own health rather than
  assuming it.