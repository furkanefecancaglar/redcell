# REDCELL — what is deployed, what is not, and what is blocked

This file used to be a menu of hosting options for a local Python server that is no longer the
product. It now records the actual state, because a runbook that describes a system you do not
run is worse than no runbook.

## What is live

**The Cloudflare Worker.** One deployed unit, every surface behind one URL.

```bash
npx wrangler deploy
```

- Production: https://redcell.redcellv1.workers.dev
- State: Workers KV. Two namespaces — `LEADS` (accounts, sessions, API keys, subscriptions,
  scan history, counters) and `BREACH_LOG`.
- Secrets are set with `npx wrangler secret put <NAME>`, never committed.

The deploy token in use **cannot create new KV namespaces**. Everything added since rides
`LEADS` under key prefixes (`usr:`, `uid:`, `sess:`, `sub:`, `akey:`, `keyidx:`, `histidx:`,
`pcust:`, `lead:`, `stat:`, `report:`, `rl:`). Adding a genuinely separate namespace needs a
broader token.

Always verify after deploying — the Worker parsing is not evidence the pages are right:

```bash
./tools/verify.sh
```

## What is built but not hosted

**`services/api/`** — a multi-tenant FastAPI backend: orgs, users, JWT auth, scoped API keys,
agents CRUD, scans, SARIF export, Alembic migrations against Postgres. 22 modules. It runs
locally and its tests pass. **It has never served a request in production.**

It is not dead code, and it is not currently the plan either. The honest position:

- The Worker is the product. It is live, verified, and has auth, billing, history, MCP and the
  CI gate. `services/api` duplicates the auth and API-key layers in a second language.
- The one thing it would genuinely fix is storage. Round 48 measured KV's real limits: a
  read-modify-write index lost keys under concurrent mints, `list()` lags about a minute, and
  revocation takes 11–22s to propagate. Postgres has none of those problems.
- Hosting it needs a host account and a Postgres instance. That is an external blocker
  (see below), not a technical one.

So it stays, unhosted and honestly labelled, until either the storage limits start costing
users something or the hosting blocker clears. What must **not** happen is quietly maintaining
two divergent implementations of the same product — rounds 46 and 47 showed that duplicated
engines drift silently, which is why every engine now has a parity test.

Run it locally:

```bash
cd services/api
pip install -r requirements.txt
cp .env.example .env          # set SECRET_KEY at minimum
uvicorn app.main:app --reload # http://127.0.0.1:8000/api/v1/docs
```

Known gap: `POST /scans` rejects any `type` other than `static` or `toolcheck` with an explicit
"not implemented yet" — see `services/api/app/api/v1/scans.py`.

## What is retired

`attic/` holds the earlier hosting scaffolding — the local `server.py` console, the root
Dockerfile and compose file, `fly.toml`, `render.yaml`, and the Fly deploy scripts. Kept for
reference, wired to nothing.

**`redcell.fly.dev` is not ours.** It resolves and serves a dark-themed "Redcells — AI Red
Teaming Platform" on a different stack. `flyctl` has never been installed on this machine, and
`fly.toml` itself warns that the app name may already be taken. Earlier docs implied we had
pivoted to Fly and were measuring its uptime; that claim was not true and has been removed. Do
not treat that host as ours, and do not deploy to that name.

## External blockers — these need a human

These are not engineering problems and cannot be worked around in code.

1. **GitHub account suspended.** `api.github.com/repos/furkanefecan/redcell` is 404 and pushes
   fail with `remote: Your account is suspended`. This blocks the public repo, package
   publishing and CI. It needs an appeal to GitHub support — not re-authentication, which is
   what earlier notes wrongly assumed.
   *Meanwhile:* full history is preserved as restore-verified git bundles in `~/redcell-backup/`.
   Each is created with `git bundle create <file> --all` and then test-cloned to prove it
   restores. That is the only copy outside this machine's working tree.

2. **Paddle KYC and payout details.** Billing is wired end to end — Paddle.js overlay checkout,
   HMAC-verified webhooks, subscription state in KV — but no money can be taken until the
   account clears KYC and a payout method is on file. Domain approval is still pending.

Until both clear, the product can be used but not bought, and the source cannot be published.
