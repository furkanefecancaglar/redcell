# Examples

**`redcell-gate.workflow.yml`** — the CI gate, ready to copy into your own repository at
`.github/workflows/`. It fails a build when a pull request weakens an agent's system prompt
below a resilience threshold. Pure static analysis, no API key, no network call.

It lived in this repo's own `.github/workflows/` for a while, which was a mistake: it is a
template written for *your* paths (`redcell/redcell_ci.py`, `prompts/**`), so it failed on every
push here and left a permanent red X on a security project's front page. It is documentation, so
it lives with the documentation now.

What runs in this repo instead is `.github/workflows/prompt-gate.yml`, which points the same tool
at the prompts in `prompts/` — the hardened examples we publish and ask people to copy. If our own
advice ever scores below the bar we tell customers to hold, our build breaks first.

Setup is three steps:

1. Vendor the two files you need:
   ```bash
   mkdir -p redcell && cd redcell
   curl -O https://redcell.redcellv1.workers.dev/src/redcell_static.py
   curl -O https://redcell.redcellv1.workers.dev/src/redcell_ci.py
   ```
2. Copy `redcell-gate.workflow.yml` to `.github/workflows/redcell.yml`.
3. Point the globs at wherever your prompts actually live, and set `--min-score`.

Prefer one curl over a vendored file? `POST /gate` returns HTTP 422 below the threshold and 200
above it, so the status code alone fails the build: https://redcell.redcellv1.workers.dev/ci
