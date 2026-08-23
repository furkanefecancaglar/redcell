# Published prompts

The hardened prompts this project publishes and asks people to copy. They are gated in CI by
REDCELL itself (`.github/workflows/prompt-gate.yml`): if our own advice ever scores below the
threshold we tell customers to hold, our build fails before anyone else finds out.

- **`billing-assistant.txt`** — the hardened example from `/example` and the quickstart. It is the
  same text `tools/snippet_check.mjs` asserts the live `/gate` endpoint passes, so the local tool,
  the deployed API and this file cannot drift apart without something going red. Currently scores
  90/100.
