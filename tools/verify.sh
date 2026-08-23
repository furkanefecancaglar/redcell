#!/usr/bin/env bash
# Run every verification layer in one command.
#
# Each layer catches a different class of failure, and the ones that actually bit us were
# never the first:
#   pytest        — the code is correct
#   page_audit    — the HTML we SERVE is sound and the numbers we advertise are true
#   snippet_check — the commands we tell people to COPY actually work
#   doc_check     — the REPOSITORY's own docs match the product
# A shipped bug had correct code, a passing suite, and a broken copy-paste snippet. Separately,
# README described a local Python CLI months after the product became a deployed Worker.
#
#   ./tools/verify.sh                     # against production
#   ./tools/verify.sh http://127.0.0.1:8787   # against a local wrangler dev
set -uo pipefail
cd "$(dirname "$0")/.."

BASE="${1:-https://redcell.redcellv1.workers.dev}"
NODE_BIN="/home/furkan/.nvm/versions/node/v22.23.2/bin"
[ -d "$NODE_BIN" ] && PATH="$NODE_BIN:$PATH"

fails=0
step () {
  local name="$1"; shift
  printf '\n\033[1m== %s ==\033[0m\n' "$name"
  if "$@"; then
    printf '   \033[32mPASS\033[0m %s\n' "$name"
  else
    printf '   \033[31mFAIL\033[0m %s\n' "$name"
    fails=$((fails + 1))
  fi
}

run_pytest () {
  # shellcheck disable=SC1091
  [ -f .venv/bin/activate ] && . .venv/bin/activate
  python -m pytest -q 2>&1 | tail -3
  # tail would mask pytest's status, so read it from PIPESTATUS explicitly
  return "${PIPESTATUS[0]}"
}
run_js_syntax () {
  local bad=0
  for f in redcell.js redcell_scanner.js redcell_toolcheck.js redcell_semantic.js; do
    node --check "$f" || bad=1
  done
  return "$bad"
}

# The account tests and the /account audit both write to KV, and on the free plan those writes
# come out of the same 1,000-a-day budget real users need — this suite exhausted it once and
# sign-ups were down for a full day. Run just those parts against a throwaway local Worker:
# same code, same assertions, nothing charged to production. Everything else still runs against
# the deployed site, because that is the thing being verified.
ACCOUNT_BASE=""
DEV_PID=""

start_local () {
  # setsid puts the dev server in its OWN process group. Without it, stop_local's group kill
  # took this script down too (exit 137) — the server was a background job of the same group.
  setsid npx wrangler dev --port 8788 --local >/tmp/redcell-verify-dev.log 2>&1 &
  DEV_PID=$!
  for _ in $(seq 1 40); do
    if curl -s -o /dev/null "http://127.0.0.1:8788/health" 2>/dev/null; then
      ACCOUNT_BASE="http://127.0.0.1:8788"
      # The local D1 starts empty, so without the schema every account test fails with a
      # storage error that looks exactly like the production quota being spent. Apply it.
      npx wrangler d1 execute redcell-db --local --file=migrations/0001_accounts.sql \
        >/tmp/redcell-verify-d1.log 2>&1 || true
      return 0
    fi
    sleep 1
  done
  printf '   \033[33mnote\033[0m local Worker did not start; account tests will hit %s\n' "$BASE"
  return 0
}

stop_local () {
  # Kill the process GROUP that owns the port, not a command-line pattern. wrangler dev is a node
  # parent that respawns its workerd child, and the child's argv reads "entry=localhost:8788", so
  # pattern-matching missed it and the parent immediately started another one. Observed directly:
  # after three rounds of pkill a workerd was still holding the port, and only killing the group
  # cleared it. A hung dev server sat on port 8795 for two days this way.
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  local owners pg
  owners=$(ss -ltnp 2>/dev/null | grep -E '127\.0\.0\.1:8788|localhost:8788' \
    | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  local self_pg
  self_pg=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ')
  for p in $owners; do
    pg=$(ps -o pgid= -p "$p" 2>/dev/null | tr -d ' ')
    # never kill our own group, even if setsid was unavailable — losing the verifier mid-run
    # tells you nothing about the product
    if [ -n "$pg" ] && [ "$pg" != "$self_pg" ]; then kill -9 -"$pg" 2>/dev/null; fi
    kill -9 "$p" 2>/dev/null
  done
  return 0
}

# Tear the local Worker down on every exit path, including Ctrl-C. A verification run that
# leaves a server listening is exactly the kind of stray this project keeps finding.
trap stop_local EXIT INT TERM

run_pages    () { ACCOUNT_BASE="$ACCOUNT_BASE" node tools/page_audit.mjs "$BASE"; }
run_snippets () { ACCOUNT_BASE="$ACCOUNT_BASE" node tools/snippet_check.mjs "$BASE"; }

step "unit tests"        run_pytest
step "js syntax"         run_js_syntax
start_local
step "served pages"      run_pages
step "published snippets" run_snippets
stop_local
step "documentation"      node tools/doc_check.mjs "$BASE"

printf '\n'
if [ "$fails" -ne 0 ]; then
  printf '\033[31m%d layer(s) failed against %s\033[0m\n' "$fails" "$BASE"
  exit 1
fi
printf '\033[32mall layers pass against %s\033[0m\n' "$BASE"
