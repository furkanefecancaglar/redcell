#!/usr/bin/env bash
# Run every verification layer in one command.
#
# Three layers exist because they catch different classes of failure, and the ones that
# actually bit us were never the first:
#   pytest        — the code is correct
#   page_audit    — the HTML we SERVE is sound and the numbers we advertise are true
#   snippet_check — the commands we tell people to COPY actually work
# A shipped bug had correct code, a passing suite, and a broken copy-paste snippet.
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

step "unit tests"        run_pytest
step "js syntax"         run_js_syntax
step "served pages"      node tools/page_audit.mjs "$BASE"
step "published snippets" node tools/snippet_check.mjs "$BASE"

printf '\n'
if [ "$fails" -ne 0 ]; then
  printf '\033[31m%d layer(s) failed against %s\033[0m\n' "$fails" "$BASE"
  exit 1
fi
printf '\033[32mall layers pass against %s\033[0m\n' "$BASE"
