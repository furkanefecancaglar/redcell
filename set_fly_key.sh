#!/usr/bin/env bash
# Set the NIM key as a Fly secret WITHOUT printing it.
# Reads the nemotron engine (key + model) from ~/nvidia-test/engines.py and pushes
# it as REDCELL_NIM_KEYS. Run this once (and again to rotate). Requires: fly auth login.
set -euo pipefail
cd "$(dirname "$0")"

ENGINE="${1:-nemotron}"          # which engine to ship as the judge/target
KEYFILE="${HOME}/nvidia-test/engines.py"

if [[ ! -f "$KEYFILE" ]]; then
  echo "ERROR: $KEYFILE not found. Put your NIM key there, or set REDCELL_NIM_KEYS by hand." >&2
  exit 1
fi

# Build the JSON in Python so the key is never echoed to the terminal.
SECRET="$(python3 - "$ENGINE" <<'PY'
import json, os, sys
sys.path.insert(0, os.path.expanduser("~/nvidia-test"))
from engines import ENGINES
name = sys.argv[1]
cfg = ENGINES[name]
out = {name: {"key": cfg["key"], "model": cfg["model"]}}
if cfg.get("extra_body"):
    out[name]["extra_body"] = cfg["extra_body"]
print(json.dumps(out))
PY
)"

if [[ -z "$SECRET" ]]; then echo "ERROR: could not read engine '$ENGINE'." >&2; exit 1; fi

echo "Setting REDCELL_NIM_KEYS on Fly (engine: $ENGINE) — value not shown."
fly secrets set REDCELL_NIM_KEYS="$SECRET" >/dev/null
echo "Done. The live /scan engine now has its key. (0-API surfaces already worked without it.)"
