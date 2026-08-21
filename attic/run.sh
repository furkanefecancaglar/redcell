#!/usr/bin/env bash
# Local run: installs deps, starts the server (127.0.0.1 by default).
set -e
cd "$(dirname "$0")"
python3 -m pip install -q -r requirements.txt 2>/dev/null || true
exec python3 server.py
