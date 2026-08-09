#!/usr/bin/env bash
# Put REDCELL on a FREE public URL — no account, no card, no host.
# Runs the server locally and opens a Cloudflare quick-tunnel (a trycloudflare.com
# https URL). The URL lives while this stays running; Ctrl-C stops both.
#
# Full product: 0-API surfaces (/scan-config, /firewall) always work; /scan (live
# engine) works too via your local ~/nvidia-test/engines.py key.
set -euo pipefail
cd "$(dirname "$0")"
PORT="${REDCELL_PORT:-8770}"

# 1) cloudflared — single free binary from Cloudflare (no account/card). Download if missing.
CF="$(command -v cloudflared || true)"
if [[ -z "$CF" ]]; then
  mkdir -p "$HOME/.local/bin"
  echo "Downloading cloudflared (Cloudflare tunnel binary, ~/.local/bin)…"
  curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
       -o "$HOME/.local/bin/cloudflared"
  chmod +x "$HOME/.local/bin/cloudflared"
  CF="$HOME/.local/bin/cloudflared"
fi

# 2) start REDCELL locally
echo "Starting REDCELL on 127.0.0.1:$PORT …"
python3 server.py >/tmp/redcell_server.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT
sleep 2
if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "server up ✓  (local: http://127.0.0.1:$PORT)"
else
  echo "server failed to start — see /tmp/redcell_server.log" >&2
  exit 1
fi

# 3) open the free public tunnel — the https URL prints in cloudflared's output below
echo ""
echo "Opening a FREE public tunnel — look for the https://<random>.trycloudflare.com URL below."
echo "Share that URL. Ctrl-C here stops the server + tunnel."
echo "NOTE: /scan (live engine) spends your NIM quota if others call it — the 0-API"
echo "      /scan-config + /firewall are safe to share freely."
echo ""
exec "$CF" tunnel --url "http://localhost:$PORT"
