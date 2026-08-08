#!/usr/bin/env python3
"""REDCELL NIM client — keys from env in prod, local engines.py in dev.

Key indirection so the product is deploy-ready:
  * If REDCELL_NIM_KEYS is set (JSON: {"engine":{"key":..,"model":..,"extra_body":{..}?}}),
    the engine table comes from the environment — nothing is hardcoded, nothing
    committed. This is the hosted path.
  * Otherwise it falls back to importing ~/nvidia-test/engines.py, so the dev box
    keeps working exactly as before with zero config.

The chat() retry logic mirrors engines.py so behaviour is identical either way.
"""
from __future__ import annotations

import json
import os
import sys
import time

try:
    import requests
except ImportError:
    raise SystemExit("HATA: 'requests' kurulu değil. Kur: pip install requests")

INVOKE_URL = os.environ.get("REDCELL_NIM_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
TIMEOUT = 120
MAX_RETRIES = 4
RETRY_STATUSES = {404, 429, 500, 502, 503, 529}
RETRY_BACKOFF = 4


def _load_engines():
    raw = os.environ.get("REDCELL_NIM_KEYS")
    if raw:
        try:
            table = json.loads(raw)
            if not isinstance(table, dict) or not table:
                raise ValueError("REDCELL_NIM_KEYS must be a non-empty JSON object")
            for name, cfg in table.items():
                if "key" not in cfg or "model" not in cfg:
                    raise ValueError(f"engine '{name}' needs 'key' and 'model'")
            return table, "env"
        except Exception as e:
            raise SystemExit(f"REDCELL_NIM_KEYS is set but invalid: {e}")
    # dev fallback: the local, git-ignored engines.py
    sys.path.insert(0, os.path.expanduser("~/nvidia-test"))
    try:
        from engines import ENGINES as LOCAL
        return dict(LOCAL), "local engines.py"
    except Exception:
        # No keys anywhere. Do NOT crash: the 0-API surfaces (/scan-config, /firewall,
        # CI, firewall lib) must still work. chat() raises a clear error only if the
        # live engine (/scan) is actually invoked.
        return {}, "none (set REDCELL_NIM_KEYS to enable the live engine)"


ENGINES, KEY_SOURCE = _load_engines()
DEFAULT_ENGINE = os.environ.get("REDCELL_DEFAULT_ENGINE",
                                "nemotron" if "nemotron" in ENGINES else
                                (next(iter(ENGINES)) if ENGINES else "nemotron"))


def chat(engine, messages, max_tokens=4096, temperature=0.6, top_p=0.95):
    """Send messages to one engine, return the reply text. Retries transient errors."""
    if engine not in ENGINES:
        raise ValueError(f"Unknown engine '{engine}'. Options: {list(ENGINES)}")
    cfg = ENGINES[engine]
    payload = {
        "model": cfg["model"], "messages": messages,
        "temperature": temperature, "top_p": top_p,
        "max_tokens": max_tokens, "stream": False,
    }
    if cfg.get("extra_body"):
        payload.update(cfg["extra_body"])
    headers = {"Authorization": f"Bearer {cfg['key']}", "Accept": "application/json"}

    attempts = 0
    while True:
        attempts += 1
        try:
            r = requests.post(INVOKE_URL, headers=headers, json=payload, timeout=TIMEOUT)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if attempts < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF * attempts)
                continue
            raise RuntimeError(f"{engine}: network error ({e})")
        if r.status_code in RETRY_STATUSES and attempts < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF * attempts)
            continue
        if r.status_code != 200:
            raise RuntimeError(f"{engine}: HTTP {r.status_code} → {r.text[:200]}")
        return r.json()["choices"][0]["message"].get("content") or ""


if __name__ == "__main__":
    print(f"NIM key source: {KEY_SOURCE}")
    print(f"engines: {list(ENGINES)}")
    print(f"default: {DEFAULT_ENGINE}")
