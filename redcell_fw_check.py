#!/usr/bin/env python3
"""REDCELL firewall regression check — fail CI if a known injection stops being caught.

Distinct from redcell_ci.py (which scores a system PROMPT). This reads fixture files of
known-attack lines (your corpus of injections that must never slip past the firewall) and
exits non-zero if any line is allowed. Drop it in CI so a change that weakens the firewall
— or a prompt/config that would let a known attack through — can't merge.

    python3 redcell_fw_check.py attacks/injections.txt
    python3 redcell_fw_check.py "attacks/**/*.txt" --require block   # stricter: must BLOCK

Fixture format: one attack per line; blank lines and lines starting with '#' are ignored.
Exit codes: 0 = every attack caught · 1 = at least one slipped (or a named file missing)
· 3 = no path args.
"""
from __future__ import annotations

import argparse
import glob
import sys

from redcell_firewall import inspect


def check(paths, require="flag"):
    files = []
    for p in paths:
        if any(c in p for c in "*?["):
            files.extend(glob.glob(p, recursive=True))
        else:
            files.append(p)
    if not files:
        print("no fixture files matched — nothing to check", file=sys.stderr)
        return 0
    caught_ok = {"block"} if require == "block" else {"block", "flag"}
    total = misses = 0
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except OSError as e:
            print(f"MISS  {path}  (read error: {e})")
            misses += 1
            continue
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            v = inspect(line)
            if v.action in caught_ok:
                print(f"ok    [{v.action:5}] {line[:60]}")
            else:
                misses += 1
                print(f"MISS  {path}:{i}  {v.action} (needed {require}+): {line[:60]}")
    print(f"\n{total - misses}/{total} known injections caught (require={require})")
    return 1 if misses else 0


def main():
    ap = argparse.ArgumentParser(description="REDCELL firewall regression check")
    ap.add_argument("paths", nargs="*", help="fixture files of known attacks (globs allowed)")
    ap.add_argument("--require", choices=["flag", "block"], default="flag",
                    help="minimum verdict that counts as caught (default: flag)")
    args = ap.parse_args()
    if not args.paths:
        print("usage: redcell_fw_check.py <fixture-file>... [--require flag|block]", file=sys.stderr)
        raise SystemExit(3)
    raise SystemExit(check(args.paths, require=args.require))


if __name__ == "__main__":
    main()
