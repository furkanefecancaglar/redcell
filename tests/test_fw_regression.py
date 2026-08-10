"""Dogfood: REDCELL regression-tests its OWN firewall against a corpus of real attack
strings (attacks/injections.txt). If a rule change lets any known class slip past
inspect(), this fails — the same gate we ship to users (redcell_fw_check.py), run on us."""
import glob
import os

import pytest

import redcell_fw_check as fc

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = sorted(glob.glob(os.path.join(REPO, "attacks", "*.txt")))


def test_attack_fixtures_exist():
    assert FIXTURES, "expected attack fixtures under attacks/*.txt"


def test_every_known_attack_is_caught():
    # flag-tier: every fixture line must be flagged or blocked (exit 0 from the checker)
    assert fc.check(FIXTURES, require="flag") == 0


@pytest.mark.parametrize("path", FIXTURES)
def test_no_line_slips(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    import redcell_firewall as fw
    slipped = [ln for ln in lines if fw.inspect(ln).action == "allow"]
    assert not slipped, "these known attacks slipped (allow): " + "; ".join(s[:50] for s in slipped)
