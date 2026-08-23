"""Generalisation tracking against a second, independent corpus.

Set 1 (tests/heldout_corpus.py) stopped being held out the moment its gaps were fixed. This set
was written afterwards, from different attack families and different benign domains, and is
kept as a MOVING BASELINE rather than a pass/fail target: the miss count is recorded, and the
test fails if it grows. Tuning rules until this reaches zero would destroy the only honest
generalisation estimate the project has.

Measured on the day it was written, against the current engine:
  false positives     0 / 30   (0%)
  missed, claimed langs  7 / 20   (35%)  after de-spacing was added to the pre-pass
  missed, other langs    4 / 4    (100%) — the documented limit, scored separately

For contrast, the same set against the pre-round-60 engine missed 11 of 20 (55%), so those
rules did generalise to phrasings they were never shown.
"""
from heldout_corpus2 import ATTACKS_SUPPORTED, ATTACKS_UNSUPPORTED, BENIGN

import redcell_firewall as fw

MISS_BUDGET = 7          # measured, not aspirational — lower it only with a measurement


def _detected(text):
    return fw.inspect(text).action in ("flag", "block")


def test_no_false_positives_on_independent_benign_traffic():
    """The precision half. No rule has ever been changed to satisfy this set, so it is the
    cleanest number the project has: 0 of 30 ordinary business messages flag."""
    flagged = [t for t in BENIGN if _detected(t)]
    assert not flagged, f"{len(flagged)}/{len(BENIGN)} benign messages now flag: {flagged}"


def test_generalisation_does_not_regress():
    missed = [t for t in ATTACKS_SUPPORTED if not _detected(t)]
    assert len(missed) <= MISS_BUDGET, (
        f"misses grew to {len(missed)}/{len(ATTACKS_SUPPORTED)} (budget {MISS_BUDGET}): {missed}"
    )


def test_unsupported_languages_are_a_known_limit():
    """Italian, Portuguese, Russian and Japanese are not claimed. This asserts the limit is real
    rather than accidental, so if coverage is ever added the docs get updated with it."""
    detected = [t for t in ATTACKS_UNSUPPORTED if _detected(t)]
    assert not detected, (
        "coverage appeared for a language the product does not claim; update the docs: " + str(detected)
    )
