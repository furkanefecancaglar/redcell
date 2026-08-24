"""Set 14 as a regression guard — the joined-history layer, measured once and retired.

Every turn in every thread here is clean on its own; the extraction exists only in the sequence.
The suite asserts that precondition first, because a thread whose last message trips a rule by
itself would be measuring the single-message layer and quietly inflating this number.

Result at measurement: 1 of 15 attack threads caught, 15 of 15 benign threads clean.

That is not the same as saying the joined pass does not work. It does work on split directives
that carry attack vocabulary — "forget all" in one turn, "previous instructions" in the next —
and tests/test_multiturn.py asserts it catches at least six of those. What it does not do is
notice a sequence where no turn contains anything to notice.
"""
import sys

sys.path.insert(0, '/home/furkan/redcell')
import redcell_firewall as fw  # noqa: E402
from heldout_corpus14 import ATTACK_THREADS, BENIGN_THREADS  # noqa: E402

CAUGHT_AT_MEASUREMENT = 1


def test_precondition_every_turn_is_clean_alone():
    """Without this the number above measures the wrong layer."""
    bad = [m for th in ATTACK_THREADS + BENIGN_THREADS for m in th
           if fw.inspect(m).action != "allow"]
    assert not bad, "these turns trip a rule statelessly: " + repr(bad)


def test_no_false_positives_on_benign_threads():
    fps = [th for th in BENIGN_THREADS if fw.inspect_thread(th)["action"] != "allow"]
    assert not fps, "joined pass flagged ordinary threads: " + repr([t[-1] for t in fps])


def test_thread_detection_does_not_regress():
    n = sum(1 for th in ATTACK_THREADS if fw.inspect_thread(th)["action"] != "allow")
    assert n >= CAUGHT_AT_MEASUREMENT, (
        "joined-pass detection on set 14 fell from %d to %d" % (CAUGHT_AT_MEASUREMENT, n))
