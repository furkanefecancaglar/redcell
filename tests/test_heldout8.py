"""Set 8 as a regression guard.

Measured once and retired. No rule was written against it, so both halves are genuine held-out
results — but the attack half is asserted only not to get worse. Freezing 16/30 as a threshold
would turn a measurement into a target, which is the failure the whole train/judge split exists
to prevent.

The classifier's single false positive here is recorded rather than fixed: it is the first one on
a fresh benign set, it is why the stage remains off by default, and a test that knows about it
will notice if a retrain makes it worse.
"""
import sys

sys.path.insert(0, '/home/furkan/redcell')
import redcell_classifier as clf  # noqa: E402
import redcell_firewall as fw  # noqa: E402
from heldout_corpus8 import ATTACKS_SUPPORTED, ATTACKS_UNSUPPORTED, BENIGN  # noqa: E402

RULES_DETECTED_AT_MEASUREMENT = 16
CLASSIFIER_FP_AT_MEASUREMENT = 1


def _rules(text):
    return fw.inspect(text).action in ("flag", "block")


def test_rules_have_no_false_positives_on_set8():
    fps = [t for t in BENIGN if _rules(t)]
    assert not fps, "false positives returned: " + repr(fps)


def test_rule_detection_does_not_regress():
    n = sum(1 for t in ATTACKS_SUPPORTED if _rules(t))
    assert n >= RULES_DETECTED_AT_MEASUREMENT, (
        "set 8 rule detection fell from %d to %d" % (RULES_DETECTED_AT_MEASUREMENT, n))


def test_classifier_false_positives_do_not_grow():
    n = sum(1 for t in BENIGN if clf.score(t) >= clf.THRESHOLD)
    assert n <= CLASSIFIER_FP_AT_MEASUREMENT, (
        "the classifier now flags %d ordinary messages here, up from %d"
        % (n, CLASSIFIER_FP_AT_MEASUREMENT))


def test_unsupported_languages_stay_undetected():
    """Not a defect — a documented limit, asserted so it cannot become an accidental claim."""
    assert not [t for t in ATTACKS_UNSUPPORTED if _rules(t)]
