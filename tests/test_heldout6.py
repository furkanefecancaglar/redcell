"""Set 6 as a regression guard.

Measured once and retired. No rule was written against it, so both halves are genuine held-out
results — but the attack half is asserted only not to get worse. Freezing 14/26 as a threshold
would turn a measurement into a target, which is the failure this whole train/judge split exists
to prevent.
"""
import sys

sys.path.insert(0, '/home/furkan/redcell')
import redcell_firewall as fw  # noqa: E402
from heldout_corpus6 import ATTACKS_SUPPORTED, ATTACKS_UNSUPPORTED, BENIGN  # noqa: E402

DETECTED_AT_MEASUREMENT = 14


def _detected(text):
    return fw.inspect(text).action in ("flag", "block")


def test_no_false_positives_on_set6_benign():
    fps = [t for t in BENIGN if _detected(t)]
    assert not fps, "false positives returned: " + repr(fps)


def test_set6_detection_does_not_regress():
    n = sum(1 for t in ATTACKS_SUPPORTED if _detected(t))
    assert n >= DETECTED_AT_MEASUREMENT, (
        "set 6 detection fell from %d to %d" % (DETECTED_AT_MEASUREMENT, n))


def test_unsupported_languages_stay_undetected():
    """Not a defect — a documented limit. Asserted so it cannot become an accidental claim."""
    assert not [t for t in ATTACKS_UNSUPPORTED if _detected(t)]
