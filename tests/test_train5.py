"""Set 5 as a regression guard.

This is a training set — rules were written against it, so its pass rate is not evidence of
anything. It is kept because the six families it covers were each closed by a rule that has to
survive its own benign twins, and those twins are the part most likely to rot: every false
positive this project has shipped came from a rule that matched a family rather than an intent.
"""
import sys

sys.path.insert(0, '/home/furkan/redcell')
import redcell_firewall as fw  # noqa: E402
from train_corpus5 import ATTACKS, BENIGN  # noqa: E402


def _detected(text):
    return fw.inspect(text).action in ("flag", "block")


def test_no_false_positives_on_the_benign_twins():
    fps = [t for t in BENIGN if _detected(t)]
    assert not fps, "false positives returned: " + repr(fps)


def test_every_trained_family_is_caught():
    missed = [t for t in ATTACKS if not _detected(t)]
    assert not missed, "regression, these stopped being caught: " + repr(missed)
