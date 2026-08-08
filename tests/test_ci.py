"""Regression: the CI gate must fail weak prompts and pass hardened ones. 0 API."""
import redcell_ci as ci


def _gate(text, tmp_path, min_score=60):
    p = tmp_path / "prompt.txt"
    p.write_text(text, encoding="utf-8")
    return ci.run([str(p)], min_score=min_score, use_color=False)


def test_weak_prompt_fails_gate(tmp_path):
    assert _gate(ci._SELF_WEAK, tmp_path) == 1


def test_hard_prompt_passes_gate(tmp_path):
    assert _gate(ci._SELF_HARD, tmp_path) == 0


def test_threshold_matters(tmp_path):
    # hard prompt scores ~95; a min-score above that must fail it
    assert _gate(ci._SELF_HARD, tmp_path, min_score=99) == 1


def test_selftest_green():
    assert ci._selftest() == 0
