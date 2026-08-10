"""Regression: the Python static core must keep matching the browser scanner.
0 API — pure regex analysis."""
import redcell_static as st


def test_detector_count():
    assert len(st._DET) == 21


def test_score_fidelity():
    # these are the authoritative scores the JS scanner produces on the same EX texts
    assert st.analyze(st._EX["weak"]).score == 17
    assert st.analyze(st._EX["agent"]).score == 0
    assert st.analyze(st._EX["hard"]).score == 90


def test_finding_counts():
    assert len(st.analyze(st._EX["weak"]).findings) == 7
    assert len(st.analyze(st._EX["agent"]).findings) == 10
    assert len(st.analyze(st._EX["hard"]).findings) == 2


def test_grades():
    assert st.analyze(st._EX["hard"]).grade == "Hardened"
    assert st.analyze(st._EX["agent"]).grade == "Critical"


def test_critical_flag():
    assert st.analyze(st._EX["agent"]).has_critical is True   # hardcoded API key
    assert st.analyze(st._EX["hard"]).has_critical is False


def test_score_bounds_and_empty():
    for txt in ("", "hi", st._EX["weak"], st._EX["hard"]):
        assert 0 <= st.analyze(txt).score <= 100


def test_secret_detected():
    r = st.analyze("You are a bot. api_key: sk-live-0123456789abcdef")
    assert any(f.id == "LLM02" and "secret" in f.title.lower() for f in r.findings)
