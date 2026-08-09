"""Regression: the resilience benchmark runs and ranks sensibly. 0 API."""
import benchmark


def test_runs_and_ranked_desc():
    rows = benchmark.run()
    assert len(rows) >= 8
    scores = [r["score"] for r in rows]
    assert scores == sorted(scores, reverse=True)


def test_hardened_beats_naive():
    by = {r["name"]: r for r in benchmark.run()}
    assert by["Hardened enterprise"]["score"] > by["Naive support bot"]["score"]


def test_hardened_grade_and_naive_weak():
    by = {r["name"]: r for r in benchmark.run()}
    assert by["Hardened enterprise"]["grade"] in ("Hardened", "Resilient")
    assert by["Naive support bot"]["score"] <= 40


def test_row_shape():
    for r in benchmark.run():
        assert {"name", "score", "grade", "findings", "has_critical", "top_finding"} <= set(r)
