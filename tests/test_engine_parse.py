"""Regression: engine judge-parsing + auto-failover selection. 0 API — only the
pure helpers are exercised; the live engine (chat/run_scan/probe_alive) is never called."""
import redcell_engine as e


# ---- _extract_verdict_object: robust to verbose/nested/think-block/junk output ----
def test_verdict_clean():
    assert e._extract_verdict_object('{"verdict":"FAIL","confidence":0.9,"reason":"leak"}')["verdict"] == "FAIL"


def test_verdict_verbose_prefix():
    assert e._extract_verdict_object('The agent refused. {"verdict":"PASS","confidence":0.8,"reason":"ok"}')["verdict"] == "PASS"


def test_verdict_think_block_and_stray_brace():
    raw = '<think>reasoning with { an unbalanced brace</think> final {"verdict":"FAIL","reason":"y"}'
    assert e._extract_verdict_object(raw)["verdict"] == "FAIL"


def test_verdict_nested_object():
    assert e._extract_verdict_object('{"verdict":"FAIL","meta":{"a":1,"b":[1,2]},"reason":"y"}')["verdict"] == "FAIL"


def test_verdict_skips_non_verdict_object():
    assert e._extract_verdict_object('{"note":"analyzing"} then {"verdict":"PASS","confidence":1,"reason":"r"}')["verdict"] == "PASS"


def test_verdict_none_when_absent():
    assert e._extract_verdict_object("there is no json verdict here") is None


# ---- _parse_batch ----
def test_parse_batch_by_id():
    raw = '[{"id":"a","verdict":"PASS","confidence":0.9,"reason":"r"},{"id":"b","verdict":"FAIL","confidence":0.8,"reason":"r2"}]'
    out = e._parse_batch(raw, ["a", "b"])
    assert out["a"]["verdict"] == "PASS" and out["b"]["verdict"] == "FAIL"


def test_parse_batch_positional_fallback():
    raw = '[{"verdict":"FAIL","confidence":1,"reason":"r"}]'   # no id → align by position
    assert e._parse_batch(raw, ["only"])["only"]["verdict"] == "FAIL"


def test_parse_batch_ignores_bad_verdict():
    raw = '[{"id":"a","verdict":"MAYBE","confidence":1,"reason":"r"}]'
    assert "a" not in e._parse_batch(raw, ["a"])


# ---- auto_select_judge (mock probes; no network) ----
def test_auto_select_prefers_distinct_alive_lowest_latency():
    p = {"nemotron": {"alive": True, "latency": 1.0},
         "minimax": {"alive": True, "latency": 3.0},
         "glm": {"alive": False, "error": "timeout"}}
    assert e.auto_select_judge("nemotron", p) == "minimax"


def test_auto_select_falls_back_to_target_when_no_distinct():
    p = {"nemotron": {"alive": True, "latency": 1.0}}
    assert e.auto_select_judge("nemotron", p) == "nemotron"


def test_auto_select_picks_only_alive_even_if_target_down():
    p = {"nemotron": {"alive": False, "error": "410"}, "minimax": {"alive": True, "latency": 3.0}}
    assert e.auto_select_judge("nemotron", p) == "minimax"


def test_autofailover_off_by_default_uses_configured_judge():
    assert e.AUTOFAILOVER is False
    assert e._judge_engine() == e.JUDGE_ENGINE
