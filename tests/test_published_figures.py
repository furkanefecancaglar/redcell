"""Every number printed on the site, tied to the thing it describes.

Round 93 found two published figures that nothing was checking: a PyPI claim that pointed at
another author's package, and an "adds about 3 ms" that no measurement here could support. The
pattern was the same in both — a precision claim about something nobody measured. Engine numbers
survive audits because tests assert them; prose numbers rot because nothing does.

So this file asserts the prose. Timings are bounded loosely and deliberately: the purpose is to
catch a claim rotting by an order of magnitude on a machine that is not a benchmark rig, not to
police jitter. A tight bound here would fail on a busy laptop and get deleted, which is worse
than no bound at all.
"""
import json
import os
import re
import subprocess
import sys
import time

import pytest

sys.path.insert(0, "/home/furkan/redcell")
import redcell_firewall as fw  # noqa: E402

ROOT = "/home/furkan/redcell"
NODE = "/home/furkan/.nvm/versions/node/v22.23.2/bin/node"
TYPICAL = "Can you confirm the delivery date for order 4412 please?"


def _worker():
    with open(os.path.join(ROOT, "worker.js"), encoding="utf-8") as f:
        return f.read()


def test_the_16_kb_inspection_cap_is_real_and_identical_in_both_engines():
    """The site says inspection is capped at the first 16 KB so worst-case CPU stays bounded.
    Two engines serve that promise and they could drift apart silently."""
    assert fw._MAX_INSPECT == 16384
    with open(os.path.join(ROOT, "redcell.js"), encoding="utf-8") as f:
        js = f.read()
    m = re.search(r"const MAX_INSPECT\s*=\s*(\d+)", js)
    assert m and int(m.group(1)) == fw._MAX_INSPECT, "the JS engine caps at a different size"
    assert "16 KB" in _worker() or "16&nbsp;KB" in _worker()


def test_the_python_engine_latency_claim_has_not_rotted():
    """Published as roughly 650 us for a typical message under CPython."""
    fw.inspect(TYPICAL)
    t0 = time.perf_counter()
    for _ in range(300):
        fw.inspect(TYPICAL)
    us = (time.perf_counter() - t0) / 300 * 1e6
    assert us < 6500, "Python engine is %.0f us; the site says roughly 650" % us


@pytest.mark.skipif(not os.path.exists(NODE), reason="node not available")
def test_the_served_engine_latency_claims_have_not_rotted():
    """Published as 50-70 us on a typical message and about 1.3 ms on a 2 KB document, both
    against the JavaScript engine that actually serves the API."""
    script = (
        "const {inspect}=require('%s/redcell.js');"
        "const t='%s';const big='Section 1. '.repeat(180);"
        "for(let i=0;i<3000;i++){inspect(t);inspect(big);}"
        "const b=(f,n)=>{const s=process.hrtime.bigint();for(let i=0;i<n;i++)f();"
        "return Number(process.hrtime.bigint()-s)/n/1000;};"
        "console.log(JSON.stringify([b(()=>inspect(t),20000),b(()=>inspect(big),2000)]));"
        % (ROOT, TYPICAL)
    )
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-400:]
    typical_us, big_us = json.loads(out.stdout.strip().splitlines()[-1])
    assert typical_us < 700, "typical message is %.0f us; the site says 50-70" % typical_us
    assert big_us < 13000, "a 2 KB document is %.0f us; the site says about 1300" % big_us


def test_the_language_count_on_the_landing_page_matches_what_is_documented():
    """The landing page advertises a count of non-English languages. SECURITY.md names them.
    Neither is derived from the other, so they can disagree — and a language count is exactly the
    kind of figure that gets stale when a rule adds a fifth."""
    m = re.search(r"(\d+)\s*non-English languages", _worker())
    assert m, "the landing page no longer states a language count"
    claimed = int(m.group(1))
    with open(os.path.join(ROOT, "SECURITY.md"), encoding="utf-8") as f:
        sec = f.read()
    named = re.search(r"Non-English coverage is ([^.]+)\.", sec)
    assert named, "SECURITY.md no longer names the supported languages"
    count = len(re.split(r",|\band\b", named.group(1)))
    assert claimed == count, (
        "the landing page says %d non-English languages, SECURITY.md names %d (%s)"
        % (claimed, count, named.group(1).strip()))


def test_the_price_has_exactly_one_source_of_truth():
    """It used to live in a constant plus three hand-written "$39" literals on the landing page,
    the pitch page and the account page, kept in sync by a comment saying "keep in sync". A
    visitor seeing one price and being charged another is the worst drift a billing page can have.

    Literals are allowed only inside comments — the explanation of this very bug contains one."""
    src = _worker()
    m = re.search(r"^const PLAN_PRICE_USD = (\d+);", src, re.M)
    assert m, "PLAN_PRICE_USD is gone"
    price = int(m.group(1))

    stripped = re.sub(r"/\*[\s\S]*?\*/", " ", src)
    stripped = re.sub(r"^\s*//.*$", " ", stripped, flags=re.M)
    # Only OUR price counts. A first attempt at this matched any "$NN" and flagged the funding
    # figures on the comparison page ($855M seed, Lakera's $20M) — third-party facts, not our
    # billing. Two shapes are the real risk: the bare current price, and anything "$NN/mo".
    strays = re.findall(r"\$%d\b" % price, stripped)
    strays += [m.group(0) for m in re.finditer(r"\$\d+\s*(?:<[^>]*>)?\s*/mo", stripped)]
    assert not strays, "hand-written price literals are back: %r" % strays

    assert src.index("const PLAN_PRICE_USD") < src.index("const LANDING = "), (
        "PLAN_PRICE_USD must be defined before the module-level page templates that interpolate "
        "it, or they hit the temporal dead zone at load")
    assert "${PLAN_PRICE_USD}" in src and "+ PLAN_PRICE_USD +" in src
    assert price > 0
