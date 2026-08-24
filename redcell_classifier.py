"""Optional second-stage scorer — the Python half of the pair. See redcell_classifier.js.

Kept byte-for-byte equivalent to the JS scorer and asserted so by the parity test. The two must
agree: the Worker serves the JS engine and every published measurement is produced by the Python
one, so a divergence would mean the numbers on the site describe a different product than the
one customers call.
"""
import json
import math
import os
import re
from collections import Counter

_MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", "injection_lr.json")
_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)
_MAX_CHARS = 4000

with open(_MODEL_PATH, encoding="utf-8") as _f:
    _M = json.load(_f)
_W = {int(k): v for k, v in _M["w"].items()}
_B = _M["b"]
_BUCKETS = _M["buckets"]
THRESHOLD = _M["thr"]


def _fnv1a(s):
    """32-bit FNV-1a. Python's built-in hash() is randomised per process — weights trained in one
    run scored ~0.11 on everything in the next — and it cannot be reproduced in JS."""
    h = 0x811C9DC5
    for ch in s:
        h ^= ord(ch) & 0xFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def score(text):
    """Probability in [0,1] that the text is an injection attempt."""
    if not isinstance(text, str) or not text:
        return 0.0
    t = text.lower()[:_MAX_CHARS]
    words = _TOKEN.findall(t)
    f = Counter()
    for w in words:
        f[_fnv1a("u:" + w) % _BUCKETS] += 1
    for a, b in zip(words, words[1:]):
        f[_fnv1a("b:" + a + "_" + b) % _BUCKETS] += 1
    f[_BUCKETS - 1] += min(len(words) / 50.0, 4.0)
    f[_BUCKETS - 2] += t.count("\n") / 5.0
    f[_BUCKETS - 3] += sum(c in "{}[]<>|" for c in t) / 10.0

    norm = math.sqrt(sum(v * v for v in f.values())) or 1.0
    z = _B + sum(_W.get(k, 0.0) * (v / norm) for k, v in f.items())
    return 1 / (1 + math.exp(-max(-30, min(30, z))))
