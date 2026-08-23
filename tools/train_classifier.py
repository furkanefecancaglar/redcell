"""Pure-Python logistic regression over hashed word n-grams. No numpy, no sklearn, no API.

Trained ONLY on the public TRAIN splits. The TEST splits are never touched until the final
evaluation, and never used to pick the threshold — that is chosen on a validation slice held out
of TRAIN, because tuning a threshold on the test set is the same sin as tuning rules on it.
"""
import json, math, random, re, sys
from collections import Counter

BUCKETS = 1 << 15
random.seed(12345)          # fixed: Date.now()/random drift would make this unreproducible

TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)

def fnv1a(s):
    """Stable 32-bit hash. Python's built-in hash() is randomised per process, so weights trained
    in one run scored ~0.11 on everything in the next — the model looked dead when it was only
    unreachable. It also has to be computable in JS for the edge port, which hash() never was."""
    h = 0x811c9dc5
    for ch in s:
        h ^= ord(ch) & 0xFF
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

def feats(text):
    t = text.lower()[:4000]
    words = TOKEN.findall(t)
    out = Counter()
    for w in words:
        out[fnv1a("u:" + w) % BUCKETS] += 1
    for a, b in zip(words, words[1:]):
        out[fnv1a("b:" + a + "_" + b) % BUCKETS] += 1
    # a few dense signals a bag of words cannot see
    out[BUCKETS - 1] += min(len(words) / 50.0, 4.0)
    out[BUCKETS - 2] += t.count("\n") / 5.0
    out[BUCKETS - 3] += sum(c in "{}[]<>|" for c in t) / 10.0
    n = math.sqrt(sum(v * v for v in out.values())) or 1.0
    return {k: v / n for k, v in out.items()}

def train(rows, epochs=14, lr0=0.5, l2=1e-6):
    w = {}
    b = 0.0
    data = [(feats(t), y) for t, y in rows]
    for ep in range(epochs):
        random.shuffle(data)
        lr = lr0 / (1 + ep)
        for f, y in data:
            z = b + sum(w.get(k, 0.0) * v for k, v in f.items())
            p = 1 / (1 + math.exp(-max(-30, min(30, z))))
            g = p - y
            b -= lr * g
            for k, v in f.items():
                w[k] = w.get(k, 0.0) * (1 - lr * l2) - lr * g * v
    return w, b

def prob(w, b, text):
    f = feats(text)
    z = b + sum(w.get(k, 0.0) * v for k, v in f.items())
    return 1 / (1 + math.exp(-max(-30, min(30, z))))

def load(path):
    out = []
    for r in json.load(open(path)):
        t = r.get("text") or r.get("prompt")
        out.append((t, int(r["label"])))
    return out

train_rows = load("deepset_train.json") + load("safeguard_train.json")
random.shuffle(train_rows)
cut = int(len(train_rows) * 0.85)
tr, val = train_rows[:cut], train_rows[cut:]
print(f"train {len(tr)}  val {len(val)}  (test splits untouched)")

w, b = train(tr)
print(f"model: {len(w)} non-zero weights")

# threshold chosen on VALIDATION, for precision >= 0.95 — precision is the asset being protected
scored = sorted(((prob(w, b, t), y) for t, y in val), reverse=True)
best_thr, best_rec = 0.99, 0.0
for thr in [i / 100 for i in range(50, 100)]:
    tp = sum(1 for p, y in scored if p >= thr and y == 1)
    fp = sum(1 for p, y in scored if p >= thr and y == 0)
    fn = sum(1 for p, y in scored if p < thr and y == 1)
    if tp + fp == 0: continue
    pre = tp / (tp + fp); rec = tp / (tp + fn) if tp + fn else 0
    if pre >= 0.95 and rec > best_rec:
        best_thr, best_rec = thr, rec
print(f"threshold {best_thr:.2f} chosen on validation (precision>=0.95, recall {best_rec*100:.1f}%)")

def evaluate(name, path):
    rows = load(path)
    tp = fp = tn = fn = 0
    for t, y in rows:
        d = prob(w, b, t) >= best_thr
        tp += y == 1 and d; fn += y == 1 and not d; fp += y == 0 and d; tn += y == 0 and not d
    rec = tp / (tp + fn) if tp + fn else 0; pre = tp / (tp + fp) if tp + fp else 0
    print(f"  {name:<28} recall {rec*100:5.1f}%  precision {pre*100:5.1f}%  FP {fp} ({100*fp/(tn+fp):.1f}%)")

print("\nHELD OUT — never seen in training or threshold selection:")
evaluate("deepset TEST (116)", "deepset_test.json")
evaluate("safe-guard TEST (2060)", "safeguard_test.json")
json.dump({"w": {str(k): round(v, 6) for k, v in w.items() if abs(v) > 1e-4},
           "b": b, "thr": best_thr, "buckets": BUCKETS},
          open("lr_model.json", "w"))
print("\nweights written to lr_model.json")
