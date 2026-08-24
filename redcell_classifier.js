/**
 * Optional second-stage scorer: logistic regression over hashed word uni/bigrams.
 *
 * The rule engine is precise and incomplete — measured at 93-100% precision but 17-28% recall on
 * public third-party corpora. This adds recall on traffic that resembles those corpora, at the
 * cost of a model that has to be trusted rather than read. It is therefore OFF by default and
 * returns a score the caller can act on, rather than silently changing verdicts.
 *
 * No API, no dependency, no network: 3,000 float weights and a dot product. Sub-millisecond.
 *
 * Parity with the Python scorer is not optional — both engines must agree, so the tokenizer uses
 * \p{L} rather than \w. JS's \w is ASCII-only, and the training data is half German; a \w-based
 * split would have silently disagreed with Python on every umlaut.
 */
import MODEL from './redcell_model.js';

const TOKEN = /\p{L}+/gu;
const MAX_CHARS = 4000;

function fnv1a(s) {
  let h = 0x811c9dc5;
  // Iterate CODE POINTS, not UTF-16 units. Python's ord() walks code points, so charCodeAt made
  // the two scorers disagree on any astral character — caught on mathematical bold letters,
  // which are exactly what an obfuscated payload uses.
  for (const ch of s) {
    h ^= ch.codePointAt(0) & 0xff;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

/** Raw probability in [0,1] that the text is an injection attempt. */
export function score(text) {
  if (typeof text !== 'string' || !text) return 0;
  const t = text.toLowerCase().slice(0, MAX_CHARS);
  const words = t.match(TOKEN) || [];
  const B = MODEL.buckets;
  const f = new Map();
  const bump = (k, d) => f.set(k, (f.get(k) || 0) + d);
  for (const w of words) bump(fnv1a('u:' + w) % B, 1);
  for (let i = 0; i + 1 < words.length; i++) bump(fnv1a('b:' + words[i] + '_' + words[i + 1]) % B, 1);
  bump(B - 1, Math.min(words.length / 50, 4));
  let nl = 0; for (let i = 0; i < t.length; i++) if (t.charCodeAt(i) === 10) nl++;
  bump(B - 2, nl / 5);
  let br = 0; for (const c of t) if ('{}[]<>|'.indexOf(c) >= 0) br++;
  bump(B - 3, br / 10);

  let norm = 0;
  for (const v of f.values()) norm += v * v;
  norm = Math.sqrt(norm) || 1;

  let z = MODEL.b;
  for (const [k, v] of f) {
    const w = MODEL.w[k];
    if (w !== undefined) z += w * (v / norm);
  }
  z = Math.max(-30, Math.min(30, z));
  return 1 / (1 + Math.exp(-z));
}

/** The threshold chosen for zero false positives on ordinary business traffic. */
export const THRESHOLD = MODEL.thr;

export default { score, THRESHOLD };
