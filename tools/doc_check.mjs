#!/usr/bin/env node
/**
 * Verify that the repository's own documentation is true.
 *
 * The other layers check the deployed product. Nothing checked the repo, and it drifted badly:
 * README described REDCELL as a local Python CLI long after the product became a deployed
 * Worker, claimed 37 firewall rules while the code shipped 38, and DEPLOY.md recommended
 * deploying to a fly.io app name that belongs to somebody else. Every one of those was read by
 * anyone evaluating the project — which is the worst possible audience for a stale claim.
 *
 * Checks, in order of how badly each one bit us:
 *   1. counts asserted in prose match /health
 *   2. local paths referenced in markdown exist
 *   3. links to our own domain resolve
 *   4. retired hosts are not presented as ours
 *
 * Usage: node tools/doc_check.mjs [baseUrl]
 */
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BASE = (process.argv[2] || 'https://redcell.redcellv1.workers.dev').replace(/\/$/, '');
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/* Identify our own traffic so it stays out of the public counters at /stats. This layer was
   added without the wrapper the other two tools have, and it fetches every REDCELL link in
   every document on each run — which is where "52 real landing visits" came from. */
const _fetch = globalThis.fetch;
globalThis.fetch = async (url, opts = {}) => {
  // Retry belongs in the wrapper, not at each call site: this same transient-network crash was
  // fixed four times in a row, once per new fetch, before being put where new fetches inherit it.
  const withHeaders = { ...opts, headers: { 'User-Agent': 'redcell-verify/1', 'X-REDCELL-Synthetic': '1', ...(opts.headers || {}) } };
  let last;
  for (let i = 0; i < 3; i++) {
    try { return await _fetch(url, withHeaders); }
    catch (e) { last = e; await new Promise((r) => setTimeout(r, 500 * (i + 1))); }
  }
  throw last;
};

const failures = [];
const ok = [];
const fail = (where, msg) => failures.push(where + ': ' + msg);

// Markdown at the repo root plus attic/, which must stay honest about being retired.
// The backlog is a historical log — it records what we believed at the time, including the
// mistakes, so auditing it for present-tense truth would be wrong.
const SKIP = new Set(['REDCELL_BACKLOG.md']);
const docs = [];
// GTM/ was outside the sweep, so the launch copy kept claiming 37 detectors and 188 tests
// long after both were corrected everywhere else. The documents most likely to be published
// are exactly the ones that must not drift.
for (const d of ['.', 'attic', 'services/api', 'GTM']) {
  const dir = join(ROOT, d);
  if (!existsSync(dir)) continue;
  for (const f of readdirSync(dir)) {
    if (f.endsWith('.md') && !SKIP.has(f) && statSync(join(dir, f)).isFile()) {
      docs.push({ rel: d === '.' ? f : d + '/' + f, path: join(dir, f) });
    }
  }
}

// Retry the ground-truth fetch as well. The link checks were given a retry and this one was
// not, so a single dropped connection failed the whole layer with "cannot verify counts".
let health = null;
for (let i = 0; i < 3 && !health; i++) {
  health = await fetch(BASE + '/health').then((r) => r.json()).catch(() => null);
  if (!health) await new Promise((r) => setTimeout(r, 600 * (i + 1)));
}
if (!health) {
  console.log('doc check: /health unreachable, cannot verify counts');
  process.exit(1);
}

for (const doc of docs) {
  const text = readFileSync(doc.path, 'utf8');

  /* 1 — a number stated in prose must match what the code actually ships. */
  // A number the text explicitly frames as past ("used to say 37") is a description of a fixed
  // bug, not a live claim. Flagging it would push the docs toward vagueness about their own
  // history, which is the opposite of what this layer is for.
  const historical = (idx) => /used to|previously|earlier|no longer|was advertising|while the code shipped/i
    .test(text.slice(Math.max(0, idx - 160), idx + 160));
  const check = (re, truth, label) => {
    for (const m of text.matchAll(re)) {
      if (historical(m.index)) continue;
      if (!truth.includes(Number(m[1])))
        fail(doc.rel, 'claims ' + m[1] + ' ' + label + ', /health says ' + truth.join(' or '));
    }
  };
  check(/(\d+)\s+firewall\s+(?:rules|detectors)/gi, [health.firewall_rules], 'firewall rules');
  check(/(?<![\d/])(\d+)\s+(?:static\s+)?detectors/gi, [health.detectors, health.firewall_rules], 'detectors');
  // a ratio like "13/19 attacks" is a result from a corpus, not a claim about the shipped count
  check(/(?<![\d/])(\d+)\s+attacks?\b/gi, [health.attacks], 'attacks');

  /* 2 — a path named in the docs must exist. A README table pointing at a directory that was
         renamed reads as authoritative and is simply wrong. */
  for (const m of text.matchAll(/`([a-zA-Z0-9_./-]+\/[a-zA-Z0-9_./-]*)`/g)) {
    const p = m[1];
    if (p.startsWith('http') || p.includes('*') || p.startsWith('/') || p.includes('..')) continue;
    if (/\/\./.test(p)) continue;   // `redcell_toolcheck.py/.js` names two files, it is not a path
    if (!/\.(py|js|mjs|md|toml|yaml|yml|sh|ini|txt)$/.test(p) && !p.endsWith('/')) continue;
    if (!existsSync(join(ROOT, p))) fail(doc.rel, 'references `' + p + '` which does not exist');
  }

  /* 3 — links to our own site must resolve. Third-party links are not our business to police. */
  for (const m of text.matchAll(/https:\/\/redcell\.redcellv1\.workers\.dev(\/[^\s)`'"]*)?/g)) {
    const url = m[0].replace(/[.,]$/, '');
    // Retry transient failures: a dropped connection is not evidence that a documented link
    // is dead, and reporting it as dead sends someone chasing a URL that works.
    let r = null;
    for (let i = 0; i < 3 && !r; i++) {
      r = await fetch(url).catch(() => null);
      if (!r) await new Promise((res) => setTimeout(res, 500 * (i + 1)));
    }
    // 400 on a GET means the route is there and telling us a parameter is missing — that is
    // presence, which is all this check is for. The convenience GETs answer exactly that.
    if (r && r.status === 400) continue;
    if (r && (r.status === 404 || r.status === 405)) {
      // POST-only endpoints are documented by URL. An empty POST proves the route exists:
      // it answers 400 for a missing field, and only a genuinely absent route answers 404.
      const p = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).catch(() => null);
      // 400 (missing field) or 401 (unsigned webhook) means the route is there and rejecting a
      // deliberately empty body, which is exactly what a documented POST endpoint should do.
      if (p && [200, 400, 401, 403, 422].includes(p.status)) continue;
      if (p && p.status !== 404) r = p;
    }
    if (!r || r.status >= 400) fail(doc.rel, url + ' -> ' + (r ? 'HTTP ' + r.status : 'unreachable'));
  }

  /* 4 — retired infrastructure must not be described as ours. This is the specific lie that
         was in SYSTEM_DESIGN.md ("no downtime since the fly.io pivot") for weeks. */
  for (const host of ['fly.dev', 'onrender.com']) {
    if (!text.includes(host)) continue;
    const lines = text.split('\n').filter((l) => l.includes(host));
    for (const l of lines) {
      const disowned = /not ours|belongs to|someone else|retired|superseded|was\b|earlier|do not/i.test(l);
      // a nearby disclaimer counts too — the statement may span lines
      const idx = text.indexOf(l);
      const near = text.slice(Math.max(0, idx - 400), idx + 400);
      if (!disowned && !/not ours|belongs to someone else|never been installed/i.test(near))
        fail(doc.rel, 'mentions ' + host + ' without disowning it: "' + l.trim().slice(0, 90) + '"');
    }
  }
}

ok.push(docs.length + ' documents checked against /health and the filesystem');

console.log('doc check against ' + BASE);
ok.forEach((o) => console.log('  ok   ' + o));
if (failures.length) {
  console.log('\nFAIL (' + failures.length + '):');
  failures.forEach((f) => console.log('  x  ' + f));
  process.exit(1);
}
console.log('\nPASS — the repository documentation matches the product');
