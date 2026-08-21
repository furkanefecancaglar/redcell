#!/usr/bin/env node
/**
 * Rendered-page audit for the REDCELL Worker.
 *
 * Every page is assembled by string concatenation, so the failure mode that
 * matters is not "does the source parse" (node --check already covers that) but
 * "is the HTML we actually serve well-formed". This shipped once: an external
 *   <script src=...></script>
 * was folded into the inline script string, its closing tag terminated the inline
 * block early, and the rest of the page's JavaScript rendered as visible text.
 * node --check passed, pytest passed, and the page was still broken.
 *
 * Usage:  node tools/page_audit.mjs [baseUrl]
 *         node tools/page_audit.mjs http://127.0.0.1:8787
 */
const BASE = (process.argv[2] || 'https://redcell.redcellv1.workers.dev').replace(/\/$/, '');

const PAGES = [
  '/', '/docs', '/agents', '/ci', '/mcp', '/quickstart', '/example', '/vs',
  '/methodology', '/changelog', '/benchmark', '/breach', '/pitch',
  '/signup', '/login', '/terms', '/privacy', '/refunds',
];

// Ground truth for the numbers the marketing copy quotes. A security product that
// advertises a detector count it does not have loses the argument before it starts;
// the landing said 37 while the code and /health said 38.
let TRUTH = null;
async function loadTruth() {
  try {
    const r = await fetch(BASE + '/health');
    const d = await r.json();
    TRUTH = { firewall: d.firewall_rules, statics: d.detectors, attacks: d.attacks };
  } catch (e) { TRUTH = null; }
}

const failures = [];
const notes = [];
function fail(page, msg) { failures.push(page + ': ' + msg); }

/** Inline <script> blocks, excluding <script src=...> which have no body. */
function inlineScripts(html) {
  const out = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    if (/\bsrc\s*=/i.test(m[1])) continue;
    out.push(m[2]);
  }
  return out;
}

/** Text the user can actually read, with script/style stripped out. */
function visibleText(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ');
}

async function get(url, tries = 3) {
  let last;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { redirect: 'manual' });
      return { status: r.status, body: await r.text() };
    } catch (e) {
      last = e;
      await new Promise((r) => setTimeout(r, 400 * (i + 1)));
    }
  }
  throw last;
}

async function audit(page) {
  let res, html;
  try {
    const r = await get(BASE + page);
    res = { status: r.status };
    html = r.body;
  } catch (e) {
    return fail(page, 'request failed: ' + e.message);
  }
  if (res.status !== 200) return fail(page, 'HTTP ' + res.status);

  // 1. the bug that shipped: a nested <script> inside an inline block
  for (const body of inlineScripts(html)) {
    if (/<script\b/i.test(body)) {
      fail(page, 'inline <script> block contains a nested <script> tag — the closing tag will end the block early');
    }
  }

  // 2. its symptom, caught independently: raw code visible as page text
  const text = visibleText(html);
  for (const marker of ['function q(i)', 'async function post(', 'document.getElementById(', 'Paddle.Checkout.open']) {
    if (text.includes(marker)) fail(page, 'raw JavaScript is rendered as page text (found "' + marker + '")');
  }

  // 3. unrendered template artifacts
  if (/\$\{[A-Za-z_]/.test(html)) fail(page, 'unrendered ${...} template placeholder in output');
  if (html.includes('undefined<') || html.includes('>undefined')) notes.push(page + ': literal "undefined" in output');

  // 4. tag balance for the elements we build by hand
  for (const tag of ['script', 'style', 'footer', 'header']) {
    const open = (html.match(new RegExp('<' + tag + '\\b', 'gi')) || []).length;
    const close = (html.match(new RegExp('</' + tag + '>', 'gi')) || []).length;
    if (open !== close) fail(page, '<' + tag + '> unbalanced: ' + open + ' open / ' + close + ' close');
  }

  // 5. the chrome every page is supposed to carry
  if (!html.includes('class=rf')) fail(page, 'shared footer missing');
  for (const l of ['/terms', '/privacy', '/refunds']) {
    if (!html.includes('href="' + l + '"')) fail(page, 'legal link ' + l + ' missing from footer');
  }

  // 6. quoted numbers must match what the code actually ships
  if (TRUTH) {
    const claims = [
      [/<b>(\d+)<\/b>\s*(?:&nbsp;)?\s*firewall detectors/g, TRUTH.firewall, 'firewall detectors'],
      [/(\d+)\s+detectors block injection/g, TRUTH.firewall, 'firewall detectors'],
      [/<b>(\d+)<\/b>\s*(?:&nbsp;)?\s*static checks/g, TRUTH.statics, 'static checks'],
    ];
    for (const [re, truth, what] of claims) {
      let m;
      while ((m = re.exec(html))) {
        if (Number(m[1]) !== truth) fail(page, 'claims ' + m[1] + ' ' + what + ' but the code ships ' + truth);
      }
    }
  }

  // 7. the old dark/red identity must be gone
  // the first sweep only listed the primary tokens, so tinted leftovers (a dark-red border,
  // a red wash behind a card) survived on five pages unnoticed. Check those too.
  for (const tok of ['0b0d12', 'ff3b46', '9aa4b6', 'eaedf4', '3a2030', '2a1918', 'ff5b64',
                     'rgba(255,59,70', 'rgba(255, 59, 70']) {
    if (html.includes(tok)) fail(page, 'legacy dark/red token ' + tok + ' still present');
  }
}

const t0 = Date.now();
await loadTruth();
for (const p of PAGES) await audit(p);   // sequential: parallel bursts trip the edge

console.log('audited ' + PAGES.length + ' pages against ' + BASE + ' in ' + (Date.now() - t0) + 'ms');
if (notes.length) { console.log('\nnotes:'); notes.forEach((n) => console.log('  - ' + n)); }
if (failures.length) {
  console.log('\nFAIL (' + failures.length + '):');
  failures.forEach((f) => console.log('  x ' + f));
  process.exit(1);
}
console.log('PASS — all pages well-formed, chrome intact, no legacy tokens');
