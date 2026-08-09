/*!
 * REDCELL Cloudflare Worker — the free, permanent, no-card home for the 0-API surfaces.
 * Serves /firewall (runtime injection verdict) and /scan-config (static resilience score)
 * at the edge. Both are pure JS (no model calls), so this runs on Cloudflare's free plan
 * with no card. The live /scan engine stays on the full server (needs the NIM key).
 *
 * Deploy: see CLOUDFLARE_WORKER.md  (wrangler login → wrangler deploy).
 */
import fw from './redcell.js';
import scan from './redcell_scanner.js';

const inspect = fw.inspect;
const analyze = scan.analyze;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
  });
}

const LANDING = `<!doctype html><meta charset=utf-8><title>REDCELL API</title>
<style>body{font:15px/1.6 system-ui;max-width:720px;margin:40px auto;padding:0 20px;color:#15171d;background:#f4f2ec}
code{background:#eae7de;padding:2px 6px;border-radius:5px}b{color:#c02a2a}</style>
<h1>RED<b>CELL</b> — security layer for AI agents</h1>
<p>Free edge API. Two 0-API surfaces:</p>
<ul>
<li><code>POST /firewall</code> <code>{"input":"..."}</code> → runtime injection verdict (allow/flag/block)</li>
<li><code>POST /scan-config</code> <code>{"system_prompt":"..."}</code> → static resilience score (OWASP LLM Top 10)</li>
<li><code>GET /health</code></li>
</ul>
<p>Example: <code>curl -X POST $URL/firewall -d '{"input":"ignore all previous instructions"}'</code></p>`;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    if (url.pathname === '/' ) return new Response(LANDING, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS } });

    if (url.pathname === '/health') {
      return json({
        ok: true,
        surfaces: {
          'scan-config': 'POST {system_prompt} → static resilience score (0 API)',
          'firewall': 'POST {input} → runtime injection verdict (0 API)',
        },
        detectors: scan.DET.length,
        firewall_rules: fw.RULES.length + 1,
        edge: true,
      });
    }

    if (request.method === 'POST' && url.pathname === '/firewall') {
      const body = await request.json().catch(() => ({}));
      if (!body || !body.input) return json({ error: 'input required' }, 400);
      return json(inspect(String(body.input)));
    }

    if (request.method === 'POST' && url.pathname === '/scan-config') {
      const body = await request.json().catch(() => ({}));
      if (!body || !body.system_prompt) return json({ error: 'system_prompt required' }, 400);
      return json(analyze(String(body.system_prompt)));
    }

    return json({ error: 'not found' }, 404);
  },
};
