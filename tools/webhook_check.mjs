#!/usr/bin/env node
/**
 * Verify the money path: a signed Paddle webhook must upgrade the account, and an unsigned one
 * must not.
 *
 * This is the one path nobody had ever exercised. Paddle's own simulator is sandbox-only, so it
 * cannot be tested from the live dashboard, and testing it in production would mean taking a
 * real payment. It runs against a local Worker with the secret from .dev.vars.
 *
 * The second assertion is the important one. If an unsigned event were accepted, anyone who
 * knew the URL could POST themselves onto the paid plan — the endpoint is public by necessity.
 *
 *   node tools/webhook_check.mjs http://127.0.0.1:8788 <secret>
 */
import { createHmac } from 'node:crypto';

const BASE = (process.argv[2] || 'http://127.0.0.1:8788').replace(/\/$/, '');
const SECRET = process.argv[3];
if (!SECRET) { console.log('usage: webhook_check.mjs <base> <secret>'); process.exit(2); }

const fail = [], ok = [];

const email = 'webhookcheck' + Math.floor(Date.now() / 1000) + '@example.org';
const pass = 'Str0ng-Pass-9xQ';
let cookie = '';
const call = async (path, opts = {}) => {
  const r = await fetch(BASE + path, { ...opts, headers: { 'Content-Type': 'application/json', Cookie: cookie, ...(opts.headers || {}) } });
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  let b = null; try { b = JSON.parse(await r.text()); } catch (e) { }
  return { status: r.status, body: b };
};

const reg = await call('/auth/register', { method: 'POST', body: JSON.stringify({ email, password: pass }) });
if (reg.status !== 200) { console.log('could not register against ' + BASE + ': ' + reg.status); process.exit(1); }
const me = await call('/auth/export');
const uid = me.body?.account?.id;
if (!uid) { console.log('could not read the account id'); process.exit(1); }

const body = JSON.stringify({
  event_type: 'subscription.activated',
  data: { id: 'sub_check', status: 'active', customer_id: 'ctm_check',
    custom_data: { user_id: uid, plan: 'pro' },
    current_billing_period: { ends_at: '2026-12-31T00:00:00Z' } },
});
const ts = String(Math.floor(Date.now() / 1000));
const h1 = createHmac('sha256', SECRET).update(ts + ':' + body).digest('hex');

const unsigned = await fetch(BASE + '/billing/webhook/paddle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
if (unsigned.status === 200) fail.push('an UNSIGNED webhook was accepted — anyone could grant themselves Pro');
else ok.push('unsigned webhook rejected (' + unsigned.status + ')');

const signed = await fetch(BASE + '/billing/webhook/paddle', {
  method: 'POST', headers: { 'Content-Type': 'application/json', 'Paddle-Signature': `ts=${ts};h1=${h1}` }, body });
if (signed.status !== 200) fail.push('a correctly signed webhook was rejected (' + signed.status + ')');
else ok.push('signed webhook accepted');

await new Promise((r) => setTimeout(r, 1500));
const after = await call('/auth/me');
if (after.body?.plan !== 'pro') fail.push('the account did not become pro after activation: ' + JSON.stringify(after.body));
else ok.push('account upgraded to pro');

const sarif = await fetch(BASE + '/history.sarif', { headers: { Cookie: cookie } });
if (sarif.status !== 200) fail.push('the Pro gate did not open: /history.sarif returned ' + sarif.status);
else ok.push('Pro gate opened (/history.sarif 200)');

await call('/auth/delete', { method: 'POST', body: JSON.stringify({ password: pass }) });

console.log('webhook check against ' + BASE);
ok.forEach((o) => console.log('  ok   ' + o));
if (fail.length) { console.log('\nFAIL:'); fail.forEach((f) => console.log('  x  ' + f)); process.exit(1); }
console.log('\nPASS — the money path works and cannot be forged');
