// Kept in the repo because the live path cannot be exercised without NIM keys and KV writes.
// Simulate the accumulate-and-flush arithmetic exactly as written in the worker, and assert the
// invariant that matters: every attempt is counted once — none lost at a flush boundary, none
// double-counted. Flush thresholds are where off-by-one lives.
const FLUSH_MS = 5 * 60_000, BREACH_FLUSH_EVERY = 5;
let store = { attempts: 0, wins: 0, blocked: 0 }, techStore = {}, writes = 0;
let _bPending = { attempts: 0, wins: 0, blocked: 0 }, _bTech = {}, _bLastFlush = 0;

function play(now, win, blocked, ids) {
  _bPending.attempts += 1;
  if (win) _bPending.wins += 1;
  if (blocked) _bPending.blocked += 1;
  for (const id of ids) _bTech[id] = (_bTech[id] || 0) + 1;
  if (_bLastFlush === 0) _bLastFlush = now;
  if (_bPending.attempts >= BREACH_FLUSH_EVERY || (now - _bLastFlush) > FLUSH_MS) {
    const pend = _bPending, tech = _bTech;
    _bPending = { attempts: 0, wins: 0, blocked: 0 }; _bTech = {};
    _bLastFlush = now;
    store.attempts += pend.attempts; store.wins += pend.wins; store.blocked += pend.blocked;
    writes += 1;
    if (Object.keys(tech).length) {
      for (const [id, n] of Object.entries(tech)) techStore[id] = (techStore[id] || 0) + n;
      writes += 1;
    }
  }
}

let t = 1_000_000, expWins = 0, expBlocked = 0, expTech = 0;
const N = 23;
for (let i = 0; i < N; i++) {
  const win = i % 7 === 0, blocked = i % 3 === 0, ids = i % 2 ? ['direct-injection'] : [];
  if (win) expWins++; if (blocked) expBlocked++; if (ids.length) expTech++;
  t += 1000;
  play(t, win, blocked, ids);
}
const flushed = store.attempts, pending = _bPending.attempts;
console.log(`  ${N} plays -> flushed ${flushed}, still pending ${pending}, KV writes for aggregates: ${writes}`);
console.log(`  conservation: ${flushed + pending === N ? 'OK — nothing lost or double counted' : 'BROKEN'}`);
console.log(`  wins  ${store.wins + _bPending.wins}/${expWins}  blocked ${store.blocked + _bPending.blocked}/${expBlocked}`);
console.log(`  techniques counted ${(techStore['direct-injection'] || 0) + (_bTech['direct-injection'] || 0)}/${expTech}`);
console.log(`  per-attempt aggregate writes: ${(writes / N).toFixed(2)} (was 2.00 before batching)`);

// Exit non-zero if the invariant breaks, so this can be wired into CI later.
if (store.attempts + _bPending.attempts !== N) process.exit(1);
