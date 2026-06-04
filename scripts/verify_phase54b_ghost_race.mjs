/**
 * Verification helper — NOT production code.
 *
 * Phase 54b Fix 2 verification: simulate the polling race that the
 * optimistic ghost activation has to survive. Does NOT load React or
 * browser DOM. Mirrors the relevant merge-logic and ref-state
 * structures from investigation-flow.js in plain JS and asserts:
 *
 *   Scenario A: late-arriving poll response with the same ghost
 *     (ghost_state="ghost") does NOT clobber the optimistic
 *     "activating" state.
 *
 *   Scenario B: when the ghost id disappears from the next poll
 *     (real run spawned), the activating record is cleared and
 *     the node is no longer forced to "activating".
 *
 *   Scenario C: when 6s elapses without the ghost disappearing,
 *     the timeout handler clears the activating record and
 *     dispatches inv-ghost-activation-timeout.
 *
 * Run from repo root:
 *   node scripts/verify_phase54b_ghost_race.mjs
 */

// ── Mirror the production state-management logic exactly ─────────────
const activatingIds = new Set();
const activationTimers = new Map();
let dispatched = [];

function dispatch(name, detail) {
  dispatched.push({ name, detail });
}

function onGhostActivate(nodeId, timeoutMs = 6000) {
  activatingIds.add(nodeId);
  const prev = activationTimers.get(nodeId);
  if (prev) clearTimeout(prev);
  const t = setTimeout(() => {
    activatingIds.delete(nodeId);
    activationTimers.delete(nodeId);
    dispatch('inv-ghost-activation-timeout', { nodeId });
  }, timeoutMs);
  activationTimers.set(nodeId, t);
}

// Merge function — same algorithm as the production refresh handler.
function merge(prevNodes, freshNodes) {
  const freshNodeIds = new Set(freshNodes.map(n => n.id));
  // Clear activatingIds whose ghosts disappeared (real run spawned).
  for (const id of [...activatingIds]) {
    if (!freshNodeIds.has(id)) {
      activatingIds.delete(id);
      const t = activationTimers.get(id);
      if (t) { clearTimeout(t); activationTimers.delete(id); }
    }
  }
  const merged = freshNodes.map(n => {
    const data = { ...n.data, __archived: false };
    if (activatingIds.has(n.id) && data.ghost_state === 'ghost') {
      data.ghost_state = 'activating';
    }
    return { ...n, data };
  });
  for (const old of prevNodes) {
    if (freshNodeIds.has(old.id)) continue;
    merged.push({ ...old, data: { ...old.data, __archived: true } });
  }
  return merged;
}

function gs(nodes, id) {
  const n = nodes.find(x => x.id === id);
  return n ? n.data.ghost_state : undefined;
}

// ── Scenario A: late poll clobber test ───────────────────────────────
console.log('─── Scenario A — late poll arrives after click ───');

// Initial state: ghost node from the backend.
let nodes = [{ id: 'ghost-x', data: { ghost_state: 'ghost' } }];

// Operator clicks the ghost. Optimistic flip + register activating.
onGhostActivate('ghost-x');
nodes = nodes.map(n => n.id === 'ghost-x'
  ? { ...n, data: { ...n.data, ghost_state: 'activating' } }
  : n);
console.log('  T+50ms after click — ghost_state:', gs(nodes, 'ghost-x'),
            '(expected: activating)');

// Late-arriving poll N response: backend still says "ghost".
const lateFresh = [{ id: 'ghost-x', data: { ghost_state: 'ghost' } }];
nodes = merge(nodes, lateFresh);
const afterLate = gs(nodes, 'ghost-x');
console.log('  T+200ms after merge — ghost_state:', afterLate,
            '(expected: activating)');
const scenarioA_pass = afterLate === 'activating';
console.log('  Scenario A:', scenarioA_pass ? 'PASS' : 'FAIL');
console.log();

// ── Scenario B: real run spawned → ghost gone → clear ───────────────
console.log('─── Scenario B — real run spawns, ghost disappears ───');

const realRunFresh = [
  { id: 'exec-run123-s0', data: { kind: 'execution_stage', ghost_state: undefined } },
];
nodes = merge(nodes, realRunFresh);
console.log('  after-real-run nodes:', nodes.map(n => n.id));
const activatingCleared = !activatingIds.has('ghost-x');
const timerCleared      = !activationTimers.has('ghost-x');
console.log('  activatingIds.has(ghost-x):', activatingIds.has('ghost-x'),
            '(expected: false)');
console.log('  activationTimers.has(ghost-x):', activationTimers.has('ghost-x'),
            '(expected: false)');
const scenarioB_pass = activatingCleared && timerCleared;
console.log('  Scenario B:', scenarioB_pass ? 'PASS' : 'FAIL');
console.log();

// ── Scenario C: timeout fires after 6s with no spawn ────────────────
console.log('─── Scenario C — timeout fires after 6s of no progress ───');

// Reset.
activatingIds.clear();
for (const t of activationTimers.values()) clearTimeout(t);
activationTimers.clear();
dispatched = [];

// Use a 100ms timeout so the test doesn't actually wait 6s.
onGhostActivate('ghost-y', 100);
console.log('  T+0ms — activatingIds.has(ghost-y):',
            activatingIds.has('ghost-y'), '(expected: true)');

setTimeout(() => {
  const stillActivating = activatingIds.has('ghost-y');
  const eventFired = dispatched.some(
    d => d.name === 'inv-ghost-activation-timeout'
         && d.detail.nodeId === 'ghost-y',
  );
  console.log('  T+150ms — activatingIds.has(ghost-y):', stillActivating,
              '(expected: false)');
  console.log('  T+150ms — inv-ghost-activation-timeout fired with nodeId:',
              eventFired);
  const scenarioC_pass = !stillActivating && eventFired;
  console.log('  Scenario C:', scenarioC_pass ? 'PASS' : 'FAIL');
  console.log();
  console.log('='.repeat(40));
  const ok = scenarioA_pass && scenarioB_pass && scenarioC_pass;
  console.log('OVERALL:', ok ? 'PASS' : 'FAIL');
  process.exit(ok ? 0 : 1);
}, 150);
