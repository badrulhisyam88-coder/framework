/**
 * Verification helper — NOT production code.
 *
 * Phase 54 layout stress test: one ExploitationPath with 3 completed
 * action chains and 4 ghost suggestions. Confirms the layout module
 * places ghosts as siblings of real actions (multiple LR lanes from
 * the path) and not as descendants of the longest existing chain.
 *
 * Run from repo root:
 *   sed 's|https://esm.sh/dagre@0.8.5|/tmp/node_modules/dagre/index.js|' \
 *     frontend/static/js/graph-layout.js > /tmp/graph-layout-test.js
 *   node scripts/verify_phase54_layout.mjs
 */
import { layoutInvestigationGraph, NODE_DIMS }
  from '/tmp/graph-layout-test.js';

const nodes = [];
const edges = [];

// Spine: surface → category → finding → path
nodes.push({ id: 'surface-root', type: 'surface',
             position: {x:0, y:0}, data: { node_id: 'surface-root',
             title: 'http://target/', kind: 'surface' }});
nodes.push({ id: 'cat-misconfig', type: 'category',
             position: {x:0, y:0}, data: { node_id: 'cat-misconfig',
             title: 'Misconfig', finding_count: 1, kind: 'category' }});
nodes.push({ id: 'disc-csp', type: 'finding',
             position: {x:0, y:0}, data: { node_id: 'disc-csp',
             title: 'Missing CSP', kind: 'finding' }});
nodes.push({ id: 'path-disc-csp-injection.xss_reflected',
             type: 'exploitation_path',
             position: {x:0, y:0}, data: { node_id: 'path-disc-csp-injection.xss_reflected',
             title: 'Reflected XSS', kind: 'exploitation_path' }});
edges.push({ id: 'e1', source: 'surface-root', target: 'cat-misconfig', type: 'smoothstep' });
edges.push({ id: 'e2', source: 'cat-misconfig', target: 'disc-csp', type: 'smoothstep' });
edges.push({ id: 'e3', source: 'disc-csp', target: 'path-disc-csp-injection.xss_reflected', type: 'smoothstep' });

// 3 completed action chains, each: action → stage → stage → outcome → evidence
// In the current model an action is anchored at the finding (disc-) via the
// run, NOT at the path. Replicate that: chains hang off the FINDING; ghosts
// hang off the PATH. This matches the actual emission semantics.
for (let i = 1; i <= 3; i++) {
  const runId = `run${i}`;
  const stages = [
    `exec-${runId}-s0`, `exec-${runId}-s1`,
  ];
  const outcome = `exec-${runId}-r0`;
  const evidence = `evidence-${runId}`;

  // Stage 1 anchored at finding (matches _overlay_execution_runs behavior
  // — prev_id starts at parent_node_id = disc-csp).
  nodes.push({ id: stages[0], type: 'execution_stage',
               position: {x:0, y:0}, data: { kind: 'execution_stage',
               title: `chain ${i} stage 1` }});
  edges.push({ id: `e-disc-csp->${stages[0]}`, source: 'disc-csp',
               target: stages[0], type: 'smoothstep' });
  nodes.push({ id: stages[1], type: 'execution_stage',
               position: {x:0, y:0}, data: { kind: 'execution_stage',
               title: `chain ${i} stage 2` }});
  edges.push({ id: `e-${stages[0]}->${stages[1]}`, source: stages[0],
               target: stages[1], type: 'smoothstep' });
  nodes.push({ id: outcome, type: 'outcome',
               position: {x:0, y:0}, data: { kind: 'outcome',
               title: `chain ${i} outcome` }});
  edges.push({ id: `e-${stages[1]}->${outcome}`, source: stages[1],
               target: outcome, type: 'smoothstep' });
  nodes.push({ id: evidence, type: 'evidence',
               position: {x:0, y:0}, data: { kind: 'evidence',
               title: `chain ${i} evidence` }});
  edges.push({ id: `e-${outcome}->${evidence}`, source: outcome,
               target: evidence, type: 'smoothstep' });
}

// 4 ghost suggestions hanging off the PATH (not the finding).
for (let i = 1; i <= 4; i++) {
  const gid = `ghost-path-disc-csp-injection.xss_reflected-ghost_kind_${i}`;
  nodes.push({ id: gid, type: 'action',
               position: {x:0, y:0}, data: { kind: 'action',
               ghost_state: 'ghost', title: `ghost suggestion ${i}` }});
  edges.push({ id: `e-path->${gid}`, source: 'path-disc-csp-injection.xss_reflected',
               target: gid, type: 'smoothstep' });
}

const { nodes: laid } = layoutInvestigationGraph(nodes, edges);

// Sort by (y, x) for readable output.
laid.sort((a, b) => a.position.y - b.position.y || a.position.x - b.position.x);

console.log('=== Laid-out positions ===');
for (const n of laid) {
  const d = NODE_DIMS[n.type] || { w: 240, h: 64 };
  const tag = n.data.ghost_state === 'ghost' ? '[GHOST]' : '       ';
  console.log(
    `  (${String(Math.round(n.position.x)).padStart(5)},`
    + ` ${String(Math.round(n.position.y)).padStart(5)})`
    + `  ${String(d.w).padStart(3)}×${String(d.h).padStart(2)}`
    + `  ${tag} ${n.type.padEnd(18)} ${(n.data.title || '').slice(0, 38)}`,
  );
}

// Overlap check.
let overlaps = 0;
for (let i = 0; i < laid.length; i++) for (let j = i+1; j < laid.length; j++) {
  const a = laid[i], b = laid[j];
  const da = NODE_DIMS[a.type] || { w: 240, h: 64 };
  const db = NODE_DIMS[b.type] || { w: 240, h: 64 };
  const ax2 = a.position.x + da.w, ay2 = a.position.y + da.h;
  const bx2 = b.position.x + db.w, by2 = b.position.y + db.h;
  if (a.position.x < bx2 && ax2 > b.position.x
      && a.position.y < by2 && ay2 > b.position.y) {
    console.log(`  OVERLAP: ${a.id} vs ${b.id}`);
    overlaps++;
  }
}

console.log();
console.log(overlaps === 0 ? '✓ no overlaps' : `✗ ${overlaps} overlap(s)`);

// Bounding box readout.
const xs = laid.map(n => n.position.x);
const ys = laid.map(n => n.position.y);
const xs2 = laid.map(n => n.position.x + (NODE_DIMS[n.type]||{w:240}).w);
const ys2 = laid.map(n => n.position.y + (NODE_DIMS[n.type]||{h:64}).h);
console.log();
console.log('=== Bounding box ===');
console.log(`  x: ${Math.min(...xs)}..${Math.max(...xs2)}`);
console.log(`  y: ${Math.min(...ys)}..${Math.max(...ys2)}`);
