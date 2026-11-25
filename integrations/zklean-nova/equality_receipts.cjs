// ZKL-NOVA-17: verify hosted shard evidence and bind the exported artifacts.
// Rust verifies Nova/Spartan proofs. This gate validates its receipts and file
// integrity against the source-owned corpus, sample endpoints and shared shape.
"use strict";
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

const FIELD = 28948022309329048855892746252171976963363056481941647379679742748393362948097n;
const SHARDS = 4, CORPUS_CASES = 21, CORPUS_STEPS = 7673;
const MATRIX_SCHEMA = 'zkl-nova-17/equality-frontier-v1';
const MANIFEST_SCHEMA = 'zkl-nova-17/equality-artifact-manifest-v1';
const MATRIX_FIELDS = ['depth', 'rule_read_counts', 'state_ids', 'signature_digests',
  'record_field_bits', 'record_fields', 'read_capacity', 'hashes', 'constraints',
  'wires', 'nonzeros', 'hash_constraints', 'node_domain', 'leaf_domain',
  'term_domain', 'node_vector', 'leaf_vector'];
const TIMER_FILES = ['generation-time.txt', 'time.txt'];
const need = (ok, message) => { if (!ok) throw Error(message); };
const same = (a, b, message) => assert.deepStrictEqual(a, b, message);
const sum = xs => xs.reduce((a, b) => a + b, 0);
const sorted = xs => [...xs].sort();
const unique = xs => [...new Set(xs)];
const integer = (x, lo, hi, label) => need(Number.isSafeInteger(x) && x >= lo && x <= hi, label);
const duration = (x, label) => need(typeof x === 'number' && Number.isFinite(x) && x >= 0, label);

function regular(file, maxBytes = 256 * 1024 * 1024) {
  const s = fs.lstatSync(file);
  need(s.isFile() && !s.isSymbolicLink(), `regular file required: ${file}`);
  integer(s.size, 1, maxBytes, `file size: ${file}`);
  return s.size;
}
function json(file, maxBytes = 16 * 1024 * 1024) {
  regular(file, maxBytes);
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { throw Error(`invalid JSON in ${file}: ${e.message}`); }
}
function digest(file, maxBytes) {
  const bytes = regular(file, maxBytes), h = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r'), buffer = Buffer.alloc(1024 * 1024);
  try {
    for (;;) { const n = fs.readSync(fd, buffer, 0, buffer.length, null); if (!n) break; h.update(buffer.subarray(0, n)); }
  } finally { fs.closeSync(fd); }
  return { sha256: h.digest('hex'), bytes };
}
function scalar(x, label) {
  need(typeof x === 'string' && /^(0|[1-9][0-9]*)$/.test(x) && x.length <= 77, label);
  const n = BigInt(x); need(n < FIELD, label); return n;
}
function state(z, arity, label) {
  need(Array.isArray(z) && z.length === arity, `${label}: state arity`);
  z.forEach((x, i) => scalar(x, `${label}: coordinate ${i}`));
}
function decodeState(z, arity, label) {
  need(Array.isArray(z) && z.length === arity, `${label}: state arity`);
  return z.map((x, i) => {
    need(typeof x === 'string' && /^[0-9a-f]{64}$/.test(x), `${label}: LE hex ${i}`);
    const n = BigInt('0x' + x.match(/../g).reverse().join(''));
    need(n < FIELD, `${label}: canonical field ${i}`); return n.toString();
  });
}
function labels(sourceHead, runId) {
  need(typeof sourceHead === 'string' && /^[0-9a-f]{40}$/.test(sourceHead), 'source head must be a full lowercase Git SHA');
  need(/^[1-9][0-9]*$/.test(String(runId)), 'run ID must be a positive integer');
  const run = Number(runId); integer(run, 1, Number.MAX_SAFE_INTEGER, 'run ID exceeds exact integer range');
  return { source_head: sourceHead, run_id: run };
}
function shardIndex(s) {
  need(typeof s === 'string' && /^[0-3]\/4$/.test(s), 'shard must be 0/4, 1/4, 2/4 or 3/4');
  return Number(s[0]);
}
function inputs() {
  const fixtureFile = path.join(__dirname, 'equality_fixtures.json');
  const sampleFile = path.join(__dirname, 'equality_frontier_sample.json');
  const fixtures = json(fixtureFile), sample = json(sampleFile);
  need(Array.isArray(fixtures) && fixtures.length === CORPUS_CASES, 'expected 21 source fixtures');
  need(fixtures.every(x => /^[a-z][a-z0-9_]*$/.test(x.name) && Array.isArray(x.rows) && x.rows.length > 1), 'invalid source fixture');
  same(unique(fixtures.map(x => x.name)).length, CORPUS_CASES, 'duplicate source fixture name');
  same(sum(fixtures.map(x => x.rows.length)), CORPUS_STEPS, 'source corpus row total');
  same(sample.mode, 'sample', 'committed sample mode');
  same(sample.total_steps, CORPUS_STEPS, 'committed sample row total');
  same(sample.cases.map(x => x.name), fixtures.map(x => x.name), 'committed sample case order');
  integer(sample.depth, 1, 20, 'history depth');
  const arity = sample.depth + 4;
  same(sample.state_ids.length, 2 * arity, 'state input/output binding count');
  const matrix = Object.fromEntries(MATRIX_FIELDS.map(k => { need(Object.hasOwn(sample, k), `missing sample matrix field ${k}`); return [k, sample[k]]; }));
  fixtures.forEach((f, i) => {
    const s = sample.cases[i];
    same(s.steps, f.rows.length, `${f.name}: sample steps`);
    same(s.goal, f.goal, `${f.name}: sample goal`);
    state(s.initial, arity, f.name + ' initial'); state(s.terminal, arity, f.name + ' terminal');
    scalar(s.goal_digest, `${f.name}: goal digest`);
    same(s.initial[1], '0', `${f.name}: initial count`);
    same(s.initial[2], s.goal_digest, `${f.name}: initial goal`);
    same(s.initial[3], '0', `${f.name}: initial seal`);
    need(s.initial.slice(4).every(x => x === '0'), `${f.name}: initial frontier`);
    same(s.terminal[1], String(f.rows.length), `${f.name}: terminal count`);
    same(s.terminal[2], s.goal_digest, `${f.name}: terminal goal`);
    same(s.terminal[3], '1', `${f.name}: terminal seal`);
  });
  return { fixtures, sample, matrix, arity, source_inputs: {
    fixtures: digest(fixtureFile), sample: digest(sampleFile), gate: digest(__filename),
    cargo_lock: digest(path.join(__dirname, 'nova-smoke', 'Cargo.lock'))
  } };
}
function expected(ctx, index) { return ctx.fixtures.map((fixture, i) => ({ fixture, sample: ctx.sample.cases[i] })).filter((_, i) => i % SHARDS === index); }
function matrixFile(file, ctx) {
  const m = json(file, 128 * 1024 * 1024);
  same(sorted(Object.keys(m)), ['rows', 'schema', 'summary'], 'matrix top-level fields');
  same(m.schema, MATRIX_SCHEMA, 'matrix schema');
  same(m.summary, ctx.matrix, 'matrix summary differs from committed sample');
  need(Array.isArray(m.rows) && m.rows.length === ctx.matrix.constraints, 'matrix constraint count');
  let nonzeros = 0;
  for (const row of m.rows) {
    need(Array.isArray(row) && row.length === 3, 'R1CS equation must contain A/B/C');
    for (const lc of row) {
      need(Array.isArray(lc), 'R1CS linear combination'); let prev = -1;
      for (const term of lc) {
        need(Array.isArray(term) && term.length === 2, 'R1CS sparse term');
        const [i, coefficient] = term;
        integer(i, 0, ctx.matrix.wires - 1, 'R1CS wire index'); need(i > prev, 'R1CS terms must be strictly ordered'); prev = i;
        need(scalar(coefficient, 'R1CS coefficient') !== 0n, 'R1CS explicit zero coefficient'); nonzeros++;
      }
    }
  }
  same(nonzeros, ctx.matrix.nonzeros, 'matrix nonzero count');
}
function fullSummary(full, ctx, cases) {
  same(full.mode, 'full', 'all row assignments must be checked');
  for (const k of MATRIX_FIELDS) same(full[k], ctx.matrix[k], `full summary matrix field ${k}`);
  same(full.cases.map(x => x.name), cases.map(x => x.fixture.name), 'full summary shard cases');
  const steps = sum(cases.map(x => x.fixture.rows.length));
  same(full.total_steps, steps, 'full summary steps'); same(full.total_checked, steps, 'full matrix checks');
  same(full.total_mutations_rejected, 4 * cases.length, 'full terminal/goal mutation total');
  same(full.boundary_checks, 2 ** ctx.matrix.depth, 'all frontier boundary insertions');
  const tags = [], constants = new Set(); let rawReads = 0, maxReads = 0;
  cases.forEach(({fixture: f, sample: s}, i) => {
    const c = full.cases[i];
    for (const k of ['name', 'steps', 'goal', 'goal_digest', 'initial', 'terminal']) same(c[k], s[k], `${f.name}: full ${k}`);
    same(c.matrices_checked, f.rows.length, `${f.name}: unchecked matrix rows`);
    same(c.mutations_rejected, 4, `${f.name}: terminal/goal attacks`);
    const traceTags = sorted(unique(f.rows.map(r => r[0])));
    same(c.checked_tags, traceTags, `${f.name}: full rule coverage`); tags.push(...traceTags);
    for (const row of f.rows) {
      const reads = ctx.matrix.rule_read_counts[row[0]];
      integer(reads, 0, ctx.matrix.read_capacity, 'source rule read count'); rawReads += reads; maxReads = Math.max(maxReads, reads);
      if (row[0] === 'JK') { const term = f.rows[row[2]]; need(term?.[0] === 'C', 'source JK constant reference'); constants.add(term[1]); }
    }
  });
  const coverage = full.coverage, pinned = ctx.sample.coverage;
  need(coverage && pinned, 'supplementary coverage missing');
  for (const k of ['name', 'steps', 'goal', 'goal_digest', 'initial', 'terminal']) same(coverage[k], pinned[k], `supplementary ${k}`);
  same(coverage.matrices_checked, coverage.checked_tags.length, 'supplementary sampled tag count');
  same(coverage.checked_tags, sorted(unique(coverage.checked_tags)), 'supplementary tag uniqueness');
  need(coverage.checked_tags.every(t => Object.hasOwn(ctx.matrix.rule_read_counts, t)), 'unknown supplementary tag');
  tags.push(...coverage.checked_tags);
  same(full.distinct_tags_checked, sorted(unique(tags)), 'combined checked tags');
  same(full.constant_ids_challenged, [...constants].sort((a, b) => a - b), 'constant signature coverage');
  same(full.regenerated_rejections.constant_signature, constants.size, 'constant signature attacks');
  same(full.read_stats.rows, steps, 'read-stat rows'); same(full.read_stats.raw, rawReads, 'raw read total');
  same(full.read_stats.max_raw, maxReads, 'maximum read count');
  integer(full.read_stats.unique, 0, rawReads, 'unique read count');
  integer(full.read_stats.max_unique, 0, maxReads, 'maximum unique read count');
  for (const [name, n] of Object.entries(full.regenerated_rejections)) integer(n, 0, 1000000, `regenerated rejection count ${name}`);
}
function proofReceipt(p, f, s, ctx) {
  same(p.name, f.name, 'proof case name'); same(p.steps, f.rows.length, `${f.name}: proof steps`);
  same(p.goal, f.goal, `${f.name}: proof goal AST`);
  same(decodeState(p.initial_state_le_hex, ctx.arity, f.name + ' initial'), s.initial, `${f.name}: proof initial state`);
  same(decodeState(p.terminal_state_le_hex, ctx.arity, f.name + ' terminal'), s.terminal, `${f.name}: proof terminal state`);
  for (const k of ['passed', 'unsealed_prefix_refused', 'serialization_roundtrip']) same(p[k], true, `${f.name}: ${k}`);
  same(p.recursive_verifier_rejections, 16, `${f.name}: recursive mutation checks`);
  same(p.compressed_verifier_rejections, 16, `${f.name}: compressed mutation checks`);
  same(p.malformed_steps_rejected, 2, `${f.name}: malformed-step checks`);
  need(Array.isArray(p.fold_seconds) && p.fold_seconds.length === f.rows.length, `${f.name}: fold timings`);
  p.fold_seconds.forEach(x => duration(x, `${f.name}: fold duration`));
  for (const k of ['init_seconds', 'mean_steady_fold_seconds', 'verify_seconds', 'compression_seconds', 'compressed_verify_seconds']) duration(p[k], `${f.name}: ${k}`);
  const mean = sum(p.fold_seconds.slice(1)) / (f.rows.length - 1);
  need(Math.abs(mean - p.mean_steady_fold_seconds) <= 1e-10 * Math.max(1, mean), `${f.name}: steady fold mean`);
  integer(p.compressed_bytes, 1, 8 * 1024 * 1024, `${f.name}: compressed size`);
  integer(p.recursive_bytes, 1, 256 * 1024 * 1024, `${f.name}: recursive size`);
}
function receiptSummary(receipt, ctx, cases, index) {
  same(receipt.passed, true, 'Rust proof gate did not pass');
  same(receipt.shared_vk, true, 'shared key assertion missing');
  same(receipt.native_hash_parity, true, 'native Poseidon parity missing');
  same(receipt.shard, {index, total: SHARDS}, 'Rust shard identity');
  same(receipt.corpus_steps, CORPUS_STEPS, 'Rust corpus total');
  same(receipt.corpus_proofs, CORPUS_CASES, 'Rust corpus proof count');
  same(receipt.steps, sum(cases.map(x => x.fixture.rows.length)), 'Rust shard total');
  same(receipt.depth, ctx.matrix.depth, 'Rust history depth');
  same(receipt.matrix_constraints, ctx.matrix.constraints, 'Rust matrix constraints');
  same(receipt.step_constraints, ctx.matrix.constraints + 2 * ctx.arity, 'Rust state binding constraints');
  integer(receipt.primary_constraints, receipt.step_constraints, 10000000, 'primary augmented constraints');
  integer(receipt.secondary_constraints, 1, 10000000, 'secondary constraints');
  integer(receipt.vk_bytes, 1, 256 * 1024 * 1024, 'verifier key size');
  duration(receipt.setup_seconds, 'setup duration'); duration(receipt.compression_setup_seconds, 'compression setup duration');
  same(receipt.proofs.map(x => x.name), cases.map(x => x.fixture.name), 'Rust shard proof cases');
  cases.forEach(({fixture, sample}, i) => proofReceipt(receipt.proofs[i], fixture, sample, ctx));
}
function timer(file) {
  if (!fs.existsSync(file)) return null;
  regular(file, 64 * 1024); const raw = fs.readFileSync(file, 'utf8');
  const take = (pattern, label) => { const m = raw.match(pattern); need(m, `timer ${label}: ${file}`); return m[1]; };
  const wall = take(/Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*([0-9:.]+)/, 'wall time');
  const pieces = wall.split(':').map(Number);
  need((pieces.length === 2 || pieces.length === 3) && pieces.every(x => Number.isFinite(x) && x >= 0), 'timer elapsed format');
  const elapsed = pieces.reduce((a, x) => a * 60 + x, 0);
  const user = Number(take(/User time \(seconds\):\s*([0-9.]+)/, 'user time'));
  const system = Number(take(/System time \(seconds\):\s*([0-9.]+)/, 'system time'));
  const rss = Number(take(/Maximum resident set size \(kbytes\):\s*(\d+)/, 'peak RSS'));
  const swaps = Number(take(/Swaps:\s*(\d+)/, 'swaps'));
  const status = Number(take(/Exit status:\s*(\d+)/, 'exit status'));
  duration(user, 'timer user time'); duration(system, 'timer system time'); integer(rss, 1, Number.MAX_SAFE_INTEGER, 'timer RSS');
  same(status, 0, 'timed command failed'); integer(swaps, 0, Number.MAX_SAFE_INTEGER, 'timer swaps');
  return {wall_seconds: elapsed, user_seconds: user, system_seconds: system, peak_rss_kib: rss, swaps, exit_status: status};
}
function fileNames(cases, proofDir) {
  const names = ['matrix.json', 'full.json', 'receipt.json', 'shared.vk.bin', 'Cargo.lock'];
  for (const {fixture: f} of cases) names.push(f.name + '.compressed.bin', f.name + '.receipt.json');
  for (const n of TIMER_FILES) if (fs.existsSync(path.join(proofDir, n))) names.push(n);
  same(sorted(fs.readdirSync(proofDir).filter(n => n.endsWith('.compressed.bin'))), sorted(cases.map(x => x.fixture.name + '.compressed.bin')), 'unexpected or missing compressed proofs');
  same(sorted(fs.readdirSync(proofDir).filter(n => n.endsWith('.receipt.json'))), sorted(cases.map(x => x.fixture.name + '.receipt.json')), 'unexpected or missing per-case receipts');
  return sorted(names);
}
function artifact(proofDir, ctx, cases, index) {
  matrixFile(path.join(proofDir, 'matrix.json'), ctx);
  const full = json(path.join(proofDir, 'full.json')), receipt = json(path.join(proofDir, 'receipt.json'));
  fullSummary(full, ctx, cases); receiptSummary(receipt, ctx, cases, index);
  cases.forEach(({fixture: f}, i) => {
    same(json(path.join(proofDir, f.name + '.receipt.json')), receipt.proofs[i], `${f.name}: per-case receipt differs`);
    same(regular(path.join(proofDir, f.name + '.compressed.bin'), 8 * 1024 * 1024), receipt.proofs[i].compressed_bytes, `${f.name}: serialized proof length`);
  });
  same(regular(path.join(proofDir, 'shared.vk.bin')), receipt.vk_bytes, 'serialized verifier key length');
  const files = Object.fromEntries(fileNames(cases, proofDir).map(n => [n, digest(path.join(proofDir, n))]));
  same(files['Cargo.lock'], ctx.source_inputs.cargo_lock, 'artifact Cargo.lock differs from source-owned lockfile');
  const timers = {generation: timer(path.join(proofDir, TIMER_FILES[0])), proving: timer(path.join(proofDir, TIMER_FILES[1]))};
  return {full, receipt, files, timers};
}
function generatedCases(fixtureDir, ctx, cases, full) {
  const bins = [];
  cases.forEach(({fixture: f, sample: s}, j) => {
    const c = json(path.join(fixtureDir, f.name + '.json'));
    same(c.info, full.cases[j], `${f.name}: generated case info`);
    need(Array.isArray(c.states) && c.states.length === f.rows.length + 1, `${f.name}: generated state count`);
    same(c.states[0], s.initial, `${f.name}: generated initial state`);
    same(c.states.at(-1), s.terminal, `${f.name}: generated terminal state`);
    c.states.forEach((z, i) => {
      state(z, ctx.arity, `${f.name} state ${i}`);
      same(z[1], String(i), `${f.name}: state count ${i}`); same(z[2], s.goal_digest, `${f.name}: state goal ${i}`);
      same(z[3], i === f.rows.length ? '1' : '0', `${f.name}: state seal ${i}`);
      if (i < f.rows.length) {
        const n = `${f.name}-${i}.bin`; bins.push(n);
        same(regular(path.join(fixtureDir, n)), ctx.matrix.wires * 32, `${f.name}: witness ${i} length`);
      }
    });
  });
  same(sorted(fs.readdirSync(fixtureDir).filter(n => n.endsWith('.bin'))), sorted(bins), 'generated witness case/step coverage');
}
function seal(fixtureDir, proofDir, sourceHead, runId, shard) {
  const identity = labels(sourceHead, runId), index = shardIndex(shard), ctx = inputs(), cases = expected(ctx, index);
  const sourceMatrix = path.join(fixtureDir, 'matrix.json'), targetMatrix = path.join(proofDir, 'matrix.json');
  const matrixHash = digest(sourceMatrix, 128 * 1024 * 1024);
  if (path.resolve(sourceMatrix) !== path.resolve(targetMatrix)) {
    if (fs.existsSync(targetMatrix)) same(digest(targetMatrix, 128 * 1024 * 1024), matrixHash, 'existing exported matrix differs');
    else fs.copyFileSync(sourceMatrix, targetMatrix);
  }
  const a = artifact(proofDir, ctx, cases, index); generatedCases(fixtureDir, ctx, cases, a.full);
  const manifest = {schema: MANIFEST_SCHEMA, passed: true, ...identity, shard: {index, total: SHARDS},
    corpus_cases: CORPUS_CASES, corpus_steps: CORPUS_STEPS, cases: cases.map(x => x.fixture.name),
    steps: a.receipt.steps, source_inputs: ctx.source_inputs, matrix_summary: ctx.matrix, files: a.files, timers: a.timers};
  fs.writeFileSync(path.join(proofDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return manifest;
}
function combine(artifactRoot, sourceHead, runId) {
  const identity = labels(sourceHead, runId), ctx = inputs(), shards = [];
  const dirs = Array.from({length: SHARDS}, (_, k) => `zklean-equality-shard${k}-${sourceHead}`);
  same(sorted(fs.readdirSync(artifactRoot).filter(n => n.startsWith('zklean-equality-shard'))), sorted(dirs), 'exactly four matching shard artifact directories are required');
  for (let index = 0; index < SHARDS; index++) {
    const dir = path.join(artifactRoot, dirs[index]), stat = fs.lstatSync(dir);
    need(stat.isDirectory() && !stat.isSymbolicLink(), 'shard artifact must be a directory');
    const manifest = json(path.join(dir, 'manifest.json')), cases = expected(ctx, index);
    same(manifest.schema, MANIFEST_SCHEMA, 'manifest schema'); same(manifest.passed, true, 'unsealed manifest');
    for (const k of ['source_head', 'run_id']) same(manifest[k], identity[k], `manifest ${k}`);
    same(manifest.shard, {index, total: SHARDS}, 'manifest shard identity');
    same(manifest.corpus_cases, CORPUS_CASES, 'manifest corpus cases'); same(manifest.corpus_steps, CORPUS_STEPS, 'manifest corpus steps');
    same(manifest.source_inputs, ctx.source_inputs, 'manifest source inputs'); same(manifest.matrix_summary, ctx.matrix, 'manifest matrix summary');
    same(manifest.cases, cases.map(x => x.fixture.name), 'manifest shard cases');
    const a = artifact(dir, ctx, cases, index);
    same(manifest.steps, a.receipt.steps, 'manifest shard steps');
    same(manifest.files, a.files, 'artifact contents differ from sealed hashes'); same(manifest.timers, a.timers, 'artifact timing evidence differs');
    shards.push({...a, shard: manifest.shard, manifest_sha256: digest(path.join(dir, 'manifest.json')).sha256});
  }
  for (const name of ['matrix.json', 'shared.vk.bin', 'Cargo.lock']) for (const s of shards.slice(1)) same(s.files[name], shards[0].files[name], `shards do not share identical ${name}`);
  for (const k of ['primary_constraints', 'secondary_constraints', 'step_constraints', 'vk_bytes']) for (const s of shards.slice(1)) same(s.receipt[k], shards[0].receipt[k], `shard circuit metric ${k}`);
  const byName = new Map();
  for (const s of shards) for (const p of s.receipt.proofs) { need(!byName.has(p.name), 'duplicate proof case across shards'); byName.set(p.name, p); }
  same(byName.size, CORPUS_CASES, 'aggregate proof count');
  const proofs = ctx.fixtures.map(f => { need(byName.has(f.name), `missing aggregate proof ${f.name}`); return byName.get(f.name); });
  same(sum(proofs.map(p => p.steps)), CORPUS_STEPS, 'aggregate proof steps');
  need(proofs.every(p => p.compressed_bytes === proofs[0].compressed_bytes && p.recursive_bytes === proofs[0].recursive_bytes), 'shared circuit proof sizes differ');
  same(sorted(unique(shards.flatMap(s => s.full.distinct_tags_checked))), sorted(Object.keys(ctx.matrix.rule_read_counts)), 'aggregate rule coverage');
  same(unique(shards.flatMap(s => s.full.constant_ids_challenged)).sort((a, b) => a - b), ctx.sample.constant_ids_challenged, 'aggregate constant coverage');
  const regenerated = {};
  for (const s of shards) for (const [k, v] of Object.entries(s.full.regenerated_rejections)) regenerated[k] = (regenerated[k] || 0) + v;
  return {schema: 'zkl-nova-17/equality-hosted-aggregate-v1', passed: true, ...identity,
    scope: 'Hosted Nova/Spartan receipts and artifact integrity for the restricted equality/Nat admission relation.',
    shared_vk: true, matrix: {...ctx.matrix, ...shards[0].files['matrix.json'],
      step_constraints: shards[0].receipt.step_constraints, primary_constraints: shards[0].receipt.primary_constraints, secondary_constraints: shards[0].receipt.secondary_constraints},
    verifier_key: shards[0].files['shared.vk.bin'], cargo_lock: shards[0].files['Cargo.lock'], source_inputs: ctx.source_inputs,
    totals: {shards: SHARDS, proofs: CORPUS_CASES, steps: CORPUS_STEPS, matrices_checked: sum(shards.map(s => s.full.total_checked)),
      supplementary_matrices_checked: sum(shards.map(s => s.full.coverage.matrices_checked)),
      recursive_verifier_rejections: sum(proofs.map(p => p.recursive_verifier_rejections)), compressed_verifier_rejections: sum(proofs.map(p => p.compressed_verifier_rejections)),
      malformed_steps_rejected: sum(proofs.map(p => p.malformed_steps_rejected)), unsealed_prefixes_refused: proofs.length, serialization_roundtrips: proofs.length,
      compressed_proof_bytes: sum(proofs.map(p => p.compressed_bytes)), direct_assignment_goal_mutations: sum(shards.map(s => s.full.total_mutations_rejected)),
      regenerated_rejections: Object.fromEntries(Object.entries(regenerated).sort(([a], [b]) => a.localeCompare(b)))},
    proof_sizes: {compressed_bytes: proofs[0].compressed_bytes, recursive_bytes: proofs[0].recursive_bytes},
    per_shard: shards.map(s => ({shard: s.shard, manifest_sha256: s.manifest_sha256, files: s.files, timers: s.timers, receipt: s.receipt,
      matrices_checked: s.full.total_checked, supplementary_coverage: s.full.coverage, regenerated_rejections: s.full.regenerated_rejections})), proofs};
}
if (require.main === module) {
  try {
    const [command, ...args] = process.argv.slice(2); let result;
    if (command === 'seal' && args.length === 5) result = seal(...args);
    else if (command === 'combine' && args.length === 3) result = combine(...args);
    else throw Error('usage: equality_receipts.cjs seal fixture-dir proof-dir source-head run-id k/4 | combine artifact-root source-head run-id');
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } catch (e) { process.stderr.write(`equality receipt gate: ${e.message}\n`); process.exitCode = 1; }
}
module.exports = {seal, combine};
