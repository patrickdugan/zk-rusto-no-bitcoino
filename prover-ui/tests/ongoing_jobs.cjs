const assert = require('node:assert/strict');
const test = require('node:test');
const {ongoingJobs} = require('../web/app.js');

function setup(overrides = {}) {
  const ark = {
    fresh: true,
    phase: 'Replaying checkpoints',
    knownPhase: 'Replaying checkpoints',
    sample: {
      active: true, stage: 'replay', ark_running: true, nova_running: true,
      core_new: 2, recursion_new: 19, core_replayed: 100, sampled_at_unix: 1729,
    },
  };
  return {ark, local: [], localFresh: true, localSample: 1730, ...overrides};
}

test('reports the GPU and CPU jobs independently from the same cloud heartbeat', () => {
  const input = setup();
  const [ark, nova] = ongoingJobs(input);
  assert.deepEqual([ark.status, nova.status], ['Running', 'Running']);
  assert.equal(ark.where, 'Hyperstack · A100 GPU');
  assert.equal(nova.where, 'Hyperstack · CPU');
  assert.equal(ark.heardAt, 1729);
  assert.deepEqual(ark.metrics.map(([,value]) => value), [2, 19, 100]);
  input.ark.sample.nova_running = false;
  assert.deepEqual(ongoingJobs(input).map(job => job.id), ['cloud-ark']);
});

test('preparation, stale and paused telemetry never appear as a running prover', () => {
  const input = setup();
  Object.assign(input.ark.sample, {stage: 'preparing', ark_running: false, nova_running: false});
  assert.equal(ongoingJobs(input)[0].status, 'Preparing');
  input.ark.fresh = false;
  assert.equal(ongoingJobs(input)[0].status, 'Stale');
  input.paused = true;
  assert.equal(ongoingJobs(input)[0].status, 'Paused');
});

test('distinguishes local resource waits from historical proof evidence', () => {
  const local = [
    {id: 'wait', title: 'Ark coordinator', status: 'resource wait', backend: 'SP1 / CUDA'},
    {id: 'verified', title: 'Prior proof', status: 'verified receipt', audit: {valid: true}},
    {id: 'local-nova', title: 'Local Nova', running: true, process: {pid: 11}, backend: 'CPU'},
  ];
  const input = setup({ark: null, local});
  assert.deepEqual(ongoingJobs(input).map(job => [job.id,job.status]),
    [['wait','Waiting for resources'],['local-nova','Running']]);
  assert.equal(ongoingJobs({...input,localFresh:false})[1].status, 'Stale');
});
