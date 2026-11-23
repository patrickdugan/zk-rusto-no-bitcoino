const assert = require('node:assert/strict');
const test = require('node:test');
const {arkBudgets, arkCampaign, ongoingJobs, rememberCheckpoints, checkpointTrend} = require('../web/app.js');

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

function sample(t, core, recursion, replayed) {
  return {sampled_at_unix:t,core_new:core,recursion_new:recursion,core_replayed:replayed};
}

test('replays never appear as fresh increments or throughput', () => {
  const history=[sample(1000,2,4,100), sample(1030,2,5,150), sample(1060,2,8,200)]
    .reduce(rememberCheckpoints, []);
  const trend=checkpointTrend(history);
  assert.deepEqual(trend.lastMinute,{core:0,recursion:4});
  assert.equal(trend.rate,0);
  assert.equal(trend.progress.unique_shards,202);
  assert.equal(trend.progress.recent_events.length,0);
  assert.equal(rememberCheckpoints(history,sample(1060,99,100,200)),history);
  assert.equal(rememberCheckpoints(history,sample(1070,0,0,0)).length,1);
});

test('a cloud checkpoint stream can forecast a first-page scenario without clearing proof gates', () => {
  const history=[sample(1000,2,4,100), sample(1030,5,6,100), sample(1060,8,8,100)]
    .reduce(rememberCheckpoints, []);
  const trend=checkpointTrend(history);
  assert.equal(trend.rate,6);
  const options={
    now:1060,setupRecorded:true,
    coreSource:{active:true,connected:true,startedAt:1000,progress:trend.progress},
    plan:{core:168,...Object.fromEntries(arkBudgets.map(([id])=>[id,1]))},
  };
  const campaign=arkCampaign({status:'inactive'},options);
  assert.equal(campaign.core.count,108);
  assert.ok(campaign.proofRemaining.fast>=600);
  assert.deepEqual(campaign.rows.filter(row=>row.done).map(row=>row.id),['setup']);
  assert.equal(arkCampaign({status:'inactive'},{...options,coreSource:{...options.coreSource,connected:false}}).proofFinish,null);
});
