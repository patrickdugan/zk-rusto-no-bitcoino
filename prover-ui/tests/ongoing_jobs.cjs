const assert = require('node:assert/strict');
const test = require('node:test');
const {arkBudgets, arkCampaign, ongoingJobs, rememberCheckpoints, checkpointTrend, checkpointMosaic, a100Budget, observedBudgetPace, arkWorkerLabel} = require('../web/app.js');

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

test('the restored mosaic separates the two kinds of work and marks replays', () => {
  const history=[
    {...sample(1000,1,4,100),recursion_replayed:8},
    {...sample(1008,2,6,101),recursion_replayed:10},
  ].reduce(rememberCheckpoints, []);
  assert.deepEqual(checkpointMosaic(history).map(({kind,replayed})=>[kind,replayed]), [
    ['core',true],['recursion',true],['recursion',true],['core',false],['recursion',false],['recursion',false],
  ]);
  assert.equal(checkpointMosaic(rememberCheckpoints(history,sample(1016,10000,6,101))).length,319);
  const old=rememberCheckpoints([],sample(1000,1,4,100));
  assert.deepEqual(checkpointMosaic(rememberCheckpoints(old,{...sample(1008,1,4,100),recursion_replayed:500})),[]);
});

test('a stopped worker can have a full saved cache without a proof-completion percentage', () => {
  assert.equal(arkWorkerLabel({observed:true,saved:4421}), 'Idle · checkpoints saved');
  assert.equal(arkWorkerLabel({observed:false,saved:4421}), 'Worker status unknown');
  assert.equal(arkWorkerLabel({observed:false,live:true,saved:4421}), 'Worker running');
});

test('the A100 planner prices only scenario cores and handles unknown targets and exact credit', () => {
  const inputs={saved:4421,rate:1.35672043,credit:3.37287894};
  const unknown=a100Budget(inputs);
  assert.equal(unknown.cost,null);
  assert.equal(unknown.runwayCores,1548);
  assert.equal(unknown.perThousand.toFixed(2),'2.18');
  const projected=a100Budget({...inputs,target:6000});
  assert.equal(projected.cost.toFixed(2),'3.44');
  assert.equal(projected.shortfall.toFixed(2),'0.07');
  assert.equal(a100Budget({...inputs,target:1727}).cost,null);
  assert.equal(a100Budget({...inputs,credit:0}).runwayCores,0);
  assert.equal(a100Budget({...inputs,rate:0}),null);
});

test('live budget uses a full fresh-core window and ignores the earlier core replay', () => {
  const history=[{t:670,core:2,replayed:2000},{t:700,core:4,replayed:4378},{t:1000,core:29,replayed:4378}];
  const pace=observedBudgetPace(history);
  assert.deepEqual(pace,{perMinute:5,seconds:300});
  const cost=a100Budget({saved:4421,target:5421,rate:1.08672043,coresPerMinute:pace.perMinute});
  assert.equal(cost.cost.toFixed(2),'3.62');
  assert.equal(observedBudgetPace([...history,{t:1010,core:30,replayed:4380}]),null);
  assert.equal(observedBudgetPace([{t:700,core:4,replayed:4378},{t:1000,core:4,replayed:4378}]),null);
});

test('private seed staging is visible without counting a GPU as running', () => {
  const input=setup();
  Object.assign(input.ark.sample,{stage:'staging',ark_running:false,nova_running:false,seed_bytes:4*2**20,seed_parts:1});
  const [row]=ongoingJobs(input);
  assert.equal(row.status,'Preparing');
  assert.equal(row.where,'Hyperstack · private storage');
  assert.deepEqual(row.metrics,[['Uploaded MiB',4],['Verified transfer parts',1]]);
});
