const {test} = require('node:test');
const assert = require('node:assert/strict');
const {estimate,clock} = require('../web/app.js');
const progress = () => ({exists:true,unique_shards:3333,
  rates:{shard_per_min_15m:5,shard_per_min_5m:10,shard_per_min_30m:4},
  recent_events:[{kind:'shard',replayed:false,t:995}]});
const live = {now:1000,connected:true,active:true};

test('uses observed core throughput for a clearly bounded milestone',()=>{
  const model=estimate(progress(),live);
  assert.equal(model.target,3400);
  assert.equal(model.remaining,67);
  assert.equal(model.seconds,804);
  assert.equal(model.fastSeconds,402);
  assert.equal(model.slowSeconds,1005);
  assert.equal(model.fullProofEta,null);
  assert.equal(model.proofComplete,false);
});
test('a reached planning target never asserts proof completion',()=>{
  const model=estimate(progress(),{...live,target:3300});
  assert.equal(model.status,'target_reached');
  assert.equal(model.seconds,null);
  assert.equal(model.proofComplete,false);
});
test('paused, disconnected, and absent producers cannot emit a countdown',()=>{
  for(const options of [{paused:true},{connected:false},{active:false}]) {
    const model=estimate(progress(),{...live,...options});
    assert.equal(model.seconds,null);
    assert.equal(clock(null,model,100),null);
  }
});
test('cached replay cannot warm up a newly restarted producer',()=>{
  const p=progress();p.recent_events.push({kind:'shard',replayed:true,t:1000});
  const model=estimate(p,{...live,startedAt:999});
  assert.equal(model.status,'learning');
  assert.equal(model.seconds,null);
});
test('silence beyond the observed cadence stops forecasting',()=>{
  const model=estimate(progress(),{...live,now:1200});
  assert.equal(model.status,'learning');
  assert.equal(model.seconds,null);
});
test('the clock stays anchored between actual core completions',()=>{
  const first=estimate(progress(),live);first.source='run-a';
  const anchor=clock(null,first,100);
  const changedRate={...first,seconds:900};
  assert.equal(clock(anchor,changedRate,104),anchor);
  const next=clock(anchor,{...first,count:3334,seconds:792},110);
  assert.equal(next.deadline,902);
  assert.notEqual(clock(anchor,{...first,source:'run-b'},110),anchor);
});
test('malformed counts and non-finite rates never create an invalid ETA',()=>{
  const p=progress();p.unique_shards=NaN;p.rates={shard_per_min_15m:Infinity};
  assert.equal(estimate(p,live).seconds,null);
  const tiny=progress();tiny.rates={shard_per_min_15m:Number.MIN_VALUE};
  assert.equal(estimate(tiny,live).status,'learning');
  assert.equal(estimate(progress(),{...live,target:-1}).manual,false);
});
