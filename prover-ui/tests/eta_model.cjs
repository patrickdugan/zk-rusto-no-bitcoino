const {test} = require('node:test');
const assert = require('node:assert/strict');
const {estimate,clock,arkCampaign,arkDeadline,cashuRoadmap,arkArchive} = require('../web/app.js');
const progress = () => ({exists:true,unique_shards:3333,
  rates:{shard_per_min_15m:5,shard_per_min_5m:10,shard_per_min_30m:4},
  recent_events:[{kind:'shard',replayed:false,t:995}]});
const live = {now:1000,connected:true,active:true};

test('private storage timestamps and releases are independent of prover liveness',()=>{
  const storage={sampled_at_unix:900,bucket_bytes:17_580_647_002,objects:3856};
  const root='https://github.com/patrickdugan/zk-rusto-no-bitcoino/releases/tag/ark-679-';
  const sample={stage:'stopped',private_storage:storage,checkpoint_release:root+'spot-a6e283d956',
    checkpoint_export_finished:false,proof_release:root+'offchain-a6e283d956',proof_commit:'a'.repeat(40)};
  assert.deepEqual(arkArchive(sample,1000),{storage:{...storage,fresh:true},checkpoint:sample.checkpoint_release,
    exportStatus:null,proof:null});
  assert.equal(arkArchive(sample,1025).storage.fresh,false);
  assert.equal(arkArchive({...sample,checkpoint_release:'https://example.com/spot-a6e283d956'},1000).exportStatus,
    'Final checkpoint export unconfirmed');
  assert.equal(arkArchive({...sample,stage:'proof_checks_passed'},1000).proof,sample.proof_release);
  assert.equal(arkCampaign({},{overnight:{stage:'proof_checks_passed',published:true}}).published,true);
});

test('uses observed core throughput for a clearly bounded milestone',()=>{
  const model=estimate(progress(),live);
  assert.equal(model.target,3400);
  assert.equal(model.remaining,67);
  assert.equal(model.seconds,804);
  assert.equal(model.fastSeconds,402);
  assert.equal(model.slowSeconds,1005);
});
test('a reached planning target never asserts proof completion',()=>{
  const model=estimate(progress(),{...live,target:3300});
  assert.equal(model.status,'target_reached');
  assert.equal(model.seconds,null);
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

const gpu = () => ({status:'gpu',progress:progress(),last_resource_age_s:1});
const campaignLive = {...live,processObserved:true,setupRecorded:true};
const plan = {core:3400,sp1:20,sdk:1,wrap:12,statementCheck:2,refusals:3,claim:43,delivery:60};
const row = (model,id) => model.rows.find(item => item.id === id);

test('a checkpoint and parallel setup can coexist with an unknown full proof ETA',()=>{
  const result=arkCampaign(gpu(),campaignLive);
  assert.equal(result.core.target,3400);
  assert.equal(result.target,null);
  assert.equal(result.proofFinish,null);
  assert.ok(result.coreCapacityUntilDeadline>result.core.count);
  assert.equal(row(result,'statement').done,true);
  assert.equal(row(result,'sp1').status,'In progress');
  assert.equal(row(result,'setup').status,'Setup verified');
  assert.equal(row(result,'claim').done,false);
});

test('the proof range adds only outstanding serial budgets to the observed core range',()=>{
  const result=arkCampaign(gpu(),{...campaignLive,plan:{...plan,setup:800}});
  const tailSeconds=(20+1+12+2+3+43)*60;
  assert.deepEqual(result.proofFinish,{fast:1000+402+tailSeconds,slow:1000+1005+tailSeconds});
  assert.deepEqual(result.deliveryFinish,{fast:result.proofFinish.fast+3600,slow:result.proofFinish.slow+3600});
  const unprepared=arkCampaign(gpu(),{...campaignLive,setupRecorded:false,plan});
  assert.equal(unprepared.proofFinish,null);
  assert.deepEqual(unprepared.missing,['M14 setup reserve if still pending']);
});

test('passing a scenario target invalidates the forecast while SP1 is still live',()=>{
  const result=arkCampaign(gpu(),{...campaignLive,plan:{...plan,core:3332}});
  assert.equal(result.proofFinish,null);
  assert.equal(result.checksPassed,false);
});

test('later phases retire only the coordinator checks already crossed',()=>{
  const result=arkCampaign({status:'m13-verify',last_resource_age_s:2},{...campaignLive,plan});
  assert.equal(row(result,'sdk').done,true);
  assert.equal(row(result,'wrap').done,true);
  assert.equal(row(result,'statementCheck').status,'In progress');
  assert.equal(row(result,'refusals').done,false);
  assert.deepEqual(result.proofFinish,{fast:3880,slow:3880});
  const claim=arkCampaign({status:'m14claim',last_resource_age_s:2},campaignLive);
  assert.equal(row(claim,'refusals').done,true);
  assert.equal(row(claim,'claim').done,false);
});

test('raw outputs do not verify the campaign and completion still leaves evidence delivery',()=>{
  const outputs={compressed_exists:true,wrap_v2_exists:true};
  const pending=arkCampaign({...gpu(),...outputs},campaignLive);
  assert.equal(pending.checksPassed,false);
  assert.equal(row(pending,'sdk').done,false);
  const partial=arkCampaign({status:'all_proof_checks_passed',compressed_exists:true},campaignLive);
  assert.equal(partial.checksPassed,false);
  const verified=arkCampaign({status:'all_proof_checks_passed',...outputs},{...campaignLive,plan:{delivery:60}});
  assert.equal(verified.checksPassed,true);
  assert.equal(row(verified,'claim').done,true);
  assert.equal(row(verified,'delivery').done,false);
  assert.deepEqual(verified.deliveryFinish,{fast:4600,slow:4600});
});

test('resource waits, display pause and stale telemetry hold a full-chain estimate',()=>{
  for(const options of [{paused:true},{connected:false},{processObserved:false}]) {
    const result=arkCampaign(gpu(),{...campaignLive,plan,...options});
    assert.equal(result.proofFinish,null);
    assert.equal(result.coreCapacityUntilDeadline,null);
  }
  const waiting=arkCampaign({status:'waiting_for_headroom_wrapv2',last_resource_age_s:1},{...campaignLive,plan});
  assert.equal(row(waiting,'wrap').status,'Resource wait');
  assert.equal(waiting.proofFinish,null);
  const stalePhase=arkCampaign({status:'m14claim',last_resource_age_s:600},{...campaignLive,plan});
  assert.equal(stalePhase.proofFinish,null);
});

test('deadline capacity subtracts entered budgets and the delivery window can straddle the cutoff',()=>{
  assert.equal(new Date(arkDeadline*1000).toISOString(),'2026-11-27T23:59:00.000Z');
  const now=arkDeadline-9300;
  const wsl=gpu();
  wsl.progress.recent_events[0].t=now-5;
  const result=arkCampaign(wsl,{...campaignLive,now,plan});
  assert.equal(result.coreCapacityUntilDeadline,3403);
  assert.ok(result.deliveryFinish.fast<arkDeadline);
  assert.ok(result.deliveryFinish.slow>arkDeadline);
  const expired=arkCampaign(wsl,{...campaignLive,now:arkDeadline,plan});
  assert.equal(expired.coreCapacityUntilDeadline,null);
});

const historicalPayment = {summary:{
  network:'testnet4',schema:'ark/shinigami-testnet4-verified-payment/v1',
  status:'independently_verified_legacy_script_payment',
}};
const historicalTapleaf = {summary:{
  network:'testnet4',schema:'ark/shinigami-testnet4-verified-tapleaf/v1',
  status:'independently_verified_real_tapleaf',
}};

test('the Cashu roadmap keeps fixture evidence and open proof gates separate',()=>{
  const road=cashuRoadmap(arkCampaign(gpu(),campaignLive),[historicalPayment,historicalTapleaf]);
  assert.equal(road.friday.find(item=>item.id==='shinigami').done,true);
  assert.equal(road.friday.find(item=>item.id==='cashu-demo').status,'Recorded regtest demo');
  assert.equal(road.friday.find(item=>item.id==='refusal-demo').status,'Verified regtest payout');
  assert.equal(road.friday.find(item=>item.id==='refusal-demo').done,true);
  assert.equal(road.friday.find(item=>item.id==='melt-reserve-demo').status,'Archived regtest settlement');
  assert.equal(road.friday.find(item=>item.id==='exact-melt-stark').done,true);
  assert.equal(road.friday.find(item=>item.id==='exact-melt-audit').done,true);
  assert.equal(road.friday.find(item=>item.id==='exact-melt-chain').done,false);
  assert.equal(road.friday.find(item=>item.id==='nova-protected').status,'Verified Nova fixture');
  assert.equal(road.friday.find(item=>item.id==='v3-live-accounting').status,'Live V3 accounting verified');
  assert.equal(road.friday.find(item=>item.id==='v3-live-accounting').done,true);
  assert.equal(road.friday.find(item=>item.id==='protected-holder').status,'Verified protected regtest exit');
  assert.equal(road.friday.find(item=>item.id==='cashu-bitvm').done,false);
  assert.equal(road.friday.find(item=>item.id==='cashu-sp1-wrap').done,false);
  assert.equal(road.friday.find(item=>item.id==='ark-proof').status,'Suspended · checkpoints preserved');
  assert.equal(road.trust.find(item=>item.id==='issuance').done,false);
  assert.equal(road.trust.find(item=>item.id==='redemption').done,false);
});

test('a duplicate or misbound Shinigami receipt cannot establish both historical verifications',()=>{
  for(const receipts of [[historicalPayment,historicalPayment], [
    historicalPayment,{summary:{...historicalTapleaf.summary,status:historicalPayment.summary.status}},
  ]]) {
    assert.equal(cashuRoadmap({checksPassed:false},receipts).friday.find(item=>item.id==='shinigami').done,false);
  }
});

test('terminal Ark checks still leave the audit and every admin-trust gate open',()=>{
  const terminal=arkCampaign({status:'all_proof_checks_passed',compressed_exists:true,wrap_v2_exists:true},campaignLive);
  const road=cashuRoadmap(terminal,[historicalPayment,historicalTapleaf]);
  assert.equal(road.friday.find(item=>item.id==='ark-proof').status,'Suspended · checkpoints preserved');
  assert.equal(road.friday.find(item=>item.id==='ark-proof').done,false);
  assert.deepEqual(road.trust.map(item=>item.id),['backing','issuance','redemption','adversarial']);
  assert.ok(road.trust.every(item=>!item.done && item.status.endsWith('· no ETA')));
});

test('overnight local checks advance the correct campaign milestones',()=>{
  const model = stage => arkCampaign({}, {connected:true,overnight:{stage,fresh:true}});
  const sdk = model('verify_sdk_m13');
  assert.equal(sdk.rows.find(row=>row.id==='sp1').done,true);
  assert.equal(sdk.rows.find(row=>row.id==='sdk').status,'In progress');
  assert.equal(sdk.checksPassed,false);

  const m14 = model('verify_m14');
  assert.equal(m14.rows.find(row=>row.id==='refusals').done,true);
  assert.equal(m14.rows.find(row=>row.id==='claim').status,'In progress');
  assert.equal(m14.checksPassed,false);

  const checked = model('proof_checks_passed');
  assert.equal(checked.checksPassed,true);
  assert.equal(checked.rows.find(row=>row.id==='delivery').done,false);
});
