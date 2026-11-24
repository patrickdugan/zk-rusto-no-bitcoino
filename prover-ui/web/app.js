// The core clock and the Ark delivery scenario consume the same checkpoint rates.
const ProofEta = (() => {
  const finite = v => typeof v === 'number' && Number.isFinite(v);
  function estimate(progress, options = {}) {
    const now = options.now ?? Date.now()/1000;
    const count = progress?.exists === true && Number.isSafeInteger(progress.unique_shards) && progress.unique_shards >= 0 ? progress.unique_shards : null;
    const manual = Number.isSafeInteger(options.target) && options.target > 0 && options.target <= 10000000 ? options.target : null;
    const target = manual ?? (count === null ? null : (Math.floor(count/100)+1)*100);
    const base = manual ? 0 : target === null ? 0 : target-100;
    const rates = [15,5,30].map(w => progress?.rates?.[`shard_per_min_${w}m`]).filter(r => finite(r) && r > 0);
    const rate = rates[0] ?? null;
    const events = (Array.isArray(progress?.recent_events)?progress.recent_events.slice(-512):[]).filter(e => e.kind === 'shard' && e.replayed === false && finite(e.t) && e.t <= now+2 && (!finite(options.startedAt)||e.t>=options.startedAt));
    const lastCore = events.length ? Math.max(...events.map(e => e.t)) : null;
    let status = options.paused ? 'paused' : !options.connected ? 'stale' : !options.active ? 'inactive' : count === null || !rate || (finite(options.startedAt)&&lastCore===null) ? 'learning' : manual && count >= target ? 'target_reached' : lastCore !== null && now-lastCore > Math.max(90,240/rate) ? 'learning' : 'tracking';
    const remaining = count === null || target === null ? null : Math.max(0,target-count);
    if(status==='tracking'&&!finite(remaining/Math.min(...rates)*60))status='learning';
    return {status,count,target,manual:manual!==null,rate,lastCore,remaining,
      fraction:count===null||target===null ? 0 : Math.min(1,Math.max(0,(count-base)/(target-base))),
      seconds:status==='tracking' ? remaining/rate*60 : null,
      fastSeconds:status==='tracking' ? remaining/Math.max(...rates)*60 : null,
      slowSeconds:status==='tracking' ? remaining/Math.min(...rates)*60 : null};
  }
  function clock(previous, model, now) {
    if(model.status!=='tracking')return null;
    if(previous && previous.target===model.target && previous.count===model.count && previous.source===model.source)return previous;
    return {target:model.target,count:model.count,source:model.source,deadline:now+model.seconds};
  }
  const arkDeadline = Date.parse('2026-11-27T23:59:00Z') / 1000;
  const arkPhases = [
    {id:'statement', label:'Ark policy and Nova statement', steps:['expected'],
      detail:'Reconstruct the expected public values from the four-VTXO snapshot, policy and Nova proof.'},
    {id:'sp1', label:'SP1 CUDA proving and compression', steps:['gpu','cpu'],
      detail:'Core proving and recursion overlap. The final recursion and compressed proof follow the core work.'},
    {id:'sdk', label:'Independent SP1 SDK verification', steps:['sdk-verify'],
      detail:'Verify the compressed proof with the ELF-derived key and compare the complete expected public values.'},
    {id:'wrap', label:'M13 shrink and transcript-v2 wrap', steps:['shrink','wrapv2'],
      detail:'Reduce the compressed SP1 proof, then produce the v2 wrap for the BitVM3 verifier.'},
    {id:'statementCheck', label:'M13 statement and Ark policy gate', steps:['m13-verify','gate'],
      detail:'Independently match the pinned verifier key, program digest, recursion root and public statement.'},
    {id:'refusals', label:'SP1 and M13 negative controls', steps:['badwrap','badprogram','badcompressed'],
      detail:'Require normal refusals for a damaged wrap, wrong program and damaged compressed proof.'},
    {id:'setup', label:'M14 statement-bound setup', steps:[],
      detail:'Can run alongside SP1. The claim phase rechecks the prepared artifacts.'},
    {id:'claim', label:'M14 honest evaluation and full-circuit rejection', steps:['m14claim'],
      detail:'Bind the single-use release to the verified wrap, require honest acceptance, then require rejection of a full-circuit input bit flip and three binding substitutions.'},
    {id:'delivery', label:'Evidence audit, publication and demo package', steps:[],
      detail:'Audit hashes and claims, commit and publish the Ark evidence, then package the Cashu walkthrough.'},
  ];
  const arkStageResources = {
    statement:'Local · exact inputs and statement',
    sp1:'GPU · core proving and recursion overlap',
    sdk:'Local CPU · after SP1 compression',
    wrap:'Local CPU · after SDK verification',
    statementCheck:'Local CPU · after M13 wrap',
    refusals:'Local CPU · after statement check',
    setup:'Local CPU and disk · parallel prerequisite',
    claim:'Local CPU and disk · after setup and proof checks',
    delivery:'Local · after independent verification',
  };
  const arkBudgets = [
    ['sp1','SP1 recursion and compression after core'],
    ['sdk','SP1 SDK verification'],
    ['wrap','M13 shrink and wrap'],
    ['statementCheck','M13 statement verification and Ark gate'],
    ['refusals','SP1 and M13 negative controls'],
    ['setup','M14 setup reserve if still pending'],
    ['claim','M14 release, honest evaluation and negatives'],
    ['delivery','Evidence audit, publication and demo package'],
  ];
  const coordinatorSteps = arkPhases.flatMap(phase => phase.steps);
  const minutes = value => finite(value) && value > 0 && value <= 10080 ? value : null;
  function arkCampaign(wsl = {}, options = {}) {
    const {connected, paused, processObserved, setupRecorded, coreSource, overnight, plan = {}} = options;
    const now = options.now ?? Date.now()/1000;
    const remainingToClose = arkDeadline-now;
    const observedLocalStage = {verify_sdk_m13:'sdk-verify',verify_m14:'m14claim',proof_checks_passed:'all_proof_checks_passed'}[overnight?.stage];
    const latestStatus = observedLocalStage || (typeof wsl.status === 'string' ? wsl.status : 'unknown');
    const waitingFor = latestStatus.startsWith('waiting_for_headroom_');
    const phase = waitingFor ? latestStatus.slice('waiting_for_headroom_'.length) : latestStatus;
    const waitingForSetup = phase === 'waiting_for_statement_bound_m14_setup';
    const checksPassed = phase === 'all_proof_checks_passed' &&
      (observedLocalStage === phase || (wsl.compressed_exists === true && wsl.wrap_v2_exists === true));
    const step = checksPassed ? coordinatorSteps.length :
      waitingForSetup ? coordinatorSteps.indexOf('m14claim') : coordinatorSteps.indexOf(phase);
    const setupReady = setupRecorded || (step >= coordinatorSteps.indexOf('m14claim') && !waitingForSetup);
    const resourceHold = waitingFor || phase === 'held_for_user_confirmation';
    const current = arkPhases.find(item => item.steps.includes(phase));
    const phaseObserved = observedLocalStage ? overnight.fresh === true :
      connected && (current?.id === 'sp1' ? processObserved :
      finite(wsl.last_resource_age_s) && wsl.last_resource_age_s <= 15);
    const published = checksPassed && overnight?.published === true;
    const rows = arkPhases.map(item => {
      if(item.id === 'setup')return {...item,status:setupReady?'Setup verified':waitingForSetup?'Waiting for setup':'Pending',done:!!setupReady};
      if(item.id === 'delivery')return {...item,status:published?'Ark proof published':'Manual milestone',done:false};
      const done = step > coordinatorSteps.indexOf(item.steps.at(-1));
      const status = done ? 'Completed' : item === current ?
        waitingFor ? 'Resource wait' : phaseObserved ? 'In progress' : 'Last reported' : 'Pending';
      return {...item,done,status};
    });
    const corePending = !rows.find(row => row.id === 'sp1').done;
    const cloudCore = corePending && coreSource?.active ? coreSource : null;
    const progress = cloudCore?.progress || wsl.progress || {};
    const core = estimate(progress,{now,connected:cloudCore?.connected ?? connected,paused,
      active:cloudCore?.active ?? (phase === 'gpu' && !waitingFor && processObserved),
      startedAt:cloudCore?.startedAt ?? wsl.phase_started_unix,target:plan.core});
    const target = core.manual ? core.target : null;
    const tail = arkBudgets.filter(([id]) => id !== 'delivery' && !rows.find(row => row.id === id).done);
    const missing = tail.filter(([id]) => minutes(plan[id]) === null).map(([,label]) => label);
    const tailSeconds = tail.reduce((total,[id]) => total+(minutes(plan[id]) ?? 0)*60,0);
    const deliverySeconds = minutes(plan.delivery) === null ? null : plan.delivery*60;
    const tracking = core.status === 'tracking';
    // The ceiling budgets the time left for core work. Unpriced work can only lower it.
    const coreCapacityUntilDeadline = tracking && corePending && remainingToClose > 0 ?
      Math.min(Number.MAX_SAFE_INTEGER,core.count+Math.floor(Math.max(0,remainingToClose-tailSeconds-(deliverySeconds ?? 0))*core.rate/60)) : null;
    const project = range => range && ({fast:now+range.fast,slow:now+range.slow});
    let proofRange = null;
    const forecastReady = cloudCore ? cloudCore.connected : connected && !resourceHold && step >= 0;
    if(forecastReady && !paused && !missing.length) {
      if(!corePending) {
        if(checksPassed || phaseObserved || waitingForSetup)proofRange={fast:tailSeconds,slow:tailSeconds};
      } else if(target !== null && tracking) {
        proofRange={fast:core.fastSeconds+tailSeconds,slow:core.slowSeconds+tailSeconds};
      } else if(target === core.count && core.status === 'target_reached' && (phaseObserved || cloudCore)) {
        proofRange={fast:tailSeconds,slow:tailSeconds};
      }
    }
    const deliveryRange = proofRange && deliverySeconds !== null ?
      {fast:proofRange.fast+deliverySeconds,slow:proofRange.slow+deliverySeconds} : null;
    return {rows, phase, checksPassed, published, resourceHold, corePending, target, core, missing,
      proofRemaining:proofRange, proofFinish:project(proofRange), deliveryFinish:project(deliveryRange),
      coreCapacityUntilDeadline};
  }
  const cashuTrustMilestones = [
    {id:'backing',label:'Prove live backing and mint liabilities',
      status:'Nova fixture verified · no ETA',
      detail:'Stock Nova verification accepted the protected ledger fixture. Its journal binds reserves, issuance intents, live claims and spent claims. Production needs canonical Bitcoin observation, available witnesses and independent handling of bearer notes issued outside that ledger.'},
    {id:'issuance',label:'Enforce proof-bound Cashu issuance',
      status:'Protected batch verified · no ETA',
      detail:'The V3 CDK fixture bound six notes to a frozen blinded batch and confirmed reserve. Offline verification checked DLEQ and reblinding under independent pins. A mint can still issue bearer notes outside the protected profile.'},
    {id:'redemption',label:'Fund redemption if the mint refuses',
      status:'Protected regtest exit verified · no ETA',
      detail:'The V3 protected claim had a funded reserve at issuance. Ordinary protected melt and timed holder recovery compete for the same Bitcoin outpoint. The separate historical 23,750-sat fixture required a cooperative melt to fund its reserve.'},
    {id:'adversarial',label:'Verify the end-to-end trust claim',
      status:'Full settlement composition open · no ETA',
      detail:'Regtest and Nova controls cover conflicting spends, replay, changed beneficiaries, reorg handling and protected admission. The complete SP1 settlement proof and BitVM3 verifier composition remain open.'},
  ];
  function cashuRoadmap(ark, records) {
    const shinigami = [
      ['ark/shinigami-testnet4-verified-payment/v1','independently_verified_legacy_script_payment'],
      ['ark/shinigami-testnet4-verified-tapleaf/v1','independently_verified_real_tapleaf'],
    ].every(([schema,status])=>records.some(record=>record.summary?.network==='testnet4' &&
      record.summary.schema===schema && record.summary.status===status));
    const friday = [
      {id:'shinigami',label:'Shinigami historical payment and Tapleaf proofs',
        status:shinigami?'Verified records available':'Recorded · receipts unavailable here',done:shinigami,
        detail:'The separate testnet4 cases independently verified historical script execution. Each passed 15 negative controls.'},
      {id:'cashu-demo',label:'Cashu issuance, Ark withdrawal and recipient exit',
        status:'Recorded regtest demo',done:true,
        detail:'CDK admitted a Core-confirmed deposit and issued Cashu. A successful mint redemption delivered an Ark VTXO. The holder then claimed that VTXO on Bitcoin while the mint and Ark server were offline.'},
      {id:'refusal-demo',label:'Dedicated Cashu reserve paid with the mint offline',
        status:'Verified regtest payout',done:true,
        detail:'Bitcoin Core confirmed 24,750 sats to the holder after six blocks and a 250-sat fee. Proof Grove holds the recorded Shinigami proof pair for issuance and the offline payout. That run used a separately funded reserve.'},
      {id:'melt-reserve-demo',label:'Fund the holder reserve by melting Cashu',
        status:'Archived regtest settlement',done:true,
        detail:'The campaign recorded a CDK-funded 24,000-sat reserve and a 23,750-sat offline payout. The exact Cairo replay matched all 24 public output words. The original Bitcoin blocks and independent checkpoint are still needed.'},
      {id:'exact-melt-stark',label:'PG-ZK-01 · Prove the exact 23,750-sat statement',
        status:'Payout STARK accepted by stock Scarb',done:true,
        detail:'The A100 run produced one STARK in 316.33 seconds. CUDA processed 805,306,331 Merkle nodes in 124.59 seconds. The VM was deleted and the estimated cost ceiling was $0.163.'},
      {id:'exact-melt-audit',label:'PG-ZK-01 · Audit the downloaded proof statement',
        status:'Independent statement audit passed',done:true,
        detail:'The verifier accepted the pinned program and profile, matched all 24 public output words and rejected one mutation of each word.'},
      {id:'exact-melt-chain',label:'PG-ZK-01 · Confirm historical Bitcoin inclusion and timelock',
        status:'Original chain evidence required',done:false,
        detail:'The original regtest blocks and an independent checkpoint are needed to confirm the archived payout and six-block timelock.'},
      {id:'nova-protected',label:'PG-ZK-02 · Verify protected reserve accounting',
        status:'Verified Nova fixture',done:true,
        detail:'The fixture journal and compressed proof exercise reserve registration, issuance, split, swap and redemption. Replay and accounting mutations are covered. Production reserve completeness and external bearer liabilities remain open.'},
      {id:'protected-holder',label:'PG-ZK-03 · Exercise a funded holder exit',
        status:'Verified protected regtest exit',done:true,
        detail:'Bitcoin Core confirmed the holder-only payout after six blocks on a reserve tied to the V3 issuance. Cooperative melt and emergency exit spend the same outpoint, so they can settle only once on the active chain.'},
      {id:'cashu-bitvm',label:'PG-ZK-04 · Bind Cashu settlement to BitVM3',
        status:'Sized fixture · full composition open',done:false,
        detail:'The fixed Cashu record circuit measured 71,477 non-free gates. A funded one-byte dispute paid both challenge and reclaim paths on regtest. Full SP1 proof verification and Bitcoin-enforced settlement composition remain open.'},
      {id:'ark-proof',label:'Ark Nova → SP1 → M13 → BitVM3 off-chain proof',
        status:'Suspended · checkpoints preserved',done:false,
        detail:ark.checksPassed?
          'The coordinator reported proof checks. The archived statement and artifact hashes still require an independent audit.':
          'General-purpose Ark proving is suspended while Cashu verification continues. The existing checkpoint archive is preserved.'},
    ];
    return {friday,trust:cashuTrustMilestones.map(item=>({status:'Open · no ETA',...item,done:false}))};
  }
  function ongoingJobs({ark, shinigami, local, localFresh, localSample, paused}) {
    const rows=[];
    const observedState=(fresh,current)=>paused?'Paused':fresh?current:'Stale';
    if(ark?.sample.active && ark.sample.stage!=='failed') {
      const sample=ark.sample;
      const activity=sample.local_verification?'Verifying':sample.ark_running?'Running':
        ['returning','stopped'].includes(sample.stage)?'Collecting results':'Preparing';
      const staging=['staging','queued','waiting_stock'].includes(sample.stage);
      rows.push({id:'cloud-ark',title:sample.local_verification?'Ark proof verification':'Ark SP1 prover',
        where:sample.local_verification?'Local machine · CPU':staging?'Hyperstack · private storage':'Hyperstack · A100 GPU',
        phase:ark.fresh?ark.phase:ark.knownPhase,status:observedState(ark.fresh,activity),heardAt:sample.sampled_at_unix,
        details:'#shard-panel',detailsLabel:sample.local_verification?'Verification details':'Checkpoint details',metrics:staging?[
          ['Uploaded MiB',Number.isSafeInteger(sample.seed_bytes)?Math.floor(sample.seed_bytes/2**20):null],
          ['Verified transfer parts',sample.seed_parts]
        ]:[
          ['New core shards',sample.core_new],['New recursion proofs',sample.recursion_new],['Replayed core shards',sample.core_replayed]
        ]});
      if(sample.nova_running)rows.push({id:'cloud-nova',title:'MNR-04 clearing proof',where:'Hyperstack · CPU',
        phase:'Regtest and Nova benchmark',status:observedState(ark.fresh,'Running'),heardAt:sample.sampled_at_unix});
    }
    if(shinigami?.sample.active) {
      const sample=shinigami.sample;
      const activity=['provisioning','booted','benchmark_started','benchmark_running','started'].includes(sample.stage)?'Preparing':
        ['retrieving','fresh_proof_independently_verified'].includes(sample.stage)?'Collecting results':'Running';
      rows.push({id:'cloud-shinigami',title:'Shinigami issuance benchmark',where:'Hyperstack · CPU',
        phase:shinigami.knownPhase,status:observedState(shinigami.active,activity),heardAt:sample.sampled_at_unix});
    }
    for(const job of local) {
      if(!job.running && !job.process && job.status!=='resource wait')continue;
      const activity=job.status==='resource wait'?'Waiting for resources':'Running';
      const isNova=job.kind==='mnr04'||job.kind==='mnr05';
      const pct=localFresh&&!paused&&finite(job.progress_pct)?Math.min(100,Math.max(0,job.progress_pct)):null;
      const metrics=[];
      if(isNova&&localFresh&&!paused) {
        if(pct!==null)metrics.push(['Progress %',Math.round(pct)]);
        if(Number.isSafeInteger(job.fold_step)&&Number.isSafeInteger(job.fold_total)&&job.fold_total>0) {
          metrics.push(['Fold step',job.fold_step],['Fold total',job.fold_total]);
        }
        metrics.push(
          ['CPU seconds',Number.isFinite(job.cpu_seconds)?Math.floor(job.cpu_seconds):null],
          ['Process RAM MiB',Number.isFinite(job.ram_bytes)?Math.floor(job.ram_bytes/2**20):null],
        );
      }
      rows.push({id:job.id,title:job.title,where:['Local machine',job.backend].filter(Boolean).join(' · '),
        phase:job.phase,status:observedState(localFresh,activity),heardAt:localSample,
        progressPct:pct,metrics,
        details:'#runtime-panel',detailsLabel:'Process details'});
    }
    return rows;
  }
  function rememberCheckpoints(history, sample) {
    const {sampled_at_unix: t, core_new: core, recursion_new: recursion, core_replayed: replayed} = sample;
    const replayedRecursion=Number.isSafeInteger(sample.recursion_replayed)&&sample.recursion_replayed>=0?sample.recursion_replayed:null;
    if(![t,core,recursion,replayed].every(value=>Number.isSafeInteger(value) && value>=0))return history;
    const last=history.at(-1);
    if(last && t<=last.t)return history;
    const prior=last && (core<last.core || recursion<last.recursion || replayed<last.replayed) ? [] : history;
    return [...prior.filter(point=>t-point.t<=1800),{t,core,recursion,replayed,replayedRecursion}].slice(-240);
  }
  function checkpointTrend(history) {
    const last=history.at(-1);
    if(!last)return null;
    const changes=history.slice(1).map((point,i)=>({t:point.t,
      core:point.core-history[i].core,recursion:point.recursion-history[i].recursion}));
    const recent=changes.filter(point=>last.t-point.t<=60);
    const rates={};
    for(const window of [5,15,30]) {
      const first=history.find(point=>last.t-point.t<=window*60);
      const span=last.t-first.t;
      if(span>=60)rates['shard_per_min_'+window+'m']=(last.core-first.core)*60/span;
    }
    const latestCore=changes.findLast(point=>point.core>0);
    const lastMinute=recent.reduce((sum,point)=>({core:sum.core+point.core,recursion:sum.recursion+point.recursion}),{core:0,recursion:0});
    return {lastMinute,recent:recent.slice(-10),latestChange:changes.findLast(point=>point.core||point.recursion),
      rate:rates.shard_per_min_5m,
      progress:{exists:true,unique_shards:last.replayed+last.core,rates,
        recent_events:latestCore?[{kind:'shard',replayed:false,t:latestCore.t}]:[]}};
  }
  function checkpointMosaic(history) {
    const newest=[];
    for(let i=history.length-1;i>0 && newest.length<319;i--) {
      const point=history[i], prev=history[i-1];
      const groups=[
        ['recursion',false,point.recursion-prev.recursion],
        ['core',false,point.core-prev.core],
        ['recursion',true,Number.isSafeInteger(point.replayedRecursion)&&Number.isSafeInteger(prev.replayedRecursion)?
          point.replayedRecursion-prev.replayedRecursion:0],
        ['core',true,point.replayed-prev.replayed],
      ];
      for(const [kind,replayed,count] of groups) {
        const slots=Math.min(319-newest.length,count);
        for(let j=0;j<slots;j++)newest.push({kind,replayed,t:point.t});
      }
    }
    return newest.reverse();
  }
  function observedBudgetPace(history) {
    const last=history.at(-1);
    if(!last)return null;
    const first=history.find(point=>point.replayed===last.replayed && last.t-point.t<=300);
    const seconds=last.t-first.t, cores=last.core-first.core;
    return seconds>=240 && cores>0 ? {perMinute:cores*60/seconds,seconds} : null;
  }
  function a100Budget({saved,target,rate,credit,coresPerMinute=10.38}) {
    if(!finite(rate)||rate<=0)return null;
    if(coresPerMinute!==null&&(!finite(coresPerMinute)||coresPerMinute<=0))return null;
    const coresPerHour=coresPerMinute===null?null:coresPerMinute*60;
    const hasTarget=Number.isSafeInteger(saved)&&saved>=0&&Number.isSafeInteger(target)&&target>0&&target>=saved&&target<=10000000;
    const hours=hasTarget&&coresPerHour!==null?(target-saved)/coresPerHour:null;
    const cost=hours===null?null:hours*rate;
    const runway=finite(credit)&&credit>=0?credit/rate:null;
    return {hours,cost,perThousand:coresPerHour===null?null:1000/coresPerHour*rate,runway,
      runwayCores:runway===null||coresPerHour===null?null:Math.floor(runway*coresPerHour),
      shortfall:cost===null||runway===null?null:Math.max(0,cost-credit)};
  }
  function arkWorkerLabel({paused,live,observed,saved,checksPassed}) {
    if(paused)return 'Display paused';
    if(live)return 'Worker running';
    if(checksPassed)return 'Proof checks passed';
    if(!observed)return 'Worker status unknown';
    return Number.isSafeInteger(saved)&&saved>0?'Idle · checkpoints saved':'Idle · no worker running';
  }
  function arkArchive(sample = {}, now = Date.now()/1000) {
    const prefix='https://github.com/patrickdugan/zk-rusto-no-bitcoino/releases/tag/ark-679-';
    const release=(value,kind)=>typeof value==='string'&&value.startsWith(prefix+kind+'-')&&
      /^[0-9a-f]{10}$/.test(value.slice((prefix+kind+'-').length))?value:null;
    const checkpoint=release(sample.checkpoint_release,'spot');
    const proof=sample.stage==='proof_checks_passed'&&/^[0-9a-f]{40}$/.test(sample.proof_commit||'')?
      release(sample.proof_release,'offchain'):null;
    const raw=sample.private_storage, age=now-raw?.sampled_at_unix;
    const storage=raw&&[raw.bucket_bytes,raw.objects,raw.sampled_at_unix].every(value=>Number.isSafeInteger(value)&&value>=0)&&
      age>=-5 ? {...raw,fresh:age<=120} : null;
    const exportStatus=checkpoint?null:sample.checkpoint_release_error===true?'Checkpoint publication needs review':
      sample.checkpoint_export_finished===true?'Final checkpoint export confirmed':
      sample.checkpoint_export_finished===false?'Final checkpoint export unconfirmed':null;
    return {checkpoint,proof,storage,exportStatus};
  }
  return {estimate,clock,arkCampaign,arkDeadline,arkBudgets,cashuRoadmap,ongoingJobs,
    rememberCheckpoints,checkpointTrend,checkpointMosaic,a100Budget,observedBudgetPace,arkWorkerLabel,arkArchive,arkStageResources};
})();
if(typeof module!=='undefined' && module.exports)module.exports=ProofEta;
if(typeof document!=='undefined') (() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const esc = v => String(v ?? 'Unavailable').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const n = (v, digits = 0) => typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString('en-US', {maximumFractionDigits: digits}) : '—';
  const gib = v => typeof v === 'number' && Number.isFinite(v) ? `${n(v / 2**30, 2)} GiB` : 'Unavailable';
  const time = t => typeof t === 'number' && Number.isFinite(t) ? new Date(t * 1000).toLocaleString() : 'Unavailable';
  const clockTime = t => typeof t === 'number' && Number.isFinite(t) ? new Date(t * 1000).toLocaleTimeString() : '--:--:--';
  const kv = (key, value) => `<div class="kv-item"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`;

  function fmtAgo(unixSec) {
    if (!Number.isFinite(unixSec)) return '--';
    const diff = Math.max(0, Math.round(Date.now() / 1000 - unixSec));
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s ago`;
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    return `${h}h ${m}m ago`;
  }

  function formatDuration(seconds) {
    if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return '--:--:--';
    const s = Math.max(0, Math.ceil(seconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  }

  function formatCompactAge(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return '0.0s';
    if (seconds < 100) return `${seconds.toFixed(1)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m${String(Math.floor(seconds % 60)).padStart(2, '0')}s`;
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${String(m).padStart(2, '0')}m`;
  }

  function planningDuration(seconds) {
    const minutes = Math.ceil(Math.max(0, seconds) / 60);
    const days = Math.floor(minutes / 1440);
    const hours = Math.floor((minutes % 1440) / 60);
    return [days && `${days}d`, hours && `${hours}h`, (minutes % 60 || !minutes) && `${minutes % 60}m`].filter(Boolean).join(' ');
  }

  const singaporeTime = new Intl.DateTimeFormat('en-SG', {
    timeZone: 'Asia/Singapore', weekday: 'short', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  });
  function finishLabel(range) {
    const fast = singaporeTime.format(range.fast * 1000);
    const slow = singaporeTime.format(range.slow * 1000);
    return `${fast === slow ? fast : `${fast} – ${slow}`} SGT`;
  }

  const PRESETS = {
    m16_mainnet: { header_blocks: 975072, nova_header_shards: 2, utxo_window_blocks: 0, payment_utxos: 1, shinigami_leaves: 0, ark_vtxos: 0, element_threshold_exp: 27, hardware_profile: 'rtx5080_12gib' },
    m18_window: { header_blocks: 975072, nova_header_shards: 2, utxo_window_blocks: 6, payment_utxos: 1, shinigami_leaves: 0, ark_vtxos: 0, element_threshold_exp: 27, hardware_profile: 'rtx5080_12gib' },
    ark_live: { header_blocks: 0, nova_header_shards: 0, utxo_window_blocks: 0, payment_utxos: 0, shinigami_leaves: 0, ark_vtxos: 4, element_threshold_exp: 26, hardware_profile: 'rtx5080_bounded_2gib' },
    ark_round_128: { header_blocks: 1016, nova_header_shards: 1, utxo_window_blocks: 0, payment_utxos: 4, shinigami_leaves: 16, ark_vtxos: 128, element_threshold_exp: 26, hardware_profile: 'rtx5080_bounded_2gib' },
    shinigami_batch: { header_blocks: 0, nova_header_shards: 0, utxo_window_blocks: 0, payment_utxos: 8, shinigami_leaves: 64, ark_vtxos: 0, element_threshold_exp: 27, hardware_profile: 'rtx5080_12gib' },
  };

  const TAB_PHASES = { live: '01', compute: '02', blocks: '03', utxos: '04', cashu: '05', estimator: '06' };

  const initialTab = new URLSearchParams(window.location.search).get('view') === 'compute' ? 'compute' : 'live';
  const state = {
    live: null,
    records: [],
    selected: null,
    userSelected: false,
    tab: initialTab,
    polling: true,
    eventSource: null,
    fallbackTimer: null,
    evidenceTimer: null,
    lastReceived: 0,
    lastSamplePerfMs: performance.now(),
    history: [],
    previous: new Map(),
    workerAdvances: new Set(),
    etaClock: null,
    etaModel: null,
    etaSource: null,
    lastEventSeq: null,
    etaTarget: null,
    newEventSeqs: new Set(),
    // 60fps Liveness & Matrix Animation State
    busParticles: [],
    busRings: [],
    tileBursts: [],
    mosaicRects: [],
    hoveredTile: null,
    replayingPreview: false,
    replayTimers: [],
    highlightedKeys: new Set(),
    cloudFeedEvents: [],
    lastCloudCounts: null,
    activeMosaicTiles: [],
    activeMosaicLive: false,
    activeMosaicSource: 'Awaiting telemetry',
  };

  const readSetting = key => { try { return localStorage.getItem(key); } catch { return null; } };
  const saveSetting = (key, value) => { try { localStorage.setItem(key, value); } catch {} };
  let checkpointKey = null;
  let checkpointHistory = [];

  function observeCloudCheckpoints() {
    const sample = state.live?.cloud_hyperstack_ark;
    if (!Number.isSafeInteger(sample?.vm_id)) return;
    const key = `rbzk.checkpoints.${sample.vm_id}.${sample.started_at_unix}`;
    if (checkpointKey !== key) {
      checkpointKey = key;
      state.lastCloudCounts = null;
      state.cloudFeedEvents = [];
      try {
        const stored = JSON.parse(readSetting(key) || '[]');
        checkpointHistory = Array.isArray(stored)
          ? stored.filter(p => [p?.t, p?.core, p?.recursion, p?.replayed].every(Number.isSafeInteger))
          : [];
      } catch {
        checkpointHistory = [];
      }
    }
    if (!sample.active || !sample.ark_running) return;
    const prevCounts = state.lastCloudCounts;
    const curCounts = {
      core: sample.core_new || 0,
      rec: sample.recursion_new || 0,
      replayed: sample.core_replayed || 0,
    };
    if (prevCounts) {
      const dCore = curCounts.core - prevCounts.core;
      const dRec = curCounts.rec - prevCounts.rec;
      const nowSec = sample.sampled_at_unix || Math.floor(Date.now() / 1000);
      if (dCore > 0) {
        const ev = { kind: 'shard', key: `a100+${dCore}`, ms: 0, replayed: false, t: nowSec, count: dCore, cloud: true };
        state.cloudFeedEvents.push(ev);
        emitCheckpointVisual(ev, null, false);
      }
      if (dRec > 0) {
        const ev = { kind: 'reduce', key: `rec+${dRec}`, ms: 0, replayed: false, t: nowSec, count: dRec, cloud: true };
        state.cloudFeedEvents.push(ev);
        emitCheckpointVisual(ev, null, false);
      }
      if (state.cloudFeedEvents.length > 24) {
        state.cloudFeedEvents = state.cloudFeedEvents.slice(-24);
      }
    }
    state.lastCloudCounts = curCounts;

    const next = ProofEta.rememberCheckpoints(checkpointHistory, sample);
    if (next !== checkpointHistory) {
      checkpointHistory = next;
      saveSetting(checkpointKey, JSON.stringify(next));
    }
  }

  const computeTargetKey = 'rbzk.compute.target';
  const computeProviderKey = 'rbzk.compute.provider';
  const computeProviders = [
    {
      id: 'runpod', name: 'Runpod', rate: '$4.39/GPU-hr',
      icon: 'M4 4h10l6 6v10H10l-6-6zM4 9h8l3 3v8M9 4v5m6 6h5',
      console: 'https://console.runpod.io/', pricing: 'https://www.runpod.io/pricing',
      setup: [
        ['Pod', 'Secure Cloud on demand · 1 × H100 SXM 80 GB'],
        ['Image', 'runpod/pytorch:1.0.3-cu1281-torch291-ubuntu2404'],
        ['Workspace', '120 GB network volume · full SSH (TCP 22)'],
        ['Runtime', 'One-hour auto-stop'],
      ],
    },
    {
      id: 'hyperstack', name: 'Hyperstack', rate: '$3.20/GPU-hr',
      icon: 'M12 3 3 8l9 5 9-5zM3 12l9 5 9-5M3 16l9 5 9-5',
      console: 'https://console.hyperstack.cloud/', pricing: 'https://www.hyperstack.cloud/gpu-pricing',
      setup: [
        ['Published flavor', 'n3-H100-SXM5x8 · Canada-1 / US-1'],
        ['Image', 'Ubuntu 24.04 · R570 · CUDA 12.8 · Docker'],
        ['Workspace', 'Persistent volume at /workspace · key-based SSH'],
      ],
      note: 'The published SXM flavor has eight GPUs. Confirm stock and the total price for a one-hour pilot.',
    },
  ];

  const planKey = 'rbzk.ark-campaign-plan.2026-11-23';
  const planFields = [['core', 'Expected total saved cores'], ...ProofEta.arkBudgets];
  let campaignPlan = {};
  try { campaignPlan = JSON.parse(readSetting(planKey)) || {}; } catch {}

  const arkProcess = () => (state.live?.runtime?.ark_processes || [])
    .find(p => p.executable === '/root/nb3-gpu-target/release/ark-prove-gpu-cached-gkr');
  const isCampaignRun = wsl => /(?:^|[\\/])ark-asp-full-20261117[\\/]?$/.test(wsl.base_dir || '');

  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  let quietMotion = reducedMotion.matches || readSetting('rbzk.motion') === 'still';

  function isMotionEnabled() {
    return !quietMotion && !reducedMotion.matches;
  }

  function applyMotion() {
    const still = !isMotionEnabled();
    document.documentElement.dataset.motion = still ? 'still' : 'live';
    const btn = $('toggle-motion');
    if (btn) {
      btn.textContent = still ? 'MOTION: STILL' : 'MOTION: LIVE';
      btn.setAttribute('aria-pressed', still ? 'true' : 'false');
    }
  }

  function setMarkup(id, markup) {
    const node = $(id);
    if (!node || node.innerHTML === markup) return;
    const open = new Set([...node.querySelectorAll('details[open]')].map(d => d.dataset.detailKey || d.querySelector('summary')?.textContent));
    const focused = node.contains(document.activeElement) ? document.activeElement?.dataset.id : null;
    node.innerHTML = markup;
    node.querySelectorAll('details').forEach(d => {
      d.open = open.has(d.dataset.detailKey || d.querySelector('summary')?.textContent);
    });
    if (focused) {
      [...node.querySelectorAll('[data-id]')].find(b => b.dataset.id === focused)?.focus({preventScroll: true});
    }
  }

  function statusClass(s) {
    return s === 'running' || s === 'Running' ? 'live' : s === 'verified receipt' ? 'cyan' : '';
  }

  function freshRuntime() {
    const rt = state.live?.runtime || {};
    return state.polling && rt.fresh && Date.now() - state.lastReceived < 15000;
  }

  function runpodSignal() {
    const cloud = state.live?.cloud_runpod;
    const received = state.polling && Date.now() - state.lastReceived < 15000;
    const fresh = received && cloud?.fresh === true;
    const authenticated = cloud?.authenticated === true;
    const running = String(cloud?.status || '').toUpperCase() === 'RUNNING';
    const gpuName = typeof cloud?.pod?.gpu_name === 'string' ? cloud.pod.gpu_name.trim() : '';
    const provider = cloud?.provider === 'Prime Intellect'
      ? (String(cloud?.pod?.upstream_provider || '').trim().toLowerCase() === 'runpod' ? 'Runpod via Prime' : 'Prime Intellect')
      : cloud?.provider === 'Runpod' ? 'Runpod' : 'Cloud';
    return {cloud, fresh, authenticated, running, gpuName, provider, active: fresh && authenticated && running};
  }

  function cloudMeasure(value, suffix) {
    return Number.isFinite(value) ? `${n(value, 1)}${suffix}` : 'Unavailable';
  }

  const hyperstackStages = {
    provisioning: 'Provisioning', booted: 'Preparing worker', benchmark_started: 'Starting benchmark',
    benchmark_running: 'Starting benchmark', started: 'Starting benchmark', execute: 'Executing Cairo',
    prove: 'Generating issuance proof', verify: 'Verifying on worker',
    reject_changed_anchor_amount: 'Testing changed amount', reject_changed_commitment: 'Testing changed commitment',
    fresh_proof_independently_verified: 'Returning proof', retrieving: 'Retrieving results',
    local_verification: 'Checking live regtest statement', verified: 'Issuance verified',
    failed: 'Benchmark failed', cleanup_unconfirmed: 'Cloud cleanup unconfirmed',
  };

  function hyperstackSignal() {
    const sample = state.live?.cloud_hyperstack;
    if (!sample || !Object.hasOwn(hyperstackStages, sample.stage)) return null;
    const age = Date.now() / 1000 - sample.sampled_at_unix;
    const active = sample.active && state.polling && Date.now() - state.lastReceived < 15000 && age >= -10 && age < 50;
    const status = !state.polling ? 'Display paused' : sample.active && !active ? 'Telemetry stale' : hyperstackStages[sample.stage];
    return {
      sample, active, status, knownPhase: hyperstackStages[sample.stage],
      hardware: sample.a100_confirmed ? 'NVIDIA A100 80 GB PCIe' : 'A100 on-demand VM',
    };
  }

  function arkCloudSignal() {
    const sample = state.live?.cloud_hyperstack_ark;
    const phases = {
      staging: 'Uploading the held checkpoint',
      queued: 'Checkpoint staged · waiting to launch',
      waiting_stock: 'Checkpoint staged · waiting for spot capacity',
      provisioning: 'Provisioning A100',
      preparing: 'Verifying the pinned GPU kit',
      restoring_public_checkpoint: 'Restoring the public checkpoint',
      restoring_private_checkpoint: 'Restoring the private checkpoint delta',
      checking_checkpoint_export: 'Checking durable checkpoint storage',
      starting: 'Starting prover',
      verify_sdk_m13: 'Independently verifying SP1 and M13',
      verify_m14: 'Evaluating and testing BitVM3',
      proof_checks_passed: 'Independent proof checks passed',
      verification_failed: 'Local proof verification failed',
      replay: 'Replaying checkpoints',
      shard: 'Writing core shards',
      reduce: 'Writing recursion checkpoints',
      returning: 'Retrieving results',
      stopped: 'Pilot stopped',
      failed: 'Pilot failed',
    };
    if (!sample || !Object.hasOwn(phases, sample.stage)) return null;
    const age = Date.now() / 1000 - sample.sampled_at_unix;
    const boot = ['staging', 'queued', 'waiting_stock', 'provisioning', 'preparing',
      'restoring_public_checkpoint', 'restoring_private_checkpoint', 'checking_checkpoint_export'].includes(sample.stage);
    const fresh = state.polling && Date.now() - state.lastReceived < 15000 && age >= -10 && age < (boot ? 125 : 35);
    const progressAge = Date.now() / 1000 - sample.last_checkpoint_at_unix;
    const phase = !state.polling ? 'Display paused' : sample.active && !fresh ? 'Server heartbeat stale'
      : fresh && sample.ark_running && progressAge >= 60 ? 'Prover running · awaiting checkpoint' : phases[sample.stage];
    return {
      sample, phase, fresh, knownPhase: phases[sample.stage],
      active: sample.active && fresh && !sample.local_verification && Number.isSafeInteger(sample.vm_id),
    };
  }

  function parseUtcSeconds(isoStr) {
    if (typeof isoStr !== 'string' || !isoStr.trim()) return null;
    const norm = /(?:Z|[+-]\d\d:\d\d)$/i.test(isoStr.trim()) ? isoStr.trim() : `${isoStr.trim()}Z`;
    const ms = Date.parse(norm);
    return Number.isFinite(ms) ? ms / 1000 : null;
  }

  function hyperstackLiveSignal() {
    const raw = state.live?.cloud_hyperstack_vms;
    const received = state.polling && Date.now() - state.lastReceived < 15000;
    const fresh = received && raw?.fresh === true;
    const authenticated = raw?.authenticated === true;
    const instances = Array.isArray(raw?.instances) ? raw.instances : [];
    const activeInstances = instances.filter(vm => vm?.active === true);
    const buckets = Array.isArray(raw?.buckets) ? raw.buckets : [];
    const totalBucketBytes = buckets.reduce((acc, b) => acc + (Number(b?.size_bytes) || 0), 0);
    const totalBucketObjects = buckets.reduce((acc, b) => acc + (Number(b?.num_objects) || 0), 0);
    return {
      raw, fresh, authenticated, instances, activeInstances, buckets,
      totalBucketBytes, totalBucketObjects,
      sampledAt: raw?.sampled_at_unix,
      status: raw?.status || 'connecting',
    };
  }

  // --- Event-Driven Completion Burst Choreography (Toasts, Stage Bus Pulse, Canvas Shockwave) ---
  function emitCheckpointVisual(ev, tileIdxOverride = null, isReplayPreview = false) {
    const isReduce = ev.kind === 'reduce';
    const qty = ev.count || 1;
    const sec = ev.ms ? ` · ${(ev.ms / 1000).toFixed(1)}s` : '';
    const label = isReduce
      ? `+${qty} REDUCE${sec}`
      : ev.replayed
      ? '↻ SHARD REPLAY'
      : `+${qty} SHARD${sec}`;

    // 1. Flash top Shard Stream ribbon & matching KPI column + spawn skewed floating pop-toast
    const targets = [$('ribbon-shard-card'), isReduce ? $('kpi-rec-card') : $('kpi-core-card')];
    const cls = isReduce ? 'flash-reduce' : 'flash-shard';
    targets.forEach(card => {
      if (!card) return;
      card.classList.remove('flash-shard', 'flash-reduce');
      void card.offsetWidth;
      card.classList.add(cls);
      const toast = document.createElement('span');
      toast.className = `pop-toast ${isReduce ? 'reduce' : 'shard'}`;
      toast.textContent = isReplayPreview ? `▶ ${label}` : label;
      card.appendChild(toast);
      setTimeout(() => toast.remove(), 1950);
    });

    // 2. Single event-only completion pulse along active stage bus wire
    // NOVA(68) -> CORE(204) -> 3:1(340) -> M13(476) -> M14(612)
    const fromX = isReduce ? 204 : 68;
    const toX = isReduce ? 340 : 204;
    const isLight = document.documentElement.getAttribute('data-theme') === 'grove';
    const color = isReduce ? (isLight ? '#070709' : '#F5F5F5') : '#E60E1B';
    state.busParticles.push({
      fromX, toX, y: 36, progress: 0, speed: 0.028, r: 4.0, color, burstOnArrive: true,
    });

    // 3. Expanding shockwave burst on the Canvas Matrix
    const targetIdx = tileIdxOverride !== null
      ? tileIdxOverride
      : Math.max(0, state.activeMosaicTiles.length - 1);
    state.tileBursts.push({
      idx: targetIdx,
      born: performance.now(),
      duration: 1350,
      color,
    });

    // 4. Mark feed item for slide-in highlight
    const hKey = String(ev.seq || ev.key || `${ev.kind}:${ev.t}`);
    state.highlightedKeys.add(hKey);
    setTimeout(() => state.highlightedKeys.delete(hKey), 2200);
  }

  function triggerRecentReplay() {
    const wsl = state.live?.wsl_prover || {};
    const events = (wsl.progress?.recent_events || []).slice(-12);
    if (!events.length) return;

    state.replayTimers.forEach(clearTimeout);
    state.replayTimers = [];
    state.replayingPreview = true;
    const pill = $('replay-mode-pill');
    const btn = $('replay-completions-btn');
    if (pill) pill.hidden = false;
    if (btn) btn.textContent = '⚡ REPLAYING 12 SHARDS…';

    const tailLen = state.activeMosaicTiles.length;
    events.forEach((ev, i) => {
      const tid = setTimeout(() => {
        const tileIdx = Math.max(0, tailLen - events.length + i);
        emitCheckpointVisual(ev, tileIdx, true);
        renderCompletionFeed();
      }, i * 360);
      state.replayTimers.push(tid);
    });

    const endTid = setTimeout(() => {
      state.replayingPreview = false;
      if (pill) pill.hidden = true;
      if (btn) btn.textContent = '▶ REPLAY LAST 12 SHARDS';
    }, events.length * 360 + 950);
    state.replayTimers.push(endTid);
  }

  // --- 60fps Continuous Animation Loop (Reticle Stopwatch, Ticking Countdowns, Bus Pulses, Canvas Matrix) ---
  function startAnimationLoop() {
    function frame(nowMs) {
      updateCockpitReticle(nowMs);
      updateLiveCountdowns();
      updateProofBusParticles();
      drawShardMosaic(nowMs);
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }

  function updateCockpitReticle(nowMs) {
    const ringArc = $('cockpit-ring-arc');
    const orbit = $('cockpit-ring-orbit');
    const timerVal = $('cockpit-timer-val');
    const timerSub = $('cockpit-timer-sub');
    if (!ringArc || !timerVal || !state.live) return;

    const circumference = 226.2;
    const arkCloud = arkCloudSignal();
    const localProc = arkProcess();
    const wsl = state.live?.wsl_prover || {};
    const nowSec = Date.now() / 1000;

    let isLiveWorker = false;
    let frac = 0.25;
    let orbitSpeed = 760;

    if (!state.polling) {
      timerVal.textContent = 'PAUSED';
      if (timerSub) timerSub.textContent = 'HOLD';
      ringArc.setAttribute('stroke', 'var(--ink-dim)');
      frac = 0.0;
    } else if (arkCloud?.active && arkCloud.sample.ark_running) {
      isLiveWorker = true;
      const s = arkCloud.sample;
      const lastCkpt = Number.isFinite(s.last_checkpoint_at_unix) ? Math.max(0, nowSec - s.last_checkpoint_at_unix) : null;
      const leaseElapsed = Number.isFinite(s.started_at_unix) ? Math.max(0, nowSec - s.started_at_unix) : 0;
      const leaseTotal = Number.isFinite(s.lease_ends_at_unix) && Number.isFinite(s.started_at_unix)
        ? Math.max(1, s.lease_ends_at_unix - s.started_at_unix) : 28800;

      if (lastCkpt !== null && lastCkpt < 3600) {
        timerVal.textContent = formatCompactAge(lastCkpt);
        if (timerSub) timerSub.textContent = 'SINCE CKPT';
      } else {
        timerVal.textContent = formatCompactAge(leaseElapsed);
        if (timerSub) timerSub.textContent = 'A100 LIVE';
      }
      frac = Math.min(0.96, Math.max(0.12, leaseElapsed / leaseTotal));
      ringArc.setAttribute('stroke', 'var(--crimson)');
      orbitSpeed = s.stage === 'replay' ? 920 : 620;
    } else if (arkCloud?.sample?.active && arkCloud.fresh) {
      isLiveWorker = true;
      const elapsed = Number.isFinite(arkCloud.sample.started_at_unix) ? Math.max(0, nowSec - arkCloud.sample.started_at_unix) : 0;
      timerVal.textContent = formatCompactAge(elapsed);
      if (timerSub) timerSub.textContent = String(arkCloud.sample.stage || 'PREP').slice(0, 9).toUpperCase();
      frac = 0.45;
      ringArc.setAttribute('stroke', 'var(--crimson)');
      orbitSpeed = 1100;
    } else if (freshRuntime() && localProc) {
      isLiveWorker = true;
      const lastEv = (wsl.progress?.recent_events || []).at(-1);
      const curS = lastEv && Number.isFinite(lastEv.t) ? Math.max(0, nowSec - lastEv.t) : 0;
      timerVal.textContent = formatCompactAge(curS);
      if (timerSub) timerSub.textContent = 'LOCAL GPU';
      frac = Math.min(0.96, curS / 40);
      ringArc.setAttribute('stroke', 'var(--crimson)');
      orbitSpeed = 680;
    } else if (hyperstackLiveSignal().activeInstances.length > 0) {
      isLiveWorker = true;
      const hs = hyperstackLiveSignal();
      const selVm = hs.activeInstances.find(v => `hyperstack-vm:${v.id}` === state.selected) || hs.activeInstances[0];
      const created = parseUtcSeconds(selVm.created_at);
      const up = created !== null ? Math.max(0, nowSec - created) : 0;
      timerVal.textContent = created !== null ? formatCompactAge(up) : String(selVm.status || 'LIVE');
      if (timerSub) timerSub.textContent = selVm.gpu ? 'CLOUD GPU' : 'CLOUD NODE';
      const cpuPct = Number(selVm.metrics?.cpu_percent);
      frac = Number.isFinite(cpuPct) ? Math.min(0.98, Math.max(0.12, cpuPct / 100)) : 0.45;
      ringArc.setAttribute('stroke', 'var(--crimson)');
      orbitSpeed = 760;
    } else {
      const saved = wsl.progress?.unique_shards;
      timerVal.textContent = Number.isSafeInteger(saved) ? n(saved) : 'IDLE';
      if (timerSub) timerSub.textContent = Number.isSafeInteger(saved) ? 'CACHED' : 'IDLE';
      ringArc.setAttribute('stroke', 'var(--ink-dim)');
      frac = Number.isSafeInteger(saved) ? 1.0 : 0.1;
    }

    ringArc.setAttribute('stroke-dashoffset', (circumference * (1 - frac)).toFixed(1));
    if (orbit) {
      const animate = isLiveWorker && isMotionEnabled();
      orbit.style.opacity = isLiveWorker ? '1' : '0.3';
      const angleRad = animate ? ((nowMs / orbitSpeed) % (Math.PI * 2)) - Math.PI / 2 : -Math.PI / 2;
      const ox = 44 + 36 * Math.cos(angleRad);
      const oy = 44 + 36 * Math.sin(angleRad);
      orbit.setAttribute('cx', ox.toFixed(1));
      orbit.setAttribute('cy', oy.toFixed(1));
    }
  }

  function updateLiveCountdowns() {
    tickDeadline();
    tickEta();
    if (!state.live) return;

    const arkCloud = arkCloudSignal();
    const nowSec = Date.now() / 1000;
    if (arkCloud?.active && Number.isFinite(arkCloud.sample.lease_ends_at_unix)) {
      const rem = Math.max(0, arkCloud.sample.lease_ends_at_unix - nowSec);
      const elapsed = Math.max(0, nowSec - (arkCloud.sample.started_at_unix || nowSec));
      const total = Math.max(1, arkCloud.sample.lease_ends_at_unix - (arkCloud.sample.started_at_unix || nowSec));
      const pct = Math.min(100, (elapsed / total) * 100);

      const gpuBadge = $('rib-gpu-badge');
      if (gpuBadge) {
        gpuBadge.textContent = `⏱ LEASE ${formatDuration(rem)}`;
        gpuBadge.className = 'eta-badge cyan';
      }
      const bar2R = $('cockpit-bar2-right');
      const bar2F = $('cockpit-bar2-fill');
      if (bar2R) bar2R.textContent = `Elapsed ${formatDuration(elapsed)} · Cutoff in ${formatDuration(rem)}`;
      if (bar2F) bar2F.style.width = `${pct.toFixed(1)}%`;

      const leaseEl = $('overview-lease');
      if (leaseEl && arkCloud.fresh) {
        leaseEl.textContent = `Lease cutoff in ${formatDuration(rem)}`;
      }
      const kpi1Foot = $('kpi-1-foot');
      if (kpi1Foot && state.selected === 'ark-sp1:campaign') {
        kpi1Foot.textContent = `VM #${arkCloud.sample.vm_id} · Cutoff ${formatDuration(rem)}`;
      }
    }
  }

  function updateProofBusParticles() {
    const layer = $('bus-particles-layer');
    if (!layer) return;
    if (!state.busParticles.length && !state.busRings.length) {
      if (layer.innerHTML !== '') layer.innerHTML = '';
      return;
    }

    const nextParticles = [];
    const svgParts = [];
    for (const p of state.busParticles) {
      p.progress += p.speed;
      if (p.progress >= 1) {
        if (p.burstOnArrive) {
          state.busRings.push({ x: p.toX, y: p.y, r: 14, alpha: 0.85, color: p.color });
        }
        continue;
      }
      nextParticles.push(p);
      const x = p.fromX + (p.toX - p.fromX) * p.progress;
      svgParts.push(`<circle cx="${x.toFixed(1)}" cy="${p.y}" r="${p.r}" fill="${p.color}" opacity="0.95"/>`);
    }
    state.busParticles = nextParticles;

    const nextRings = [];
    for (const rg of state.busRings) {
      rg.r += 0.6;
      rg.alpha -= 0.036;
      if (rg.alpha <= 0) continue;
      nextRings.push(rg);
      svgParts.push(`<circle cx="${rg.x}" cy="${rg.y}" r="${rg.r.toFixed(1)}" fill="none" stroke="${rg.color}" stroke-width="1.8" opacity="${rg.alpha.toFixed(2)}"/>`);
    }
    state.busRings = nextRings;
    layer.innerHTML = svgParts.join('');
  }

  function drawShardMosaic(nowMs) {
    const canvas = $('shard-mosaic-canvas');
    if (!canvas || state.tab !== 'live') return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);

    const cols = 40;
    const rows = 8;
    const maxSlots = cols * rows - 1;
    const slice = state.activeMosaicTiles.slice(-maxSlots);
    const gap = 3;
    const cellW = (W - gap * (cols + 1)) / cols;
    const cellH = (H - gap * (rows + 1)) / rows;
    const isLight = document.documentElement.getAttribute('data-theme') === 'grove';

    // Subtle background empty slot grid for architectural precision
    ctx.fillStyle = isLight ? 'rgba(7, 7, 9, 0.05)' : 'rgba(255, 255, 255, 0.035)';
    for (let i = slice.length; i < cols * rows; i++) {
      const col = i % cols;
      const row = Math.floor(i / cols);
      ctx.fillRect(gap + col * (cellW + gap), gap + row * (cellH + gap), cellW, cellH);
    }

    const rects = [];
    for (let i = 0; i < slice.length; i++) {
      const item = slice[i];
      const col = i % cols;
      const row = Math.floor(i / cols);
      const x = gap + col * (cellW + gap);
      const y = gap + row * (cellH + gap);

      const isReduce = item.kind === 'recursion';
      const isReplayed = !!item.replayed;
      ctx.fillStyle = isReduce
        ? isReplayed
          ? (isLight ? 'rgba(7, 7, 9, 0.28)' : 'rgba(245, 245, 245, 0.30)')
          : (isLight ? '#070709' : '#F5F5F5')
        : isReplayed
        ? 'rgba(230, 14, 27, 0.36)'
        : '#E60E1B';

      ctx.fillRect(x, y, cellW, cellH);

      if (state.hoveredTile && state.hoveredTile.idx === i) {
        ctx.strokeStyle = isLight ? '#070709' : '#FFFFFF';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x - 0.5, y - 0.5, cellW + 1, cellH + 1);
      }

      rects.push({
        idx: i, x, y, w: cellW, h: cellH,
        key: item.key || '', kind: item.kind, replayed: isReplayed,
        sec: item.seconds, t: item.t, source: item.source || state.activeMosaicSource, inFlight: false,
      });
    }

    // Active In-Flight Leading Slot (Pulsing Signal Crimson + White Target Brackets)
    const leadIdx = Math.min(cols * rows - 1, slice.length);
    const lCol = leadIdx % cols;
    const lRow = Math.floor(leadIdx / cols);
    const lx = gap + lCol * (cellW + gap);
    const ly = gap + lRow * (cellH + gap);
    if (state.activeMosaicLive) {
      const pulse = isMotionEnabled() ? 0.45 + 0.55 * Math.sin(nowMs / 240) : 0.85;
      ctx.fillStyle = `rgba(230, 14, 27, ${0.42 + 0.58 * pulse})`;
      ctx.fillRect(lx, ly, cellW, cellH);
      ctx.strokeStyle = isLight ? '#070709' : '#F5F5F5';
      ctx.lineWidth = 1.4;
      ctx.strokeRect(lx - 1.5, ly - 1.5, cellW + 3, cellH + 3);
      rects.push({ idx: leadIdx, x: lx, y: ly, w: cellW, h: cellH, inFlight: true });
    }
    state.mosaicRects = rects;

    // Expanding shockwave bursts over newly completed / replayed tiles
    const aliveBursts = [];
    for (const b of state.tileBursts) {
      const age = nowMs - b.born;
      if (age > b.duration) continue;
      aliveBursts.push(b);
      const localIdx = Math.max(0, Math.min(Math.max(0, slice.length - 1), b.idx));
      const col = localIdx % cols;
      const row = Math.floor(localIdx / cols);
      const cx = gap + col * (cellW + gap) + cellW / 2;
      const cy = gap + row * (cellH + gap) + cellH / 2;
      const t = age / b.duration;
      const radius = 4 + t * 26;
      const alpha = (1 - t) * 0.95;

      ctx.save();
      ctx.strokeStyle = b.color;
      ctx.lineWidth = 2.2 * (1 - t * 0.5);
      ctx.globalAlpha = alpha;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = '#ffffff';
      ctx.globalAlpha = Math.max(0, 1 - t * 2);
      ctx.beginPath();
      ctx.arc(cx, cy, cellW * 0.65, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
    state.tileBursts = aliveBursts;
  }

  function renderCompletionFeed() {
    const feed = $('completion-feed');
    if (!feed) return;
    const localEvents = (state.live?.wsl_prover?.progress?.recent_events || []).slice(-10);
    const combined = [...localEvents, ...state.cloudFeedEvents].slice(-8).reverse();
    if (!combined.length) {
      feed.innerHTML = `<div class="mono" style="padding:8px 2px;color:var(--ink-dim)">Waiting for checkpoint events…</div>`;
      return;
    }
    const maxMs = Math.max(40000, ...combined.map(e => e.ms || 1000));
    feed.innerHTML = combined.map(ev => {
      const isReduce = ev.kind === 'reduce';
      const pct = ev.ms ? Math.max(8, Math.min(100, (ev.ms / maxMs) * 100)) : 55;
      const dur = ev.cloud
        ? `A100 +${ev.count || 1}`
        : `${((ev.ms || 0) / 1000).toFixed(1)}s`;
      const hKey = String(ev.seq || ev.key || `${ev.kind}:${ev.t}`);
      const hi = state.highlightedKeys.has(hKey) || state.newEventSeqs.has(ev.seq) ? 'newly-arrived' : '';
      const fillCol = isReduce ? 'var(--ink)' : 'var(--crimson)';
      return `
        <div class="feed-item ${hi}">
          <span class="feed-kind ${isReduce ? 'reduce' : 'shard'}">${isReduce ? 'REDUCE' : 'SHARD'}</span>
          <span style="color:var(--ink)">${esc(String(ev.key || '').slice(0, 8))}</span>
          <div><div class="feed-dur-bar"><div class="feed-dur-fill" style="width:${pct.toFixed(1)}%;background:${fillCol}"></div></div></div>
          <span style="color:var(--ink-muted)">${esc(dur)} · ${esc(fmtAgo(ev.t))}</span>
        </div>`;
    }).join('');
  }

  // --- Campaign Overview, Milestones & Budget (Preserving 100% of Codex Truth Models) ---
  function milestoneMarkup({id, label, detail, status, done}) {
    const active = !done && /progress|pilot|verif|wait/i.test(status || '');
    const statusCls = done ? 'is-done' : active ? 'is-active' : '';
    return `<li class="campaign-milestone" data-stage="${esc(id)}" data-done="${done ? 'true' : 'false'}" data-active="${active ? 'true' : 'false'}">
      <div><strong>${esc(label)}</strong><p class="panel-sub">${esc(detail)}</p></div>
      <span class="milestone-status ${statusCls}">${esc(status)}</span>
    </li>`;
  }

  function renderCampaignOverview(campaign, cloud, trend, wsl, processObserved) {
    const proof = campaign.rows.filter(row => row.id !== 'delivery');
    const done = proof.filter(row => row.done).length;
    const savedCore = wsl.progress?.unique_shards;
    const savedRecursion = wsl.progress?.unique_reduces;
    const live = (freshRuntime() && processObserved) || (cloud?.fresh && cloud.sample.ark_running);
    const observed = cloud?.sample.active ? cloud.fresh : freshRuntime() && wsl.reachable === true;

    $('overview-progress').textContent = ProofEta.arkWorkerLabel({
      paused: !state.polling, live, observed, saved: savedCore, checksPassed: campaign.checksPassed,
    });
    $('overview-cache').textContent = Number.isSafeInteger(savedCore)
      ? `Laptop cache · ${n(savedCore)} core · ${n(savedRecursion)} recursion`
      : 'Laptop checkpoint count unavailable';
    $('overview-gates').textContent = `Proof gates · ${done} of ${proof.length} cleared`;
    if ($('overview-gates-pill')) $('overview-gates-pill').textContent = `GATES · ${done} / ${proof.length} CLEARED`;

    const archive = ProofEta.arkArchive(cloud?.sample);
    const storageRow = $('overview-storage-row');
    const storage = $('overview-storage');
    if (storageRow) storageRow.hidden = !archive.storage;
    if (archive.storage && storage) {
      const {bucket_bytes, objects, sampled_at_unix, fresh} = archive.storage;
      storage.textContent = `${fresh ? 'Live bucket' : 'Last observation'} · ${n(bucket_bytes / 1e9, 2)} GB · ${n(objects)} objects · ${clockTime(sampled_at_unix)}`;
    }
    const exportRow = $('overview-export-row');
    if (exportRow) exportRow.hidden = !archive.exportStatus;
    if ($('overview-export')) $('overview-export').textContent = archive.exportStatus || '';

    for (const [id, url] of [['overview-checkpoint-release', archive.checkpoint], ['overview-proof-release', archive.proof]]) {
      const el = $(id);
      if (!el) continue;
      el.hidden = !url;
      if (url) el.href = url;
      else el.removeAttribute('href');
    }

    const range = campaign.proofRemaining;
    $('overview-eta').textContent = campaign.checksPassed
      ? 'Proof checks passed'
      : range
      ? planningDuration(range.fast) + (planningDuration(range.fast) !== planningDuration(range.slow) ? ' – ' + planningDuration(range.slow) : '') + ' remaining'
      : !state.polling ? 'Display paused'
      : !live && !observed ? 'Awaiting worker status'
      : !live ? 'Unknown while idle'
      : campaign.target === null || campaign.missing.length ? 'Needs a workload estimate'
      : 'Waiting for fresh proving pace';

    $('overview-plan').hidden = campaign.checksPassed;

    const cloudTotalCore = cloud?.sample?.active
      ? (cloud.sample.core_new || 0) + (cloud.sample.core_replayed || 0)
      : (trend?.progress?.unique_shards ?? 0);
    const showRecovery = cloud?.sample.active && Number.isSafeInteger(savedCore) && savedCore > 0;
    $('overview-recovery').hidden = !showRecovery;
    if (showRecovery) {
      const remaining = Math.max(0, savedCore - cloudTotalCore);
      const tracking = cloud.fresh && cloud.sample.ark_running && trend && Number.isFinite(trend.rate) && trend.rate > 0;
      $('overview-recovery-count').textContent = `${n(cloudTotalCore)} / ${n(savedCore)} saved cores`;
      $('overview-recovery-eta').textContent = !remaining
        ? 'Saved core count reached'
        : tracking
        ? `${planningDuration(60 * remaining / trend.rate)} to match saved count at ${n(trend.rate, 1)}/min`
        : 'Waiting for recent core rate';
      const end = cloud.sample.lease_ends_at_unix;
      $('overview-lease').textContent = !cloud.fresh
        ? 'Pilot heartbeat stale'
        : Number.isFinite(end)
        ? `Lease cutoff in ${formatDuration(Math.max(0, end - Date.now() / 1000))}`
        : `Lease elapsed ${formatDuration(Math.max(0, Date.now() / 1000 - cloud.sample.started_at_unix))}`;
    }

    // Update Stage Bus Node States honestly
    updateStageBusNodes(campaign, cloud, wsl);
  }

  function updateStageBusNodes(campaign, cloud, wsl) {
    const s = cloud?.sample;
    const coreCount = s?.active ? (s.core_new || 0) + (s.core_replayed || 0) : (wsl.progress?.unique_shards ?? 0);
    const recCount = s?.active ? (s.recursion_new || 0) + (s.recursion_replayed || 0) : (wsl.progress?.unique_reduces ?? 0);
    const sp1Row = campaign.rows.find(r => r.id === 'sp1');
    const sdkRow = campaign.rows.find(r => r.id === 'sdk');
    const wrapRow = campaign.rows.find(r => r.id === 'wrap');
    const setupRow = campaign.rows.find(r => r.id === 'setup');
    const claimRow = campaign.rows.find(r => r.id === 'claim');

    if ($('bus-shard-count')) $('bus-shard-count').textContent = `${n(coreCount)} core`;
    if ($('bus-reduce-count')) $('bus-reduce-count').textContent = `${n(recCount)} rec`;
    if ($('bus-m13-label')) {
      $('bus-m13-label').textContent = wrapRow?.done ? 'WRAP ✓' : sdkRow?.done ? 'SDK ✓' : 'SDK + WRAP';
    }
    if ($('bus-m14-label')) {
      $('bus-m14-label').textContent = claimRow?.done ? 'VERIFIED ✓' : setupRow?.done ? 'SETUP ✓' : '785.4M GATES';
    }

    const wire = $('bus-active-wire');
    if (wire) {
      const endX = claimRow?.done ? '612' : wrapRow?.done ? '476' : sp1Row?.done ? '476' : (cloud?.active || arkProcess()) ? '340' : '204';
      wire.setAttribute('x2', endX);
    }
  }

  function renderCloudBudget() {
    const local = state.live?.wsl_prover;
    const localSaved = isCampaignRun(local || {}) ? local?.progress?.unique_shards : null;
    const usingPublished = $('budget-cache').value === 'published';
    const saved = usingPublished ? 3646 : localSaved;
    const value = id => $(id).value === '' ? null : $(id).valueAsNumber;
    const target = value('budget-target');
    const enteredRate = value('budget-rate');
    const cloud = arkCloudSignal();
    const lease = cloud?.sample.active && !cloud.sample.local_verification && Number.isSafeInteger(cloud.sample.vm_id);
    const leaseRate = lease && Number.isFinite(cloud.sample.rate_usd_per_hour) ? cloud.sample.rate_usd_per_hour : null;
    const pace = cloud?.active && cloud.sample.ark_running ? ProofEta.observedBudgetPace(checkpointHistory) : null;
    const rate = enteredRate ?? leaseRate ?? 1.35672043;
    const coresPerMinute = lease ? (pace?.perMinute ?? null) : undefined;
    const estimate = ProofEta.a100Budget({saved, target, rate, credit: value('budget-credit'), coresPerMinute});
    const catchUp = usingPublished && target === null && localSaved > saved
      ? ProofEta.a100Budget({saved, target: localSaved, rate, coresPerMinute}) : null;
    const priceBasis = enteredRate !== null ? 'Entered price' : leaseRate !== null ? 'Lease price' : 'Earlier on-demand quote';
    const paceBasis = lease
      ? (pace ? `${n(coresPerMinute, 1)} fresh cores/min over ${formatDuration(pace.seconds)}`
        : cloud.fresh ? 'Waiting for a recent fresh-core rate' : 'Waiting for a fresh server heartbeat')
      : 'Earlier A100 pilot · 10.38 fresh cores/min';
    $('budget-basis').textContent = `${priceBasis} · $${n(rate, 4)}/h · ${paceBasis}`;
    $('budget-result').textContent = !estimate ? 'Enter the hourly A100 and IP rate.'
      : Number.isSafeInteger(saved) && Number.isSafeInteger(target) && target < saved ? `Use a scenario total at or above the ${n(saved)} saved cores.`
      : estimate.perThousand === null ? 'Core cost and ETA are on hold until the live run records a recent fresh-core rate.'
      : catchUp ? `Matching the laptop’s ${n(localSaved)} saved cores would take about ${planningDuration(catchUp.hours * 3600)} and $${catchUp.cost.toFixed(2)} in core work.`
      : estimate.cost === null ? `Starting cache · ${Number.isSafeInteger(saved) ? n(saved) + ' cores' : 'count unavailable'}. Each additional 1,000 core shards costs about $${estimate.perThousand.toFixed(2)} at this pace.`
      : `${n(target - saved)} new cores · ${planningDuration(estimate.hours * 3600)} · $${estimate.cost.toFixed(2)} for core work under this scenario.`;
    $('budget-runway').textContent = estimate?.runway == null ? ''
      : `Credit covers ${n(estimate.runway, 2)} A100 hours before overhead.`
      + (estimate.runwayCores === null ? '' : ` At this pace, up to ${n(estimate.runwayCores)} new cores.`)
      + (estimate.shortfall > 0 ? ` Core-only shortfall $${estimate.shortfall.toFixed(2)}.` : '');
  }

  function updateCampaign() {
    const observed = state.live?.wsl_prover || {};
    const wsl = isCampaignRun(observed) ? observed : {};
    const processObserved = !!arkProcess();
    const setupRecorded = state.records.some(({title, summary}) =>
      title === 'm14-bounded-setup-20261123.json' &&
      summary?.schema === 'ark-m14-bounded-setup-v1' &&
      summary?.status === 'statement_bound_setup_artifacts_verified'
    );
    const connected = freshRuntime() && wsl.reachable === true;
    const cloud = arkCloudSignal();
    const trend = ProofEta.checkpointTrend(checkpointHistory);
    const archive = ProofEta.arkArchive(cloud?.sample);
    const overnight = cloud?.sample.local_verification
      ? {stage: cloud.sample.stage, fresh: cloud.fresh, published: !!archive.proof} : null;
    const coreSource = cloud?.sample.ark_running && trend && (cloud.fresh || !processObserved)
      ? {active: true, connected: cloud.fresh, startedAt: cloud.sample.started_at_unix, progress: trend.progress} : null;
    const campaignConnected = connected || overnight?.fresh === true;
    const forecastConnected = coreSource?.connected ?? campaignConnected;
    const campaign = ProofEta.arkCampaign(wsl, {
      connected: campaignConnected, paused: !state.polling, processObserved, setupRecorded, coreSource, overnight, plan: campaignPlan,
    });
    const {checksPassed, proofRemaining, proofFinish, deliveryFinish, corePending, core, target, missing} = campaign;

    let headline = 'ETA needs a scenario';
    let basis = '';
    if (checksPassed) {
      headline = 'Verifier checks passed';
      basis = campaign.published
        ? 'The coordinator verified the release and branch push.'
        : 'Coordinator reported all Ark off-chain checks passed. Evidence audit and publication follow.';
    } else if (!forecastConnected) {
      headline = state.polling ? 'Waiting for telemetry' : 'Display paused';
      basis = 'The finish projection requires fresh campaign telemetry.';
    } else if (!coreSource && (campaign.resourceHold || campaign.phase === 'stopped')) {
      headline = campaign.phase === 'stopped' ? 'Coordinator stopped' : 'Waiting for resources';
      basis = 'The finish projection is held until the campaign can advance.';
    } else if (proofFinish) {
      const fast = planningDuration(proofRemaining.fast);
      const slow = planningDuration(proofRemaining.slow);
      headline = `${fast === slow ? fast : `${fast} – ${slow}`} remaining`;
      basis = `Scenario finish ${finishLabel(proofFinish)} using the entered budgets.`;
    } else if (corePending && target === null) {
      basis = 'Prover has not reported a final core count. Set a planning target & stage budgets below to project the full chain.';
    } else if (corePending && core.count > target) {
      basis = 'The run has passed the entered core total. Update the scenario to project the full chain.';
    } else if (missing.length) {
      basis = `Remaining budget needed for ${missing.length === 1 ? missing[0] : `${missing.length} proof stages`}.`;
    } else {
      headline = 'Waiting for live progress';
      basis = 'The projection needs current proving pace or an observed verification phase.';
    }
    $('proof-finish').textContent = headline;
    $('proof-eta-basis').textContent = basis;

    renderCampaignOverview(campaign, cloud, trend, wsl, processObserved);
    renderCloudBudget();

    let outlook = 'Deadline fit is undetermined.';
    if (deliveryFinish) {
      const cutoff = ProofEta.arkDeadline;
      const fit = deliveryFinish.slow <= cutoff ? 'Scenario fits the cutoff'
        : deliveryFinish.fast > cutoff ? 'Scenario exceeds the cutoff' : 'Scenario overlaps the cutoff';
      outlook = `${fit} · package finish ${finishLabel(deliveryFinish)}`;
    } else if (proofFinish && !checksPassed) {
      outlook = proofFinish.fast > ProofEta.arkDeadline
        ? 'Proof scenario exceeds the cutoff before packaging.'
        : 'Add an audit and demo budget to compare delivery against the cutoff.';
    } else if (target !== null && core.fastSeconds !== null && Date.now() / 1000 + core.fastSeconds > ProofEta.arkDeadline) {
      outlook = 'Even the faster core scenario exceeds the cutoff before verification and packaging.';
    } else if (campaign.coreCapacityUntilDeadline !== null) {
      outlook = `At ${n(core.rate, 2)} cores/min, deadline allows ~${n(campaign.coreCapacityUntilDeadline)} saved cores after entered reserves.`;
    }
    $('deadline-outlook').textContent = outlook;

    const summary = wsl.session_summary || {};
    const passReductions = summary.session_recursion_proved + summary.session_recursion_replayed;
    setMarkup('campaign-milestones', campaign.rows.map(row => {
      let detail = row.detail + ' ' + ProofEta.arkStageResources[row.id] + '.';
      if (row.id === 'sp1' && cloud?.active && !row.done) {
        const cTot = (cloud.sample.core_new || 0) + (cloud.sample.core_replayed || 0);
        detail = `${n(cTot)} observed core shards (${n(cloud.sample.core_new)} new) & ${n(cloud.sample.recursion_new)} new recursions on A100 VM #${cloud.sample.vm_id}. ${detail}`;
        return milestoneMarkup({...row, detail, status: 'Pilot in progress'});
      }
      if (row.id === 'sp1' && wsl.progress?.exists && !row.done) {
        detail = `${n(wsl.progress.unique_shards)} saved cores${Number.isSafeInteger(passReductions) && processObserved ? ` · ${n(passReductions)} recursion checkpoints` : ''}. ${detail}`;
        if (freshRuntime() && !processObserved && wsl.status === 'inactive' && wsl.progress.unique_shards > 0) {
          return milestoneMarkup({...row, detail, status: 'Idle · resumable cache'});
        }
      }
      if (row.id === 'setup' && setupRecorded) {
        detail = `785,442,492 ciphertexts generated and verified in 4m 32s. ${detail}`;
      }
      const budget = campaignPlan[row.id];
      const remaining = Number.isFinite(budget) && !row.done ? ` · ${planningDuration(budget * 60)} budgeted` : '';
      return milestoneMarkup({...row, detail, status: row.status + remaining});
    }).join(''));

    const roadmap = ProofEta.cashuRoadmap(campaign, state.records);
    setMarkup('cashu-friday', roadmap.friday.map(milestoneMarkup).join(''));
    setMarkup('cashu-trust', roadmap.trust.map(milestoneMarkup).join(''));
    tickDeadline();
    return campaign;
  }

  function tickDeadline() {
    const remaining = ProofEta.arkDeadline - Date.now() / 1000;
    const text = remaining > 0 ? `${planningDuration(remaining)} left` : 'Submission closed';
    if ($('deadline-clock')) $('deadline-clock').textContent = text;
    if ($('kpi-5-val') && state.selected === 'ark-sp1:campaign') {
      $('kpi-5-val').textContent = remaining > 0 ? planningDuration(remaining) : 'CLOSED';
    }
  }

  function rememberEvents(progress) {
    const seq = Number(progress.seq) || 0;
    state.newEventSeqs = new Set();
    if (state.lastEventSeq !== null && seq > state.lastEventSeq && freshRuntime()) {
      const freshEvs = (progress.recent_events || []).filter(e => e.seq > state.lastEventSeq);
      freshEvs.slice(-6).forEach((ev, idx) => {
        if (!ev.replayed) state.newEventSeqs.add(ev.seq);
        setTimeout(() => emitCheckpointVisual(ev), idx * 140);
      });
    }
    state.lastEventSeq = seq;
  }

  function updateEta() {
    const wsl = state.live?.wsl_prover || {};
    const localConnected = freshRuntime();
    const localActive = localConnected && !!arkProcess();
    const cloud = arkCloudSignal();
    const remote = cloud?.sample.active && cloud.sample.ark_running &&
      Number.isSafeInteger(cloud.sample.vm_id) && (cloud.fresh || !localActive) ? cloud : null;
    const progress = remote ? (ProofEta.checkpointTrend(checkpointHistory)?.progress || {}) : (wsl.progress || {});
    const connected = remote ? remote.fresh : localConnected;
    const active = remote ? remote.active : localActive;
    const source = remote
      ? `hyperstack:${remote.sample.vm_id}:${remote.sample.started_at_unix}`
      : `${wsl.progress_source || progress.path || 'unknown'}:${wsl.prover_binary_sha256 || ''}`;

    if (source !== state.etaSource) {
      state.etaSource = source;
      state.etaClock = null;
      $('eta-target').value = readSetting(`rbzk.eta.${source}`) || '';
      state.etaTarget = $('eta-target').value ? Number($('eta-target').value) : null;
    }

    const target = state.etaTarget;
    const model = ProofEta.estimate(progress, {
      now: Date.now() / 1000, target, active, connected,
      paused: !state.polling, startedAt: remote?.sample.started_at_unix ?? wsl.phase_started_unix,
    });
    model.source = remote ? source : `${source}:${wsl.active_phase_dir || ''}`;
    model.remote = !!remote;
    state.etaClock = ProofEta.clock(state.etaClock, model, performance.now() / 1000);
    state.etaModel = model;
    document.documentElement.dataset.stream = active && connected ? 'live' : 'quiet';

    if ($('core-eta-heading')) {
      $('core-eta-heading').textContent = remote ? 'LIVE CORE FORECAST · HYPERSTACK A100' : 'LIVE CORE FORECAST · LAPTOP';
    }
    $('eta-scope').textContent = model.manual ? 'PLANNED CORE TARGET' : 'NEXT SAVED-CORE MILESTONE';
    $('eta-target-label').textContent = model.target ? `${n(model.count)} → ${n(model.target)} saved cores` : 'Waiting for a progress sample';
    $('eta-rate').textContent = model.status === 'tracking' ? `${n(model.rate, 2)} cores / min` : 'Learning live checkpoint rate';
    $('eta-range').textContent = model.seconds !== null
      ? `Recent-pace range ${formatDuration(model.fastSeconds)} – ${formatDuration(model.slowSeconds)}`
      : 'Waiting for fresh core completions to compute pace.';
    $('eta-run-age').textContent = remote
      ? `Lease elapsed ${formatDuration(Math.max(0, Date.now() / 1000 - remote.sample.started_at_unix))}`
      : typeof wsl.latest_resource?.elapsed_s === 'number'
      ? `Phase elapsed ${formatDuration(wsl.latest_resource.elapsed_s)}`
      : 'Phase elapsed --';
    $('eta-proof-total').textContent = model.manual
      ? 'Core target projection · independent verification follows'
      : 'Core milestone estimate · final proof core total not yet reported';
    $('eta-progress').hidden = !active || !model.manual || model.status !== 'tracking';
    $('eta-fill').style.width = `${model.fraction * 100}%`;
    $('eta-progress').setAttribute('aria-valuenow', String(Math.round(model.fraction * 100)));
    const latest = (progress.recent_events || []).filter(e => !e.replayed).at(-1);
    $('eta-last-proof').textContent = remote?.sample.last_checkpoint_at_unix
      ? `Last server ckpt · ${clockTime(remote.sample.last_checkpoint_at_unix)}`
      : latest
      ? `Last ${latest.kind === 'shard' ? 'core' : 'rec'} · ${clockTime(latest.t)}`
      : 'Awaiting checkpoint';
    tickEta();
  }

  function tickEta() {
    const model = state.etaModel;
    if (!model) return;
    const connected = model.remote ? arkCloudSignal()?.fresh : freshRuntime();
    const ribBadge = $('rib-shard-badge');
    if (!state.polling || !connected) {
      document.documentElement.dataset.stream = 'quiet';
      $('eta-clock').textContent = state.polling ? 'Signal stale' : 'Display paused';
      $('eta-finish').textContent = 'Estimate held';
      return;
    }
    const labels = { paused: 'Paused', stale: 'Stale', inactive: 'Idle', learning: 'Learning pace', target_reached: 'Target reached' };
    if (model.status !== 'tracking') {
      $('eta-clock').textContent = labels[model.status] || 'Waiting';
      $('eta-finish').textContent = model.status === 'target_reached'
        ? 'Planning target reached; proving continues'
        : 'Awaiting fresh core completion delta for live countdown';
      return;
    }
    const seconds = Math.max(0, state.etaClock.deadline - performance.now() / 1000);
    const fmt = seconds > 0 ? `~${formatDuration(seconds)}` : 'Awaiting ckpt';
    $('eta-clock').textContent = fmt;
    $('eta-finish').textContent = seconds > 0
      ? `Estimated milestone ${new Date(Date.now() + seconds * 1000).toLocaleTimeString()}`
      : 'Refreshing on next saved core';
    if (ribBadge) {
      ribBadge.textContent = `⏱ ${fmt}`;
      ribBadge.className = 'eta-badge amber';
    }
  }

  function renderLocalGpu() {
    const gpu = state.live?.gpu;
    const sampledAt = state.live?.sampled_at_unix;
    const now = Date.now();
    const fresh = state.polling && now - state.lastReceived < 15000 && Number.isFinite(sampledAt) && now - sampledAt * 1000 < 15000;
    const available = fresh && gpu?.available === true;
    const measure = (v, suffix) => available && Number.isFinite(v) ? `${n(v)}${suffix}` : 'Unavailable';
    const vram = v => available && Number.isFinite(v) ? gib(v * 2**20) : 'Unavailable';
    $('local-gpu-status').textContent = !state.polling ? 'DISPLAY PAUSED' : !state.live ? 'CONNECTING' : !fresh ? 'STALE / UNKNOWN' : available ? 'OBSERVED' : 'UNAVAILABLE';
    $('local-gpu-name').textContent = available && gpu.name ? gpu.name : state.live ? 'GPU measurement unavailable' : 'Waiting for telemetry';
    $('local-gpu-metrics').innerHTML = kv('GPU utilization', measure(gpu?.util_gpu_pct, '%'))
      + kv('VRAM in use', vram(gpu?.vram_used_mib))
      + kv('VRAM capacity', vram(gpu?.vram_total_mib))
      + kv('Temperature', measure(gpu?.temp_c, ' °C'));
    $('local-gpu-sample').textContent = fresh ? `NVIDIA telemetry · ${time(sampledAt)}` : 'Source · NVIDIA telemetry';
  }

  function renderHyperstack(pilot) {
    $('hyperstack-benchmark').hidden = !pilot;
    $('cashu-benchmark').hidden = !pilot;
    if (!pilot) return;
    const {sample, status, hardware} = pilot;
    $('hyperstack-stage').textContent = status;
    $('hyperstack-hardware').textContent = `${hardware} · CPU proving`;
    const elapsed = sample.sampled_at_unix - sample.started_at_unix;
    $('hyperstack-metrics').innerHTML = kv('VM', sample.vm_id)
      + kv('Pilot elapsed', formatDuration(elapsed))
      + kv('CPU threads', sample.threads ? `${sample.threads} prover / ${sample.logical_cpus} host` : cloudMeasure(sample.logical_cpus, ' host'))
      + kv('Host RAM', Number.isFinite(sample.host_ram_used_gib) && Number.isFinite(sample.host_ram_gib) ? `${n(sample.host_ram_used_gib, 1)} / ${n(sample.host_ram_gib, 1)} GiB` : 'Unavailable')
      + kv('VM & IP / hr', Number.isFinite(sample.rate_usd_per_hour) ? `$${sample.rate_usd_per_hour.toFixed(2)}` : 'Unavailable')
      + (Number.isFinite(sample.prove_seconds) ? kv('Issuance proving time', formatDuration(sample.prove_seconds)) + kv('Peak prover RAM', cloudMeasure(sample.peak_prove_ram_gib, ' GiB')) : '');
    $('hyperstack-sample').textContent = `Benchmark sample · ${time(sample.sampled_at_unix)}`;
    $('cashu-benchmark').textContent = sample.stage === 'verified'
      ? `Fresh regtest issuance verified on Hyperstack (${formatDuration(sample.prove_seconds)}). Funded payout checked with mint offline; fresh redemption proof pending.`
      : `Hyperstack issuance benchmark · ${status}. Overnight forecast pending verified proving time.`;
  }

  function renderRunpodCloud() {
    const signal = runpodSignal();
    const cloud = signal.cloud;
    const pod = cloud?.pod || {};
    const metrics = cloud?.metrics || {};
    const labels = {
      credentials_required: 'CONNECT AN API KEY', connecting: 'CONNECTING', unauthorized: 'KEY REJECTED',
      unavailable: 'PROVIDER UNAVAILABLE', multiple_pods: 'SELECT A POD', no_running_pod: 'NO RUNNING GPU POD',
      pod_not_running: 'SELECTED POD IS INACTIVE',
    };
    let status = 'CONNECTING', name = 'Cloud telemetry';
    if (!state.polling) status = 'DISPLAY PAUSED';
    else if (!cloud) status = 'WAITING FOR TELEMETRY';
    else if (!signal.running) status = labels[cloud.status] || (!signal.authenticated ? 'NOT AUTHENTICATED' : 'NO RUNNING GPU POD');
    else if (!signal.authenticated) status = 'NOT AUTHENTICATED';
    else if (!signal.fresh) status = 'STALE / UNKNOWN';
    else { status = signal.gpuName ? 'RUNNING / OBSERVED' : 'GPU UNIDENTIFIED'; name = signal.gpuName || 'GPU name unavailable'; }

    $('runpod-cloud-heading').textContent = `${signal.provider.toUpperCase()} · READ ONLY`;
    $('runpod-cloud-status').textContent = status;
    $('runpod-cloud-name').textContent = name;
    $('runpod-cloud-metrics').hidden = !signal.active;
    $('runpod-cloud-metrics').innerHTML = signal.active
      ? kv('GPU utilization', cloudMeasure(metrics.gpu_util_percent, '%'))
        + kv('GPU memory', cloudMeasure(metrics.gpu_memory_percent, '%'))
        + kv('CPU utilization', cloudMeasure(metrics.cpu_util_percent, '%'))
        + kv('Memory utilization', cloudMeasure(metrics.mem_util_percent, '%'))
      : '';
    $('runpod-cloud-sample').textContent = signal.active
      ? `${pod.name || pod.id || 'Remote GPU'} · ${time(cloud.sampled_at_unix)}`
      : cloud?.status === 'credentials_required'
      ? (cloud.provider === 'Prime Intellect' ? 'Sign in with the Prime CLI to connect telemetry.' : 'Configure a Runpod read-only API key to connect telemetry.')
      : cloud?.status === 'multiple_pods' ? 'Select a specific running GPU instance in telemetry configuration.'
      : 'Waiting for a fresh cloud GPU sample.';

    const pilot = hyperstackSignal();
    const arkCloud = arkCloudSignal();
    const hsLive = hyperstackLiveSignal();
    $('compute-source-state').textContent = arkCloud?.active
      ? `ACTIVE DISPLAY SOURCE · HYPERSTACK A100 SPOT VM #${arkCloud.sample.vm_id}`
      : hsLive.activeInstances.length
      ? `ACTIVE DISPLAY SOURCE · HYPERSTACK · ${hsLive.activeInstances[0].name.toUpperCase()}`
      : pilot?.active ? 'ACTIVE DISPLAY SOURCE · HYPERSTACK · CPU PROVING'
      : signal.active ? `ACTIVE DISPLAY SOURCE · ${signal.provider.toUpperCase()} · ${signal.gpuName || 'GPU'}`
      : 'ACTIVE DISPLAY SOURCE · LOCAL GPU';
    renderHyperstack(pilot);
    renderHyperstackLive(hsLive);
  }

  function renderHyperstackLive(hs) {
    const statusEl = $('hyperstack-live-status');
    const summaryEl = $('hyperstack-live-summary');
    const metricsEl = $('hyperstack-live-metrics');
    const listEl = $('hyperstack-live-list');
    const sampleEl = $('hyperstack-live-sample');
    if (!statusEl || !summaryEl) return;

    const statusLabels = {
      connecting: 'CONNECTING',
      credentials_required: 'NO API KEY FOUND',
      unauthorized: 'KEY REJECTED',
      unavailable: 'API UNREACHABLE',
      active: `${hs.activeInstances.length} ACTIVE VM${hs.activeInstances.length === 1 ? '' : 'S'}`,
      stopped: `${hs.instances.length} STOPPED VM${hs.instances.length === 1 ? '' : 'S'}`,
      no_running_vm: 'CONNECTED · 0 ACTIVE VMS',
    };
    statusEl.textContent = !state.polling ? 'PAUSED' : (statusLabels[hs.status] || String(hs.status || 'UNKNOWN').toUpperCase());
    summaryEl.textContent = hs.activeInstances.length
      ? hs.activeInstances.map(v => v.name).join(' · ')
      : hs.authenticated
      ? '0 active VMs on Hyperstack API'
      : 'Hyperstack API key not configured';

    metricsEl.innerHTML = kv('Active VMs', hs.authenticated ? n(hs.activeInstances.length) : 'Unavailable')
      + kv('Total VMs', hs.authenticated ? n(hs.instances.length) : 'Unavailable')
      + kv('S3 Buckets', hs.authenticated ? n(hs.buckets.length) : 'Unavailable')
      + kv('Bucket Storage', hs.buckets.length ? `${n(hs.totalBucketBytes / 1e9, 2)} GB (${n(hs.totalBucketObjects)} objs)` : '0 GB');

    const vmMarkup = hs.instances.map(vm => {
      const m = vm.metrics || {};
      const hw = [vm.gpu ? `${vm.gpu_count || 1}× ${vm.gpu}` : null, vm.cpu ? `${vm.cpu} vCPU` : null, vm.ram_gib ? `${n(vm.ram_gib, 0)} GiB RAM` : null, vm.disk_gb ? `${vm.disk_gb} GB disk` : null].filter(Boolean).join(' · ');
      const liveM = [
        Number.isFinite(m.cpu_percent) ? `CPU ${n(m.cpu_percent, 1)}%` : null,
        Number.isFinite(m.memory_used_gib) ? `RAM ${n(m.memory_used_gib, 1)} GiB` : null,
      ].filter(Boolean).join(' · ');
      return `<div class="observed-job" style="padding:8px 0">
        <div class="panel-head" style="margin-bottom:4px">
          <strong class="mono">${esc(vm.name)} <span style="color:var(--ink-dim)">#${esc(vm.id)}</span></strong>
          <span class="status-pill ${vm.active ? 'live' : ''}">${esc(vm.status)}</span>
        </div>
        <p class="panel-sub">${esc(vm.flavor || '--')} · ${esc(vm.region || '--')} · ${esc(hw || '--')}</p>
        ${liveM ? `<p class="panel-sub" style="color:var(--ink)">Live metrics: ${esc(liveM)}</p>` : ''}
      </div>`;
    }).join('');

    const bucketMarkup = hs.buckets.map(b =>
      `<div class="panel-sub mono" style="padding:4px 0;border-top:1px solid var(--line)">BUCKET: <strong>${esc(b.name)}</strong> · ${esc(b.region || '--')} · ${n((b.size_bytes || 0) / 1e9, 2)} GB · ${n(b.num_objects)} objs</div>`
    ).join('');

    listEl.innerHTML = (vmMarkup || (hs.authenticated ? '<p class="panel-sub">No virtual machines currently returned by Hyperstack <code>/v1/core/virtual-machines</code>.</p>' : '')) + bucketMarkup;
    sampleEl.textContent = hs.sampledAt ? `Hyperstack API · polled ${clockTime(hs.sampledAt)}` : 'Read-only API · Virtual Machines & Object Storage';
  }

  function renderArkCloud(arkCloud) {
    if (!arkCloud || !Number.isSafeInteger(arkCloud.sample.vm_id) || (!arkCloud.sample.active && state.live?.wsl_prover?.phase_running)) return;
    const {sample, phase} = arkCloud;
    const counts = [
      ['Core shards written (A100)', sample.core_new],
      ['Recursion written (A100)', sample.recursion_new],
      ['Core replayed (A100)', sample.core_replayed],
      ['Recursion replayed (A100)', sample.recursion_replayed],
    ].map(([label, val]) => kv(label, Number.isSafeInteger(val) ? n(val) : 'Awaiting sample')).join('');
    $('shard-heading').textContent = sample.local_verification ? 'ARK · LOCAL VERIFICATION' : 'ARK SP1 · HYPERSTACK A100 SHARDING';
    $('ark-state').textContent = phase.toUpperCase();
    $('shard-metrics').innerHTML = counts
      + kv('A100 VRAM Used', Number.isFinite(sample.vram_used_mib) ? `${n(sample.vram_used_mib)} MiB` : 'Unavailable')
      + kv('Server Heartbeat', clockTime(sample.sampled_at_unix))
      + kv('Last Checkpoint', sample.last_checkpoint_at_unix ? time(sample.last_checkpoint_at_unix) : 'Awaiting checkpoint')
      + kv('Laptop Cache (Disk)', `${n(state.live?.wsl_prover?.progress?.unique_shards)} core · ${n(state.live?.wsl_prover?.progress?.unique_reduces)} rec`);
  }

  function initCompute() {
    const targets = $('compute-target');
    const cloud = $('compute-cloud');
    const providers = $('compute-providers');
    const detail = $('compute-provider-detail');
    providers.innerHTML = computeProviders.map(({id, name, icon, rate}) => `
      <label class="compute-option">
        <input type="radio" name="compute-provider" value="${esc(id)}" aria-controls="compute-provider-detail">
        <span class="compute-option-label">
          <svg class="compute-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${esc(icon)}"/></svg>
          <span class="compute-option-text"><strong>${esc(name)}</strong><small>${esc(rate)}</small></span>
        </span>
      </label>`).join('');

    function showCloud() { cloud.hidden = targets.querySelector('input:checked').value !== 'cloud'; }
    function showProvider() {
      const selected = providers.querySelector('input:checked')?.value;
      const provider = computeProviders.find(({id}) => id === selected);
      detail.hidden = !provider;
      if (!provider) return;
      detail.innerHTML = `<dl class="compute-setup">${provider.setup.map(([label, val]) =>
        `<div><dt>${esc(label)}</dt><dd>${esc(val)}</dd></div>`).join('')}</dl>
        ${provider.note ? `<p class="panel-sub">${esc(provider.note)}</p>` : ''}
        <p class="panel-sub">Pilot kit · <code>prover-ui/pilots/ark-h100/${esc(provider.id)}.md</code></p>
        <div class="compute-provider-links">
          <a href="${esc(provider.console)}" target="_blank" rel="noopener">${esc(provider.name)} console ↗</a>
          <a href="${esc(provider.pricing)}" target="_blank" rel="noopener">Public pricing ↗</a>
        </div>`;
    }
    const target = readSetting(computeTargetKey) === 'cloud' ? 'cloud' : 'local';
    for (const input of targets.querySelectorAll('input')) input.checked = input.value === target;
    const provider = readSetting(computeProviderKey);
    for (const input of providers.querySelectorAll('input')) input.checked = input.value === provider;
    targets.onchange = ({target: t}) => { saveSetting(computeTargetKey, t.value); showCloud(); };
    providers.onchange = ({target: t}) => { saveSetting(computeProviderKey, t.value); showProvider(); };
    showCloud();
    showProvider();
  }

  function jobs() {
    const rt = state.live?.runtime || {};
    const wsl = state.live?.wsl_prover || {};
    const observed = [...(rt.jobs || [])];
    const measured = freshRuntime() && typeof wsl.last_resource_age_s === 'number' && wsl.last_resource_age_s <= 15 && wsl.phase_running;
    const resources = measured ? (wsl.latest_resource || {}) : {};
    const proc = arkProcess();
    const arkCloud = arkCloudSignal();
    if (proc || isCampaignRun(wsl) || arkCloud?.sample?.active) {
      const ark = ProofEta.arkCampaign(wsl);
      const phase = arkCloud?.active ? arkCloud.phase : (ark.rows.find(row => row.steps.includes(ark.phase))?.label || 'Ark proof and evidence delivery');
      const status = ark.checksPassed ? 'checks passed' : (proc || (arkCloud?.active && arkCloud.sample.ark_running)) ? 'running'
        : ark.resourceHold ? 'resource wait' : ark.phase === 'stopped' ? 'stopped' : 'coordinator observed';
      observed.push({
        id: 'ark-sp1:campaign',
        title: 'Ark ASP · SP1 → BitVM3',
        network: 'ARK ASP POLICY CAMPAIGN',
        backend: arkCloud?.active ? 'SP1 / A100 CUDA' : 'SP1 / CUDA',
        running: !!(proc || (arkCloud?.active && arkCloud.sample.ark_running)),
        status,
        process: proc,
        phase,
        checksPassed: ark.checksPassed,
        ram_bytes: typeof resources.cgroup_ram_mib === 'number' ? resources.cgroup_ram_mib * 2**20 : null,
        swap_bytes: typeof resources.cgroup_swap_mib === 'number' ? resources.cgroup_swap_mib * 2**20 : null,
        unit: wsl.active_phase_dir || (arkCloud?.active ? `Hyperstack A100 VM #${arkCloud.sample.vm_id}` : 'Observed native process'),
        log_tail: String(wsl.phase_log_tail || '').replace(/\x1b\[[0-9;]*m/g, '').split('\n').slice(-6),
        audit: {present: false, valid: false},
      });
    }
    const hsLive = hyperstackLiveSignal();
    for (const vm of hsLive.instances) {
      if (arkCloud?.active && arkCloud.sample.vm_id === vm.id) continue;
      const hw = [vm.gpu ? `${vm.gpu_count || 1}× ${vm.gpu}` : `${vm.cpu || '?'} vCPU`, vm.flavor].filter(Boolean).join(' · ');
      const m = vm.metrics || {};
      const mText = [
        Number.isFinite(m.cpu_percent) ? `CPU ${n(m.cpu_percent, 1)}%` : null,
        Number.isFinite(m.memory_used_gib) ? `RAM ${n(m.memory_used_gib, 1)}/${n(vm.ram_gib, 0)} GiB` : (vm.ram_gib ? `${n(vm.ram_gib, 0)} GiB RAM` : null),
        vm.region || null,
      ].filter(Boolean).join(' · ');
      observed.push({
        id: `hyperstack-vm:${vm.id}`,
        title: vm.name,
        network: `HYPERSTACK · ${String(vm.region || 'CLOUD').toUpperCase()}`,
        backend: hw || 'Hyperstack VM',
        running: !!vm.active,
        status: vm.active ? 'running' : String(vm.status || 'stopped').toLowerCase(),
        process: null,
        phase: `${vm.status || 'ACTIVE'} · ${mText || vm.flavor || 'Cloud node'}`,
        unit: `Hyperstack VM #${vm.id} (${vm.environment || vm.region || 'cloud'})`,
        log_tail: [
          `VM ID: ${vm.id} · Name: ${vm.name}`,
          `Status: ${vm.status} (power=${vm.power_state || '--'}, state=${vm.vm_state || '--'})`,
          `Flavor: ${vm.flavor || '--'} · Spot: ${vm.spot ? 'yes' : 'no'} · Image: ${vm.image || '--'}`,
          `Hardware: ${vm.gpu ? `${vm.gpu_count || 1}× ${vm.gpu}, ` : ''}${vm.cpu || '--'} vCPU, ${vm.ram_gib || '--'} GiB RAM, ${vm.disk_gb || '--'} GB disk`,
          `Created: ${vm.created_at || '--'} · Region: ${vm.region || '--'}`,
        ],
        audit: {present: false, valid: false},
        hyperstackVm: vm,
      });
    }
    return observed.map(j => freshRuntime() || (j.id === 'ark-sp1:campaign' && arkCloud?.fresh) || (j.hyperstackVm && hsLive.fresh)
      ? j : {...j, running: false, status: state.polling ? 'stale / unknown' : 'display paused'});
  }

  function select(id) {
    state.selected = id;
    state.userSelected = true;
    render();
  }

  function drawHistory() {
    const canvas = $('observations');
    if (!canvas || state.tab !== 'live') return;
    const ctx = canvas.getContext('2d');
    const width = canvas.clientWidth || 560;
    canvas.width = width * devicePixelRatio;
    canvas.height = 150 * devicePixelRatio;
    ctx.scale(devicePixelRatio, devicePixelRatio);
    ctx.clearRect(0, 0, width, 150);
    const isLight = document.documentElement.getAttribute('data-theme') === 'grove';
    ctx.strokeStyle = isLight ? 'rgba(7,7,9,0.12)' : 'rgba(255,255,255,0.10)';
    for (let y = 15; y < 150; y += 30) {
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(width, y); ctx.stroke();
    }
    const rows = state.history;
    const first = rows[0]?.t;
    const last = rows.at(-1)?.t;
    [['cpu', isLight ? '#070709' : '#f5f5f5'], ['ram', '#9a9da6'], ['gpu', '#e60e1b']].forEach(([key, color]) => {
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      let moving = false;
      rows.forEach(row => {
        if (typeof row[key] !== 'number') { moving = false; return; }
        const x = (row.t - first) / Math.max(last - first, 1) * (width - 8) + 4;
        const y = 145 - Math.min(100, Math.max(0, row[key])) * 1.3;
        if (moving) ctx.lineTo(x, y); else ctx.moveTo(x, y);
        moving = true;
      });
      ctx.stroke();
    });
    $('history-caption').textContent = `${rows.length} samples · white: local proof CPU % · gray: host RAM % · crimson: local GPU compute %`;
  }

  function rememberSample(live) {
    const rt = live.runtime || {};
    const t = rt.sampled_at_unix;
    if (!rt.fresh || typeof t !== 'number' || state.history.at(-1)?.t === t) return;
    let cpu = 0, measured = false;
    const observed = new Map(), advances = new Set();
    for (const job of rt.jobs || []) {
      if (!job.running || !job.process || typeof job.cpu_seconds !== 'number') continue;
      const key = `${job.process.pid}:${job.process.start_ticks}`;
      const prev = state.previous.get(key);
      if (prev && t > prev.t && job.cpu_seconds >= prev.cpu) {
        cpu += (job.cpu_seconds - prev.cpu) / (t - prev.t) * 50;
        measured = true;
        if (Math.floor(job.cpu_seconds) > Math.floor(prev.cpu)) advances.add(job.id);
      }
      observed.set(key, {t, cpu: job.cpu_seconds});
    }
    state.previous = observed;
    state.workerAdvances = advances;
    state.history.push({t, cpu: measured ? cpu : null, ram: live.host_memory?.load_percent, gpu: live.gpu?.util_gpu_pct});
    if (state.history.length > 180) state.history.shift();
  }

  function renderCheckpointIncrements(trend) {
    const lanes = [['core', 'core/min'], ['recursion', 'rec/min']];
    return `<div class="checkpoint-increments" aria-label="New checkpoints in last minute">${lanes.map(([kind, label]) => {
      const peak = Math.max(1, ...trend.recent.map(p => p[kind]));
      const bars = trend.recent.map(p => `<i style="--weight:${Math.max(10, 100 * p[kind] / peak)}%"></i>`).join('');
      return `<div class="checkpoint-lane"><strong>+${n(trend.lastMinute[kind])}</strong> ${label}<span class="checkpoint-spark ${kind}" aria-hidden="true">${bars}</span></div>`;
    }).join('')}</div>`;
  }

  function renderOngoingJobs(local, ark, shinigami) {
    const localFresh = freshRuntime();
    const localOnly = local.filter(j => !j.hyperstackVm && !(j.id === 'ark-sp1:campaign' && ark?.sample?.active && !j.process));
    const rows = ProofEta.ongoingJobs({
      local: localOnly, ark, shinigami, localFresh, localSample: state.live?.runtime?.sampled_at_unix, paused: !state.polling,
    });
    const hsLive = hyperstackLiveSignal();
    for (const vm of hsLive.instances) {
      if (ark?.active && ark.sample.vm_id === vm.id) continue;
      if (!vm.active) continue;
      const m = vm.metrics || {};
      const metrics = [];
      if (Number.isFinite(m.cpu_percent)) metrics.push(['CPU %', Math.round(m.cpu_percent)]);
      if (Number.isFinite(m.memory_used_gib)) metrics.push(['RAM GiB', Math.round(m.memory_used_gib)]);
      if (Number.isSafeInteger(vm.cpu)) metrics.push(['vCPUs', vm.cpu]);
      if (Number.isFinite(vm.ram_gib)) metrics.push(['Total GiB', Math.round(vm.ram_gib)]);
      rows.unshift({
        id: `hyperstack-vm:${vm.id}`,
        title: vm.name,
        where: `Hyperstack · ${vm.flavor || (vm.gpu || 'VM')} · ${vm.region || 'Cloud'}`,
        phase: `VM #${vm.id} · ${vm.status}${vm.spot ? ' (Spot)' : ''} · ${vm.image || 'Linux'}`,
        status: !state.polling ? 'Paused' : !hsLive.fresh ? 'Stale' : String(vm.status).toUpperCase() === 'ACTIVE' ? 'Running' : 'Preparing',
        heardAt: hsLive.sampledAt,
        metrics,
      });
    }
    const running = rows.filter(j => j.status === 'Running').length;
    const waiting = rows.filter(j => ['Preparing', 'Waiting for resources', 'Collecting results'].includes(j.status)).length;
    const stale = rows.filter(j => j.status === 'Stale').length;
    const count = [running ? `${running} RUNNING` : '', waiting ? `${waiting} PENDING` : '', stale ? `${stale} STALE` : ''].filter(Boolean).join(' · ');
    $('ongoing-summary').textContent = !state.polling ? 'PAUSED' : count || (localFresh ? '0 RUNNING' : 'WAITING');

    const empty = !state.polling ? 'Resume telemetry to refresh worker status.'
      : localFresh ? 'No active prover process observed.' : 'Waiting for live worker report.';
    setMarkup('ongoing-jobs', rows.map(job => {
      const heard = Number.isFinite(job.heardAt) ? new Date(job.heardAt * 1000) : null;
      const validHeard = heard && !Number.isNaN(heard.valueOf());
      const metrics = (job.metrics || []).filter(([, val]) => Number.isSafeInteger(val));
      const recent = job.id === 'cloud-ark' && ark?.fresh ? ProofEta.checkpointTrend(checkpointHistory) : null;
      const increments = recent?.recent.length ? renderCheckpointIncrements(recent) : '';
      return `<article class="ongoing-job">
        <div class="ongoing-name"><h3>${esc(job.title)}</h3><p>${esc(job.where)}</p></div>
        <div class="ongoing-monitor">
          <span class="status-pill ${job.status === 'Running' ? 'live' : ''}">${esc(job.status)}</span>
          ${validHeard ? `<time datetime="${heard.toISOString()}" title="${esc(heard.toLocaleString())}">Rpt ${esc(heard.toLocaleTimeString())}</time>` : ''}
        </div>
        <div class="ongoing-work">
          ${job.phase ? `<p>${esc(job.phase)}</p>` : ''}
          ${Number.isFinite(job.progressPct) ? `<div class="meter-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(job.progressPct)}" style="margin:6px 0 8px"><div class="meter-fill cyan" style="width:${Math.max(2, job.progressPct).toFixed(1)}%"></div></div>` : ''}
          ${metrics.length ? `<dl>${metrics.map(([label, val]) => `<div><dt>${esc(label)}</dt><dd${label === 'CPU seconds' && job.status === 'Running' && state.workerAdvances.has(job.id) ? ' class="worker-increment"' : ''}>${label === 'Progress %' ? `${n(val)}%` : n(val)}</dd></div>`).join('')}</dl>` : ''}
          ${increments}
        </div>
      </article>`;
    }).join('') || `<p class="panel-sub">${esc(empty)}</p>`);
    return {rows, running, waiting};
  }

  function updateMosaicData(arkCloud, progress) {
    const localRunning = freshRuntime() && !!arkProcess();
    const cloudLive = !!(arkCloud?.fresh && arkCloud.sample.ark_running);
    const live = cloudLive || localRunning;

    // Combine real historical laptop mosaic_tail (exact digests & latencies) + real live A100 checkpoint deltas
    const localTiles = (progress.mosaic_tail || []).slice(-319).map(tile => ({
      kind: tile.t === 1 ? 'recursion' : 'core',
      replayed: tile.r === 1,
      key: tile.k,
      seconds: tile.s,
      source: 'Laptop progress.jsonl',
    }));
    const cloudDeltas = ProofEta.checkpointMosaic(checkpointHistory).map(tile => ({
      ...tile,
      key: tile.kind === 'recursion' ? 'a100-rec' : 'a100-core',
      source: `Hyperstack A100 VM #${arkCloud?.sample?.vm_id || ''}`,
    }));

    state.activeMosaicTiles = [...localTiles, ...cloudDeltas].slice(-319);
    state.activeMosaicLive = live;
    state.activeMosaicSource = cloudLive ? `Hyperstack A100 VM #${arkCloud.sample.vm_id}` : 'Laptop progress.jsonl';

    const countEl = $('mosaic-total-count');
    if (countEl) {
      if (arkCloud?.active) {
        const s = arkCloud.sample;
        const cTot = (s.core_new || 0) + (s.core_replayed || 0);
        const rTot = (s.recursion_new || 0) + (s.recursion_replayed || 0);
        countEl.textContent = `A100: ${n(cTot)} core (${n(s.core_new)} new) · ${n(rTot)} rec (${n(s.recursion_new)} new) · ${n(state.activeMosaicTiles.length)} tiles`;
      } else {
        countEl.textContent = `${n(progress.unique_shards)} cached core · ${n(progress.unique_reduces)} rec · ${n(state.activeMosaicTiles.length)} tiles`;
      }
    }
  }

  function updateCockpitPanel(arkCloud, progress, campaign) {
    const localRunning = freshRuntime() && !!arkProcess();
    const wsl = state.live?.wsl_prover || {};
    const savedCore = progress.unique_shards ?? 0;

    if ($('cockpit-live-dot')) {
      $('cockpit-live-dot').classList.toggle('live', state.polling && (arkCloud?.active || localRunning || freshRuntime()));
    }

    if (arkCloud?.active) {
      const s = arkCloud.sample;
      const cTot = (s.core_new || 0) + (s.core_replayed || 0);
      const rTot = (s.recursion_new || 0) + (s.recursion_replayed || 0);
      if ($('cockpit-stage-tag')) {
        $('cockpit-stage-tag').textContent = `A100 VM #${s.vm_id} · STAGE: ${String(s.stage || 'LIVE').toUpperCase()}`;
      }
      if ($('cockpit-headline')) {
        $('cockpit-headline').textContent = String(arkCloud.phase || 'A100 PROVER RUNNING').toUpperCase();
      }
      if ($('cockpit-detail')) {
        $('cockpit-detail').textContent = `Hyperstack ${s.spot ? 'A100 Spot' : 'A100 On-Demand'} · ${n(s.vram_used_mib)} MiB VRAM · ${n(s.core_new)} new core + ${n(s.recursion_new)} new rec · Last ckpt ${fmtAgo(s.last_checkpoint_at_unix)}`;
      }
      const targetCore = campaignPlan.core || savedCore || 1;
      const pct = Math.min(100, (cTot / Math.max(1, targetCore)) * 100);
      if ($('cockpit-bar1-left')) {
        $('cockpit-bar1-left').textContent = campaignPlan.core
          ? `Scenario Core Target (${n(cTot)} / ${n(campaignPlan.core)})`
          : 'Saved Core Checkpoint Recovery (A100 vs Laptop Cache)';
      }
      if ($('cockpit-bar1-right')) {
        $('cockpit-bar1-right').textContent = campaignPlan.core
          ? `${n(cTot)} / ${n(campaignPlan.core)} cores (${pct.toFixed(1)}%)`
          : `${n(cTot)} / ${n(savedCore)} saved cores (${cTot >= savedCore ? 'REACHED' : pct.toFixed(1) + '%'})`;
      }
      if ($('cockpit-bar1-fill')) $('cockpit-bar1-fill').style.width = `${Math.max(2, pct).toFixed(1)}%`;

      if ($('cockpit-bar2-left')) $('cockpit-bar2-left').textContent = 'A100 Spot Lease Runway (UTC Cutoff)';
      // bar2 right & fill updated at 60fps in updateLiveCountdowns()
    } else if (localRunning) {
      if ($('cockpit-stage-tag')) $('cockpit-stage-tag').textContent = `LOCAL CUDA · PID ${arkProcess().pid}`;
      if ($('cockpit-headline')) $('cockpit-headline').textContent = 'LOCAL RTX 5080 PROVER ACTIVE';
      if ($('cockpit-detail')) $('cockpit-detail').textContent = `${n(savedCore)} unique cores · ${n(progress.unique_reduces)} reductions · ${wsl.prover_backend || 'SP1 CUDA'}`;
      if ($('cockpit-bar1-left')) $('cockpit-bar1-left').textContent = 'Local Checkpoint Cache';
      if ($('cockpit-bar1-right')) $('cockpit-bar1-right').textContent = `${n(savedCore)} core · ${n(progress.unique_reduces)} rec`;
      if ($('cockpit-bar1-fill')) $('cockpit-bar1-fill').style.width = '100%';
    } else if (hyperstackLiveSignal().activeInstances.length > 0) {
      const hs = hyperstackLiveSignal();
      const vm = hs.activeInstances.find(v => `hyperstack-vm:${v.id}` === state.selected) || hs.activeInstances[0];
      const m = vm.metrics || {};
      const created = parseUtcSeconds(vm.created_at);
      const upStr = created !== null ? formatDuration(Math.max(0, Date.now() / 1000 - created)) : '--:--:--';
      if ($('cockpit-stage-tag')) $('cockpit-stage-tag').textContent = `HYPERSTACK VM #${vm.id} · ${String(vm.status || 'ACTIVE').toUpperCase()}`;
      if ($('cockpit-headline')) $('cockpit-headline').textContent = `${String(vm.name).toUpperCase()} · ${vm.flavor || 'CLOUD NODE'}`;
      if ($('cockpit-detail')) $('cockpit-detail').textContent = `${vm.region || 'Hyperstack'} · ${vm.gpu ? `${vm.gpu_count || 1}× ${vm.gpu} · ` : ''}${vm.cpu || '--'} vCPU · ${n(vm.ram_gib, 0)} GiB RAM · ${vm.disk_gb || '--'} GB disk · Uptime ${upStr}`;
      if ($('cockpit-bar1-left')) $('cockpit-bar1-left').textContent = 'Hyperstack VM CPU Utilization (Live /metrics)';
      if ($('cockpit-bar1-right')) $('cockpit-bar1-right').textContent = Number.isFinite(m.cpu_percent) ? `${n(m.cpu_percent, 1)}% CPU` : 'Awaiting metrics sample';
      if ($('cockpit-bar1-fill')) $('cockpit-bar1-fill').style.width = Number.isFinite(m.cpu_percent) ? `${Math.min(100, Math.max(2, m.cpu_percent)).toFixed(1)}%` : '20%';
      if ($('cockpit-bar2-left')) $('cockpit-bar2-left').textContent = 'Hyperstack VM Memory Usage';
      const ramPct = Number.isFinite(m.memory_used_gib) && Number.isFinite(vm.ram_gib) && vm.ram_gib > 0 ? Math.min(100, (m.memory_used_gib / vm.ram_gib) * 100) : 0;
      if ($('cockpit-bar2-right')) $('cockpit-bar2-right').textContent = Number.isFinite(m.memory_used_gib) ? `${n(m.memory_used_gib, 2)} / ${n(vm.ram_gib, 0)} GiB (${ramPct.toFixed(0)}%)` : `${n(vm.ram_gib, 0)} GiB allocated`;
      if ($('cockpit-bar2-fill')) $('cockpit-bar2-fill').style.width = `${Math.max(2, ramPct).toFixed(1)}%`;
    } else if (freshRuntime() && (state.live?.runtime?.jobs || []).some(j => j.running && (j.kind === 'mnr05' || j.kind === 'mnr04'))) {
      const nvJob = (state.live?.runtime?.jobs || []).find(j => j.running && (j.kind === 'mnr05' || j.kind === 'mnr04'));
      const pct = Number.isFinite(nvJob.progress_pct) ? Math.min(100, Math.max(0, nvJob.progress_pct)) : null;
      const ramMiB = Number.isFinite(nvJob.ram_bytes) ? Math.round(nvJob.ram_bytes / 2**20) : null;
      if ($('cockpit-stage-tag')) $('cockpit-stage-tag').textContent = `LOCAL NOVA · PID ${nvJob.process?.pid || '--'}${pct !== null ? ` · ${pct.toFixed(1)}%` : ''}`;
      if ($('cockpit-headline')) $('cockpit-headline').textContent = String(nvJob.title || 'LOCAL NOVA PROVER ACTIVE').toUpperCase();
      if ($('cockpit-detail')) $('cockpit-detail').textContent = `${nvJob.phase || 'Folding R1CS steps'} · ${ramMiB !== null ? `${n(ramMiB)} MiB RSS · ` : ''}${nvJob.backend || 'Nova / CPU'}`;
      if ($('cockpit-bar1-left')) $('cockpit-bar1-left').textContent = 'Nova Recursive Folding & Spartan/IPA Progress';
      if ($('cockpit-bar1-right')) $('cockpit-bar1-right').textContent = pct !== null
        ? `${Number.isSafeInteger(nvJob.completed_steps) && Number.isSafeInteger(nvJob.total_steps) ? `${nvJob.completed_steps} / ${nvJob.total_steps} stages · ` : ''}${pct.toFixed(1)}%`
        : `${Math.floor(nvJob.cpu_seconds || 0)}s CPU`;
      if ($('cockpit-bar1-fill')) $('cockpit-bar1-fill').style.width = pct !== null ? `${Math.max(2, pct).toFixed(1)}%` : '35%';
      if ($('cockpit-bar2-left')) $('cockpit-bar2-left').textContent = Number.isSafeInteger(nvJob.fold_total) && nvJob.fold_total > 0 ? 'Current Circuit Recursive Fold Step' : 'Saved Laptop Checkpoint Cache';
      if (Number.isSafeInteger(nvJob.fold_step) && Number.isSafeInteger(nvJob.fold_total) && nvJob.fold_total > 0) {
        const foldPct = Math.min(100, (nvJob.fold_step / nvJob.fold_total) * 100);
        if ($('cockpit-bar2-right')) $('cockpit-bar2-right').textContent = `Fold ${nvJob.fold_step} / ${nvJob.fold_total} (${foldPct.toFixed(0)}%)`;
        if ($('cockpit-bar2-fill')) $('cockpit-bar2-fill').style.width = `${Math.max(4, foldPct).toFixed(1)}%`;
      } else {
        if ($('cockpit-bar2-right')) $('cockpit-bar2-right').textContent = `${n(savedCore)} core · ${n(progress.unique_reduces)} rec`;
        if ($('cockpit-bar2-fill')) $('cockpit-bar2-fill').style.width = savedCore > 0 ? '100%' : '0%';
      }
    } else {
      if ($('cockpit-stage-tag')) $('cockpit-stage-tag').textContent = 'IDLE · CACHE PRESERVED';
      if ($('cockpit-headline')) $('cockpit-headline').textContent = 'NO ACTIVE PROVER · RESUMABLE CACHE READY';
      if ($('cockpit-detail')) $('cockpit-detail').textContent = `Laptop checkpoint holds ${n(savedCore)} core shards and ${n(progress.unique_reduces)} recursion folds (${n(wsl.session_summary?.artifact_store_mib)} MiB store).`;
      if ($('cockpit-bar1-left')) $('cockpit-bar1-left').textContent = 'Resumable Laptop Checkpoint Cache';
      if ($('cockpit-bar1-right')) $('cockpit-bar1-right').textContent = `${n(savedCore)} core · ${n(progress.unique_reduces)} rec`;
      if ($('cockpit-bar1-fill')) $('cockpit-bar1-fill').style.width = savedCore > 0 ? '100%' : '0%';
      if ($('cockpit-bar2-left')) $('cockpit-bar2-left').textContent = 'Proof Gates Cleared (Ark → BitVM3)';
      const proofRows = (campaign?.rows || []).filter(r => r.id !== 'delivery');
      const cleared = proofRows.filter(r => r.done).length;
      if ($('cockpit-bar2-right')) $('cockpit-bar2-right').textContent = `${cleared} / ${proofRows.length || 8} gates`;
      if ($('cockpit-bar2-fill')) $('cockpit-bar2-fill').style.width = `${(cleared / Math.max(1, proofRows.length)) * 100}%`;
    }
  }

  function updateRibbonAndKpis(live, all, selected, arkCloud, pilot, cloud, workerSummary, campaign) {
    const gpu = live.gpu || {};
    const host = live.host_memory || {};
    const wsl = live.wsl_prover || {};
    const prog = wsl.progress || {};
    const archive = ProofEta.arkArchive(arkCloud?.sample);
    const hsLive = hyperstackLiveSignal();
    const primaryHsVm = hsLive.activeInstances.find(v => `hyperstack-vm:${v.id}` === state.selected) || hsLive.activeInstances[0] || null;

    // 1. Top Ribbon Col 1: Active GPU / Cloud
    if (arkCloud?.active) {
      const s = arkCloud.sample;
      $('rib-gpu-label').textContent = `HYPERSTACK · ${s.spot ? 'A100 SPOT' : 'A100 VM'}`;
      $('rib-gpu-val').textContent = Number.isFinite(s.vram_used_mib) ? `${n(s.vram_used_mib)} MiB` : 'A100 LIVE';
      $('rib-gpu-unit').textContent = `VM #${s.vm_id} · $${Number(s.rate_usd_per_hour || 0).toFixed(2)}/h`;
      const vPct = Number.isFinite(s.vram_used_mib) ? Math.min(100, (s.vram_used_mib / 81920) * 100) : 25;
      $('rib-gpu-bar').style.width = `${Math.max(8, vPct).toFixed(1)}%`;
      $('rib-gpu-sub-l').textContent = arkCloud.phase;
      $('rib-gpu-sub-r').textContent = `Rpt ${clockTime(s.sampled_at_unix)}`;
    } else if (primaryHsVm) {
      const m = primaryHsVm.metrics || {};
      $('rib-gpu-label').textContent = `HYPERSTACK · ${primaryHsVm.name.toUpperCase()}`;
      $('rib-gpu-val').textContent = primaryHsVm.gpu ? primaryHsVm.gpu : `${primaryHsVm.cpu || '--'} vCPU`;
      $('rib-gpu-unit').textContent = `VM #${primaryHsVm.id} · ${primaryHsVm.region || ''}`;
      $('rib-gpu-badge').textContent = String(primaryHsVm.status || 'ACTIVE').toUpperCase();
      $('rib-gpu-badge').className = 'eta-badge cyan';
      $('rib-gpu-bar').style.width = Number.isFinite(m.cpu_percent) ? `${Math.min(100, Math.max(8, m.cpu_percent)).toFixed(1)}%` : '35%';
      $('rib-gpu-sub-l').textContent = `${primaryHsVm.flavor || 'Hyperstack VM'}${Number.isFinite(m.cpu_percent) ? ` · CPU ${n(m.cpu_percent, 1)}%` : ''}`;
      $('rib-gpu-sub-r').textContent = `API ${clockTime(hsLive.sampledAt)}`;
    } else if (pilot?.active) {
      $('rib-gpu-label').textContent = 'HYPERSTACK · CPU PILOT';
      $('rib-gpu-val').textContent = pilot.hardware;
      $('rib-gpu-unit').textContent = `VM #${pilot.sample.vm_id}`;
      $('rib-gpu-badge').textContent = pilot.status.toUpperCase();
      $('rib-gpu-bar').style.width = '65%';
      $('rib-gpu-sub-l').textContent = pilot.status;
      $('rib-gpu-sub-r').textContent = `Rpt ${clockTime(pilot.sample.sampled_at_unix)}`;
    } else if (cloud.active) {
      $('rib-gpu-label').textContent = `${cloud.provider.toUpperCase()} GPU`;
      $('rib-gpu-val').textContent = cloudMeasure(cloud.cloud.metrics?.gpu_util_percent, '%');
      $('rib-gpu-unit').textContent = cloud.gpuName || 'Remote GPU';
      $('rib-gpu-badge').textContent = 'RUNNING';
      $('rib-gpu-bar').style.width = `${Math.min(100, cloud.cloud.metrics?.gpu_memory_percent || 0)}%`;
      $('rib-gpu-sub-l').textContent = `VRAM ${cloudMeasure(cloud.cloud.metrics?.gpu_memory_percent, '%')}`;
      $('rib-gpu-sub-r').textContent = clockTime(cloud.cloud.sampled_at_unix);
    } else {
      $('rib-gpu-label').textContent = gpu.available ? gpu.name.replace('NVIDIA GeForce ', '').toUpperCase() : 'LOCAL GPU';
      $('rib-gpu-val').textContent = gpu.available ? `${n(gpu.util_gpu_pct)}% GPU` : 'UNAVAILABLE';
      const vUsed = gpu.vram_used_mib || 0, vTot = gpu.vram_total_mib || 16303;
      $('rib-gpu-unit').textContent = gpu.available ? `${n(Math.round(vUsed))} / ${n(Math.round(vTot))} MiB` : '--';
      $('rib-gpu-badge').textContent = gpu.available ? `${gpu.temp_c}°C · ${n(gpu.power_draw_w, 0)}W` : 'OFFLINE';
      $('rib-gpu-badge').className = 'eta-badge emerald';
      $('rib-gpu-bar').style.width = gpu.available ? `${Math.min(100, (vUsed / vTot) * 100).toFixed(1)}%` : '0%';
      $('rib-gpu-sub-l').textContent = gpu.available ? `${gpu.clock_sm_mhz || 0} MHz SM` : 'No local GPU signal';
      $('rib-gpu-sub-r').textContent = 'Local RTX';
    }

    // 2. Top Ribbon Col 2: Windows & WSL RAM
    if (host.supported) {
      const freeGiB = host.avail_phys_bytes / 2**30;
      const usedGiB = host.used_phys_bytes / 2**30;
      const totGiB = host.total_phys_bytes / 2**30;
      const load = host.load_percent ?? Math.round((usedGiB / Math.max(1, totGiB)) * 100);
      $('rib-host-val').textContent = `${n(freeGiB, 2)} GiB`;
      $('rib-host-unit').textContent = `free · ${n(usedGiB, 1)}/${n(totGiB, 1)}G`;
      $('rib-host-badge').textContent = `${load}% USED`;
      $('rib-host-badge').className = `eta-badge ${freeGiB < 4 ? 'cyan' : 'emerald'}`;
      $('rib-host-bar').style.width = `${Math.min(100, load)}%`;
      $('rib-host-bar').className = `meter-fill ${freeGiB < 4 ? 'red' : 'emerald'}`;
      const vm = host.vmmem_wsl;
      $('rib-host-sub-l').textContent = vm ? `WSL WS: ${gib(vm.working_set_bytes)}` : 'vmmemWSL idle';
      $('rib-host-sub-r').textContent = vm ? `Commit ${n(vm.private_commit_bytes / 2**30, 1)} GiB` : '--';
    }

    // 3. Top Ribbon Col 3: Workers & Private Bucket
    const hsExtra = hsLive.activeInstances.filter(v => !(arkCloud?.active && arkCloud.sample.vm_id === v.id)).length;
    const cloudRunning = (arkCloud?.active && arkCloud.sample.ark_running ? 1 : 0) + (pilot?.active ? 1 : 0) + hsExtra;
    const localRunning = freshRuntime() ? all.filter(j => j.running && !j.hyperstackVm && j.id !== 'ark-sp1:campaign').length + (live.runtime?.ark_processes || []).length : 0;
    const totalRunning = workerSummary?.running ?? (cloudRunning + localRunning);
    const s3Bytes = archive.storage ? archive.storage.bucket_bytes : hsLive.totalBucketBytes;
    const s3Objs = archive.storage ? archive.storage.objects : hsLive.totalBucketObjects;
    const hasS3 = s3Bytes > 0 || s3Objs > 0;
    $('rib-workers-val').textContent = `${cloudRunning} Cloud · ${localRunning} Loc`;
    $('rib-workers-unit').textContent = hasS3 ? `${n(s3Bytes / 1e9, 2)} GB S3` : 'No bucket';
    $('rib-workers-badge').textContent = `${totalRunning} RUNNING`;
    $('rib-workers-badge').className = `eta-badge ${totalRunning > 0 ? 'cyan' : 'violet'}`;
    $('rib-workers-bar').style.width = totalRunning > 0 ? '100%' : '12%';
    $('rib-workers-bar').className = `meter-fill ${totalRunning > 0 ? 'cyan' : 'violet'}`;
    $('rib-workers-sub-l').textContent = hasS3 ? `${n(s3Objs)} bucket objects` : (hsLive.authenticated ? 'Hyperstack API live' : 'Private storage idle');
    $('rib-workers-sub-r').textContent = archive.storage ? `Obs ${clockTime(archive.storage.sampled_at_unix)}` : (hsLive.sampledAt ? `API ${clockTime(hsLive.sampledAt)}` : 'Local runtime');

    // 4. Top Ribbon Col 4: SP1 Shard Stream
    if (arkCloud?.active) {
      const s = arkCloud.sample;
      const cTot = (s.core_new || 0) + (s.core_replayed || 0);
      const rTot = (s.recursion_new || 0) + (s.recursion_replayed || 0);
      const saved = prog.unique_shards || 1;
      $('rib-shard-val').textContent = `${n(cTot)} core`;
      $('rib-shard-unit').textContent = `${n(rTot)} rec`;
      if (!state.etaModel || state.etaModel.status !== 'tracking') {
        $('rib-shard-badge').textContent = `+${n(s.core_new)} NEW`;
        $('rib-shard-badge').className = 'eta-badge amber';
      }
      $('rib-shard-bar').style.width = `${Math.min(100, (cTot / Math.max(1, saved)) * 100).toFixed(1)}%`;
      $('rib-shard-sub-l').textContent = `${n(s.core_new)} new · ${n(s.core_replayed)} replay`;
      $('rib-shard-sub-r').textContent = `+${n(s.recursion_new)} new rec`;
    } else {
      $('rib-shard-val').textContent = `${n(prog.unique_shards)} core`;
      $('rib-shard-unit').textContent = `${n(prog.unique_reduces)} rec`;
      $('rib-shard-badge').textContent = prog.exists ? 'CACHED' : 'IDLE';
      $('rib-shard-badge').className = 'eta-badge violet';
      $('rib-shard-bar').style.width = prog.unique_shards ? '100%' : '0%';
      $('rib-shard-sub-l').textContent = 'Laptop progress.jsonl';
      $('rib-shard-sub-r').textContent = wsl.session_summary?.artifact_store_mib ? `${n(wsl.session_summary.artifact_store_mib)} MiB` : '--';
    }

    // 5 Open Architectural KPI Columns (Context-aware for Ark Campaign vs Audited Testnet4 Receipts)
    const isArk = !selected || selected.id === 'ark-sp1:campaign';
    if (isArk) {
      const proofRows = (campaign?.rows || []).filter(r => r.id !== 'delivery');
      const cleared = proofRows.filter(r => r.done).length;
      const s = arkCloud?.sample;
      const cTot = arkCloud?.active ? (s.core_new || 0) + (s.core_replayed || 0) : (prog.unique_shards ?? 0);
      const rTot = arkCloud?.active ? (s.recursion_new || 0) + (s.recursion_replayed || 0) : (prog.unique_reduces ?? 0);
      const saved = prog.unique_shards ?? 0;

      $('kpi-1-label').textContent = 'ACTIVE WORKER';
      $('kpi-1-val').textContent = arkCloud?.active ? (s.spot ? 'A100 Spot VM' : 'A100 VM') : arkProcess() ? `PID ${arkProcess().pid}` : 'Idle';
      $('kpi-1-badge').textContent = arkCloud?.active && s.ark_running ? 'RUNNING' : arkProcess() ? 'LOCAL LIVE' : 'IDLE';
      $('kpi-1-badge').className = `eta-badge ${arkCloud?.active && s.ark_running ? 'cyan' : 'emerald'}`;
      $('kpi-1-foot').textContent = arkCloud?.active ? `VM #${s.vm_id} · $${Number(s.rate_usd_per_hour || 0).toFixed(2)}/h` : 'No active local process';

      $('kpi-2-label').textContent = 'SP1 CORE SHARDS';
      $('kpi-2-val').textContent = n(cTot);
      $('kpi-2-badge').textContent = arkCloud?.active ? `+${n(s.core_new)} NEW` : 'CACHED';
      $('kpi-2-badge').className = `eta-badge ${arkCloud?.active ? 'cyan' : 'emerald'}`;
      $('kpi-2-bar').style.width = saved > 0 ? `${Math.min(100, (cTot / saved) * 100).toFixed(1)}%` : '0%';
      $('kpi-2-foot').textContent = arkCloud?.active ? `${n(s.core_replayed)} replay · Disk ${n(saved)}` : `Disk cache · ${n(saved)} unique`;

      $('kpi-3-label').textContent = 'RECURSION FOLDS';
      $('kpi-3-val').textContent = n(rTot);
      $('kpi-3-badge').textContent = arkCloud?.active ? `+${n(s.recursion_new)} NEW` : 'CACHED';
      $('kpi-3-badge').className = 'eta-badge violet';
      $('kpi-3-bar').style.width = rTot > 0 ? '100%' : '0%';
      $('kpi-3-foot').textContent = arkCloud?.active ? `${n(s.recursion_replayed)} replay · Disk ${n(prog.unique_reduces)}` : '3:1 KoalaBear tree';

      $('kpi-4-label').textContent = 'PROOF GATES & S3';
      $('kpi-4-val').textContent = `${cleared} / ${proofRows.length || 8}`;
      $('kpi-4-badge').textContent = archive.storage ? `${n(archive.storage.bucket_bytes / 1e9, 2)} GB S3` : 'M14 SETUP ✓';
      $('kpi-4-badge').className = `eta-badge ${cleared === (proofRows.length || 8) ? 'done' : 'emerald'}`;
      $('kpi-4-bar').style.width = `${(cleared / Math.max(1, proofRows.length || 8)) * 100}%`;
      $('kpi-4-foot').textContent = archive.storage ? `${n(archive.storage.objects)} objs · M14 setup ✓` : 'Independent proof checks';

      $('kpi-5-label').textContent = 'NUT NOV CUTOFF';
      const rem = ProofEta.arkDeadline - Date.now() / 1000;
      $('kpi-5-val').textContent = rem > 0 ? planningDuration(rem) : 'CLOSED';
      $('kpi-5-badge').textContent = 'NOV 27 23:59Z';
      $('kpi-5-badge').className = 'eta-badge amber';
      $('kpi-5-foot').textContent = $('overview-eta')?.textContent || 'Set scenario target below';
    } else if (selected?.hyperstackVm) {
      const vm = selected.hyperstackVm;
      const m = vm.metrics || {};
      const created = parseUtcSeconds(vm.created_at);
      const upStr = created !== null ? formatDuration(Math.max(0, Date.now() / 1000 - created)) : '--:--:--';
      $('kpi-1-label').textContent = 'HYPERSTACK NODE';
      $('kpi-1-val').textContent = `VM #${vm.id}`;
      $('kpi-1-badge').textContent = String(vm.status || 'ACTIVE').toUpperCase();
      $('kpi-1-badge').className = `eta-badge ${vm.active ? 'cyan' : 'emerald'}`;
      $('kpi-1-foot').textContent = `${vm.flavor || 'Cloud'} · ${vm.spot ? 'Spot' : 'On-Demand'}`;

      $('kpi-2-label').textContent = vm.gpu ? 'GPU & VCPU' : 'COMPUTE VCPUS';
      $('kpi-2-val').textContent = vm.gpu ? `${vm.gpu_count || 1}× ${vm.gpu}` : `${vm.cpu || '--'} vCPU`;
      $('kpi-2-badge').textContent = Number.isFinite(m.cpu_percent) ? `CPU ${n(m.cpu_percent, 1)}%` : `${vm.cpu || '--'} CORES`;
      $('kpi-2-badge').className = 'eta-badge cyan';
      $('kpi-2-bar').style.width = Number.isFinite(m.cpu_percent) ? `${Math.min(100, m.cpu_percent).toFixed(1)}%` : '20%';
      $('kpi-2-foot').textContent = `${vm.cpu || '--'} vCPU · ${vm.flavor || '--'}`;

      const ramPct = Number.isFinite(m.memory_used_gib) && Number.isFinite(vm.ram_gib) && vm.ram_gib > 0 ? Math.min(100, (m.memory_used_gib / vm.ram_gib) * 100) : 0;
      $('kpi-3-label').textContent = 'VM MEMORY';
      $('kpi-3-val').textContent = Number.isFinite(m.memory_used_gib) ? `${n(m.memory_used_gib, 1)} / ${n(vm.ram_gib, 0)}G` : `${n(vm.ram_gib, 0)} GiB`;
      $('kpi-3-badge').textContent = Number.isFinite(m.memory_used_gib) ? `${ramPct.toFixed(0)}% RAM` : 'ALLOCATED';
      $('kpi-3-badge').className = 'eta-badge violet';
      $('kpi-3-bar').style.width = `${Math.max(4, ramPct).toFixed(1)}%`;
      $('kpi-3-foot').textContent = 'Hyperstack live /metrics';

      $('kpi-4-label').textContent = 'REGION & DISK';
      $('kpi-4-val').textContent = String(vm.region || 'CLOUD').toUpperCase();
      $('kpi-4-badge').textContent = vm.disk_gb ? `${vm.disk_gb} GB` : 'DISK';
      $('kpi-4-badge').className = 'eta-badge emerald';
      $('kpi-4-bar').style.width = '100%';
      $('kpi-4-foot').textContent = vm.environment || vm.image || 'Hyperstack';

      $('kpi-5-label').textContent = 'VM UPTIME';
      $('kpi-5-val').textContent = upStr;
      $('kpi-5-badge').textContent = 'LIVE API';
      $('kpi-5-badge').className = 'eta-badge amber';
      $('kpi-5-foot').textContent = `Polled ${clockTime(hsLive.sampledAt)}`;
    } else if (selected?.kind === 'mnr05' || selected?.kind === 'mnr04') {
      const pct = Number.isFinite(selected.progress_pct) ? Math.min(100, Math.max(0, selected.progress_pct)) : null;
      const ramMiB = Number.isFinite(selected.ram_bytes) ? Math.round(selected.ram_bytes / 2**20) : null;
      $('kpi-1-label').textContent = 'LOCAL NOVA WORKER';
      $('kpi-1-val').textContent = selected.process ? `PID ${selected.process.pid}` : 'Inactive';
      $('kpi-1-badge').textContent = String(selected.status || 'RUNNING').toUpperCase();
      $('kpi-1-badge').className = `eta-badge ${selected.running ? 'cyan' : 'emerald'}`;
      $('kpi-1-foot').textContent = selected.backend || 'Nova / CPU';

      $('kpi-2-label').textContent = 'PROOF PROGRESS';
      $('kpi-2-val').textContent = pct !== null ? `${pct.toFixed(1)}%` : '--';
      $('kpi-2-badge').textContent = Number.isSafeInteger(selected.completed_steps) && Number.isSafeInteger(selected.total_steps)
        ? `${selected.completed_steps} / ${selected.total_steps} STAGES` : (selected.running ? 'PROVING' : 'IDLE');
      $('kpi-2-badge').className = 'eta-badge cyan';
      $('kpi-2-bar').style.width = pct !== null ? `${Math.max(4, pct).toFixed(1)}%` : '30%';
      $('kpi-2-foot').textContent = selected.phase || 'Nova R1CS folding';

      $('kpi-3-label').textContent = 'RECURSIVE FOLDS';
      $('kpi-3-val').textContent = Number.isSafeInteger(selected.fold_step) && Number.isSafeInteger(selected.fold_total)
        ? `${selected.fold_step} / ${selected.fold_total}` : '8 + 3';
      $('kpi-3-badge').textContent = 'ZERO SETUP';
      $('kpi-3-badge').className = 'eta-badge violet';
      $('kpi-3-bar').style.width = Number.isSafeInteger(selected.fold_step) && Number.isSafeInteger(selected.fold_total) && selected.fold_total > 0
        ? `${Math.min(100, (selected.fold_step / selected.fold_total) * 100).toFixed(1)}%` : '100%';
      $('kpi-3-foot').textContent = 'Secq256k1 (8) + BN254 IPA (3)';

      $('kpi-4-label').textContent = 'CPU & RSS';
      $('kpi-4-val').textContent = ramMiB !== null ? `${n(ramMiB)} MiB` : '--';
      $('kpi-4-badge').textContent = Number.isFinite(selected.cpu_seconds) ? `${Math.floor(selected.cpu_seconds)}s CPU` : 'CPU';
      $('kpi-4-badge').className = 'eta-badge emerald';
      $('kpi-4-bar').style.width = '100%';
      $('kpi-4-foot').textContent = '0 MiB GPU VRAM · RTX 5080 free';

      $('kpi-5-label').textContent = 'NETWORK & TARGET';
      $('kpi-5-val').textContent = 'CORE 31.1';
      $('kpi-5-badge').textContent = 'BITVM3 + PTLC';
      $('kpi-5-badge').className = 'eta-badge amber';
      $('kpi-5-foot').textContent = selected.network || 'SatsHedgeZero';
    } else {
      $('kpi-1-label').textContent = 'LOCAL PROCESS';
      $('kpi-1-val').textContent = selected.process ? `PID ${selected.process.pid}` : 'Inactive';
      $('kpi-1-badge').textContent = selected.status.toUpperCase();
      $('kpi-1-badge').className = `eta-badge ${selected.audit?.valid ? 'done' : 'emerald'}`;
      $('kpi-1-foot').textContent = selected.backend || '--';

      $('kpi-2-label').textContent = 'NEG CONTROLS';
      $('kpi-2-val').textContent = selected.audit?.valid
        ? `${selected.audit.negative_controls_passed} / ${selected.audit.negative_controls_total}` : '--';
      $('kpi-2-badge').textContent = selected.audit?.valid ? '✓ PASSED' : 'PENDING';
      $('kpi-2-badge').className = `eta-badge ${selected.audit?.valid ? 'done' : 'emerald'}`;
      $('kpi-2-bar').style.width = selected.audit?.valid ? '100%' : '0%';
      $('kpi-2-foot').textContent = 'Tampered witness / statement checks';

      $('kpi-3-label').textContent = 'PROOF ARTIFACT';
      $('kpi-3-val').textContent = selected.audit?.proof_bytes ? `${n(selected.audit.proof_bytes / 1e6, 2)} MB` : '--';
      $('kpi-3-badge').textContent = selected.audit?.hash_matches ? 'SHA-256 ✓' : '--';
      $('kpi-3-badge').className = `eta-badge ${selected.audit?.hash_matches ? 'done' : 'violet'}`;
      $('kpi-3-bar').style.width = selected.audit?.hash_matches ? '100%' : '0%';
      $('kpi-3-foot').textContent = selected.audit?.proof_sha256 ? selected.audit.proof_sha256.slice(0, 18) + '…' : '--';

      $('kpi-4-label').textContent = 'NETWORK & STAGE';
      $('kpi-4-val').textContent = String(selected.network || 'TESTNET4').toUpperCase();
      $('kpi-4-badge').textContent = 'RECORDED';
      $('kpi-4-badge').className = 'eta-badge emerald';
      $('kpi-4-bar').style.width = '100%';
      $('kpi-4-foot').textContent = selected.phase || 'Verified receipt';

      $('kpi-5-label').textContent = 'AUDIT RECEIPT';
      $('kpi-5-val').textContent = selected.audit?.valid ? 'VERIFIED' : 'UNCONFIRMED';
      $('kpi-5-badge').textContent = selected.audit?.valid ? '✓ HASH BOUND' : 'NONE';
      $('kpi-5-badge').className = `eta-badge ${selected.audit?.valid ? 'done' : 'amber'}`;
      $('kpi-5-foot').textContent = selected.audit?.modified_at_unix ? time(selected.audit.modified_at_unix) : '--';
    }
  }

  function render() {
    const live = state.live || {};
    const rt = live.runtime || {};
    const cloud = runpodSignal();
    const pilot = hyperstackSignal();
    const arkCloud = arkCloudSignal();
    const all = jobs().sort((a, b) => Number(b.id.startsWith('ark-sp1:')) - Number(a.id.startsWith('ark-sp1:')));
    if (!state.userSelected || !state.selected || !all.some(j => j.id === state.selected)) {
      state.selected = all.find(j => j.running)?.id || all[0]?.id;
    }
    const selected = all.find(j => j.id === state.selected);

    // Sidebar Campaigns
    setMarkup('campaign-list', all.map(j => `
      <button type="button" class="campaign-btn ${j.id === state.selected ? 'active' : ''}" data-id="${esc(j.id)}">
        <div class="campaign-btn-top">
          <span>${esc(j.title)}</span>
          <span class="dot ${j.running ? 'live' : j.audit?.valid ? 'cyan' : ''}"></span>
        </div>
        <span class="campaign-btn-sub">${esc(j.status)} · ${esc(j.backend)}</span>
      </button>`).join('') || '<p class="panel-sub">Waiting for runtime…</p>');
    $('campaign-list').querySelectorAll('button').forEach(b => { b.onclick = () => select(b.dataset.id); });

    // Hero Strip
    $('campaign-title').textContent = selected?.title || 'ZK RAITO NO BITCOINO';
    $('campaign-network').textContent = selected?.network || 'LIVE PROVER OBSERVATIONS';
    $('campaign-subtitle').textContent = selected?.phase || selected?.backend || 'Waiting for observed proof process';
    $('campaign-eta-pill').textContent = String(selected?.status || 'CONNECTING').toUpperCase();
    $('campaign-eta-pill').className = `status-pill ${statusClass(selected?.status)}`;
    $('campaign-badge').textContent = selected?.checksPassed ? 'OFF-CHAIN CHECKS PASSED'
      : selected?.audit?.valid ? 'RECORDED AUDIT · HASH MATCHES'
      : selected?.hyperstackVm ? `HYPERSTACK VM #${selected.hyperstackVm.id} · ${String(selected.hyperstackVm.status || 'LIVE').toUpperCase()}`
      : arkCloud?.active ? `A100 SPOT VM #${arkCloud.sample.vm_id} · LIVE`
      : 'OBSERVED CAMPAIGN · UNVERIFIED';
    $('campaign-hw').textContent = selected?.hyperstackVm
      ? `Hyperstack ${selected.hyperstackVm.flavor || 'Cloud'} · ${selected.hyperstackVm.gpu ? `${selected.hyperstackVm.gpu_count || 1}× ${selected.hyperstackVm.gpu}` : `${selected.hyperstackVm.cpu || '--'} vCPU`} · ${n(selected.hyperstackVm.ram_gib, 0)} GiB RAM · ${selected.hyperstackVm.region || ''}`
      : selected?.id === 'ark-sp1:campaign' && arkCloud?.active
      ? `Hyperstack ${arkCloud.sample.spot ? 'A100 Spot' : 'A100 On-Demand'} · ${n(arkCloud.sample.vram_used_mib)} MiB VRAM · $${Number(arkCloud.sample.rate_usd_per_hour || 0).toFixed(2)}/hr`
      : selected?.running && selected.process
      ? `Local PID ${selected.process.pid} · ${selected.backend}`
      : selected?.audit?.valid ? `${selected.backend} · ${selected.audit.negative_controls_passed}/${selected.audit.negative_controls_total} negative controls passed`
      : 'Read-only observer · 0 prover interference';

    const stale = state.lastReceived > 0 && Date.now() - state.lastReceived > 15000;
    $('poll-label').textContent = !state.polling ? 'STREAM PAUSED'
      : stale ? 'RECONNECTING…'
      : live.sampled_at_unix ? `LIVE · ${clockTime(live.sampled_at_unix)}` : 'CONNECTING';
    $('live-dot').classList.toggle('live', state.polling && !stale);
    if ($('rail-mode-code')) $('rail-mode-code').textContent = state.polling ? 'LIVE' : 'HOLD';

    // Campaign milestones, workers, and forecast
    const campaign = updateCampaign();
    const workerSummary = renderOngoingJobs(all, arkCloud, pilot);
    const ark = live.wsl_prover || {};
    const progress = ark.progress || {};

    updateRibbonAndKpis(live, all, selected, arkCloud, pilot, cloud, workerSummary, campaign);
    updateMosaicData(arkCloud, progress);
    updateCockpitPanel(arkCloud, progress, campaign);
    renderCompletionFeed();

    // Runtime & Shard Cache bottom panels
    $('runtime-age').textContent = `${freshRuntime() ? 'FRESH' : 'STALE'} · ${clockTime(rt.sampled_at_unix)}`;
    setMarkup('jobs', all.map(j => `
      <article class="observed-job ${j.id === state.selected ? 'selected-job' : ''}">
        <div class="panel-head" style="margin-bottom:8px">
          <h3>${esc(j.title)}</h3>
          <span class="status-pill ${statusClass(j.status)}">${esc(j.status)}</span>
        </div>
        <div class="kv-grid">
          ${kv('Backend', j.backend)}
          ${kv('Process identity', j.process ? `PID ${j.process.pid} / start ${j.process.start_ticks}` : (j.id === 'ark-sp1:campaign' && arkCloud?.active ? `Hyperstack VM #${arkCloud.sample.vm_id}` : 'Inactive'))}
          ${kv('Current stage', j.phase || 'No stage observed')}
          ${kv('Independent audit', j.audit?.valid ? `${j.audit.negative_controls_passed}/${j.audit.negative_controls_total} neg controls · hash matches` : j.audit?.present ? 'Receipt present; unconfirmed' : 'Pending verification')}
        </div>
        <details data-detail-key="${esc(j.id)}">
          <summary>Observed journal &amp; evidence source</summary>
          <code>${esc(j.unit)}</code>
          <pre>${esc((j.log_tail || []).join('\n') || 'No local journal entries available')}</pre>
          ${j.audit?.path ? `<p class="source-path">${esc(j.audit.path)}</p>` : ''}
          ${j.audit?.proof_sha256 ? `<code>${esc(j.audit.proof_sha256)}</code>` : ''}
        </details>
      </article>`).join('') || '<p class="panel-sub">No runtime observations available.</p>');

    $('ark-state').textContent = freshRuntime() ? (rt.ark_processes?.length ? 'LOCAL PROCESS LIVE' : 'LOCAL IDLE · CACHE SAVED') : 'UNKNOWN';
    $('shard-metrics').innerHTML = kv('Unique cached core shards', progress.exists ? n(progress.unique_shards) : 'Unavailable')
      + kv('Unique cached reductions', progress.exists ? n(progress.unique_reduces) : 'Unavailable')
      + kv('Cache source', ark.progress_source || ark.base_dir || 'Unavailable')
      + kv('Mean proved latency', progress.mean_proved_ms?.shard ? `${(progress.mean_proved_ms.shard / 1000).toFixed(1)}s core · ${(progress.mean_proved_ms.reduce / 1000).toFixed(1)}s rec` : 'Measured live');
    renderArkCloud(arkCloud);

    const events = progress.recent_events || [];
    setMarkup('shard-events', events.slice(-18).reverse().map(ev =>
      `<span class="observed-tile ${ev.kind === 'reduce' ? 'reduce-tile' : 'shard-tile'} ${state.newEventSeqs.has(ev.seq) ? 'checkpoint-new' : ''}" data-seq="${esc(ev.seq)}" title="${esc(ev.key)}">${esc(ev.kind.toUpperCase())} · ${esc(String(ev.key || '').slice(0, 8))} · ${ev.replayed ? 'replay' : 'proved'} · ${n(ev.ms / 1000, 1)}s</span>`
    ).join('') || '<p class="panel-sub">No shard completion events observed.</p>');

    $('claims-list').innerHTML = all.filter(j => j.audit?.statement).map(j => `
      <article class="observed-job">
        <h3>${esc(j.title)} · ${esc(j.audit.valid ? 'audited historical claim' : 'unconfirmed receipt')}</h3>
        <pre>${esc(JSON.stringify(j.audit.statement, null, 2))}</pre>
      </article>`).join('') || '<p class="panel-sub">No payment claim receipt observed.</p>';

    // Tab visibility
    const show = {
      live: ['liveness-cockpit', 'eta-panel', 'runtime-shard-grid'],
      compute: ['compute-panel'],
      blocks: ['evidence-panel'],
      utxos: ['claims-panel'],
      cashu: ['cashu-panel'],
      estimator: ['planner-panel'],
    };
    const allTabs = ['liveness-cockpit', 'eta-panel', 'runtime-shard-grid', 'compute-panel', 'evidence-panel', 'claims-panel', 'cashu-panel', 'planner-panel'];
    allTabs.forEach(id => {
      const el = $(id);
      if (el) el.hidden = !(show[state.tab] || []).includes(id);
    });
    if ($('rail-phase-code')) $('rail-phase-code').textContent = TAB_PHASES[state.tab] || '01';

    renderLocalGpu();
    renderRunpodCloud();
    updateEta();
    drawHistory();
  }

  // --- Shard Planner Formatter ---
  async function runPlanner() {
    const form = $('planner');
    if (!form) return;
    const raw = Object.fromEntries([...new FormData(form)]);
    const payload = {};
    for (const [k, v] of Object.entries(raw)) {
      payload[k] = k === 'hardware_profile' ? v : Number(v);
    }
    try {
      const response = await fetch('/api/correlate', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
      });
      const res = await response.json();
      if ($('planner-result')) $('planner-result').textContent = `PROJECTION ONLY\n${JSON.stringify(res, null, 2)}`;
      const nv = res.nova || {}, sp = res.sp1 || {}, rc = res.resources || {};
      const cards = [
        ['Nova Segments & Steps', `${n(nv.total_segments)} segs · ${n(nv.total_steps)} steps`],
        ['R1CS & Basis', `${n(nv.total_r1cs_constraints)} R1CS (${n(nv.dominant_basis_points)} pts)`],
        ['SP1 Guest Instructions', n(sp.total_instructions)],
        ['SP1 Core Shards', n(sp.core_shards)],
        ['SP1 Recursive Reduces', n(sp.recursion_shards)],
        ['Cgroup RAM + Swap', `${rc.linux_cgroup_ram_gib} GiB RAM + ${rc.linux_swap_gib} GiB swap`],
        ['GPU VRAM / Host Reserve', `${rc.gpu_vram_gib} GiB VRAM · ${rc.windows_host_reserve_gib} GiB floor`],
        ['Est. Wall Time', `${rc.estimated_sp1_hours}h SP1 + ${nv.estimated_fold_hours}h Nova`],
      ];
      if ($('planner-cards')) $('planner-cards').innerHTML = cards.map(([k, v]) => kv(k, v)).join('');
      if ($('planner-total-tag')) $('planner-total-tag').textContent = `${n(sp.total_tasks)} total tasks`;
      const attr = sp.shard_attribution || {};
      const parts = [
        ['Header Blocks', attr.header_blocks || 0, 'var(--crimson)'],
        ['UTXO Window + Pay', attr.utxo_window_and_payments || 0, 'var(--ink)'],
        ['Shinigami Leaves', attr.shinigami_leaves || 0, 'var(--ink-muted)'],
        ['Ark VTXO Policy', attr.ark_vtxo_policy || 0, 'var(--crimson-deep)'],
      ];
      const sum = Math.max(1, parts.reduce((acc, p) => acc + p[1], 0));
      if ($('planner-attr-bar')) {
        $('planner-attr-bar').innerHTML = parts.filter(p => p[1] > 0)
          .map(([label, val, col]) => `<div class="stacked-seg" style="width:${((val / sum) * 100).toFixed(1)}%;background:${col}" title="${esc(label)}: ${n(val)}"></div>`)
          .join('');
      }
      if ($('planner-attr-legend')) {
        $('planner-attr-legend').innerHTML = parts.map(([label, val, col]) =>
          `<span class="legend-item"><i class="legend-swatch" style="background:${col}"></i>${esc(label)}: ${n(val)}</span>`
        ).join('');
      }
    } catch (error) {
      if ($('planner-result')) $('planner-result').textContent = error.message;
    }
  }

  // --- SSE 1.0s Live Stream + Fallback Poll + Evidence Inventory ---
  function ingestLive(snap) {
    state.live = snap;
    state.lastReceived = Date.now();
    state.lastSamplePerfMs = performance.now();

    const pill = $('sse-heartbeat-pill');
    if (pill) {
      $('sse-frame-label').textContent = `LIVE FRAME #${snap.frame_seq || 1} · 1.0S`;
      pill.classList.add('pulse-hit');
      setTimeout(() => pill.classList.remove('pulse-hit'), 260);
    }

    rememberSample(snap);
    rememberEvents(snap.wsl_prover?.progress || {});
    observeCloudCheckpoints();
    render();
  }

  async function fetchLiveOnce() {
    if (!state.polling) return;
    try {
      const response = await fetch('/api/live', {cache: 'no-store', signal: AbortSignal.timeout(8000)});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      ingestLive(await response.json());
    } catch (error) {
      $('poll-label').textContent = `OFFLINE · ${error.message}`;
      $('live-dot').classList.remove('live');
    }
  }

  async function fetchEvidence() {
    if (!state.polling) return;
    try {
      const evidence = await fetch('/api/campaigns', {cache: 'no-store', signal: AbortSignal.timeout(6000)});
      if (!evidence.ok) return;
      const inventory = await evidence.json();
      state.records = inventory.campaigns || [];
      $('evidence-source').textContent = `${inventory.available ? 'DISK' : 'UNAVAILABLE'} · ${state.records.length} REPORTS`;
      setMarkup('evidence-list', state.records.map(r => `
        <details class="observed-job">
          <summary>${esc(r.title)} · ${esc(r.summary?.status || 'recorded evidence')}</summary>
          <p class="source-path">${esc(r.path)}</p>
          <div class="kv-grid">${kv('Modified', time(r.modified_at_unix))}${kv('File SHA-256', r.sha256)}${kv('Report size', `${n(r.bytes)} bytes`)}</div>
          <pre>${esc(JSON.stringify(r.summary, null, 2))}</pre>
        </details>`).join('') || '<p class="panel-sub">No local result reports found.</p>');
      if (state.live) updateCampaign();
    } catch {}
  }

  function connectStream() {
    if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
    if (!state.polling || typeof EventSource === 'undefined') return;

    const es = new EventSource('/api/stream');
    state.eventSource = es;
    es.addEventListener('telemetry', ev => {
      try {
        ingestLive(JSON.parse(ev.data));
      } catch {}
    });
    es.onerror = () => {
      es.close();
      state.eventSource = null;
      if (state.polling) {
        setTimeout(() => { if (state.polling && !state.eventSource) connectStream(); }, 3000);
      }
    };
  }

  // --- Wire Controls ---
  document.querySelectorAll('.nav-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === state.tab);
    b.setAttribute('aria-selected', String(b.dataset.tab === state.tab));
    b.onclick = () => {
      state.tab = b.dataset.tab;
      document.querySelectorAll('.nav-btn').forEach(x => {
        x.classList.toggle('active', x === b);
        x.setAttribute('aria-selected', x === b ? 'true' : 'false');
      });
      render();
      document.querySelectorAll('.panel:not([hidden]), .liveness-cockpit:not([hidden])').forEach(p => {
        p.classList.remove('view-enter');
        void p.offsetWidth;
        p.classList.add('view-enter');
        setTimeout(() => p.classList.remove('view-enter'), 220);
      });
    };
  });

  const mosaicCanvas = $('shard-mosaic-canvas');
  if (mosaicCanvas) {
    mosaicCanvas.addEventListener('mousemove', ev => {
      const rect = mosaicCanvas.getBoundingClientRect();
      const x = ((ev.clientX - rect.left) / rect.width) * mosaicCanvas.width;
      const y = ((ev.clientY - rect.top) / rect.height) * mosaicCanvas.height;
      let hit = null;
      for (const tile of state.mosaicRects) {
        if (x >= tile.x && x <= tile.x + tile.w && y >= tile.y && y <= tile.y + tile.h) {
          hit = tile; break;
        }
      }
      state.hoveredTile = hit;
      if (hit) {
        $('mosaic-hover-label').textContent = hit.inFlight
          ? `IN-FLIGHT · ${state.activeMosaicSource} awaiting next checkpoint`
          : `${hit.kind === 'recursion' ? 'RecursionReduce' : 'ProveShard'} · ${hit.key || 'ckpt'}${Number.isFinite(hit.sec) ? ` · ${hit.sec}s` : ''} · ${hit.replayed ? 'REPLAYED' : 'PROVED'} (${hit.source})`;
      } else {
        $('mosaic-hover-label').textContent = 'Hover tile for digest & latency · Leading slot pulses while proving';
      }
    });
    mosaicCanvas.addEventListener('mouseleave', () => { state.hoveredTile = null; });
  }

  if ($('replay-completions-btn')) $('replay-completions-btn').onclick = triggerRecentReplay;
  if ($('open-cashu-roadmap')) $('open-cashu-roadmap').onclick = () => { $('cashu-tab').click(); $('cashu-heading').focus(); };
  if ($('overview-plan')) $('overview-plan').onclick = () => { $('campaign-plan').open = true; };
  if ($('overview-budget')) $('overview-budget').onclick = () => { $('cloud-budget').open = true; };
  if ($('overview-cashu')) $('overview-cashu').onclick = () => $('open-cashu-roadmap').click();
  if ($('cloud-budget-form')) {
    $('cloud-budget-form').onsubmit = e => e.preventDefault();
    $('cloud-budget-form').oninput = renderCloudBudget;
  }

  $('toggle-poll').onclick = () => {
    state.polling = !state.polling;
    $('toggle-poll').textContent = state.polling ? 'PAUSE' : 'RESUME';
    if (state.polling) {
      state.lastReceived = 0;
      fetchLiveOnce();
      connectStream();
    } else if (state.eventSource) {
      state.eventSource.close();
      state.eventSource = null;
    }
    render();
  };

  $('toggle-theme').onclick = () => {
    const dark = document.documentElement.dataset.theme === 'dark';
    document.documentElement.dataset.theme = dark ? 'grove' : 'dark';
    $('toggle-theme').textContent = dark ? 'VOID DARK' : 'SPEC LIGHT';
  };

  if ($('toggle-motion')) {
    $('toggle-motion').onclick = () => {
      quietMotion = !quietMotion;
      saveSetting('rbzk.motion', quietMotion ? 'still' : 'live');
      applyMotion();
    };
  }
  reducedMotion.addEventListener('change', applyMotion);

  $('eta-target-form').onsubmit = event => {
    event.preventDefault();
    const raw = $('eta-target').value.trim();
    const value = Number(raw);
    if (raw && (!Number.isSafeInteger(value) || value < 1 || value > 10000000)) {
      $('eta-target').setCustomValidity('Enter a whole core target between 1 and 10,000,000.');
      $('eta-target').reportValidity();
      return;
    }
    $('eta-target').setCustomValidity('');
    saveSetting(`rbzk.eta.${state.etaSource}`, raw);
    state.etaTarget = raw ? value : null;
    state.etaClock = null;
    updateEta();
  };
  $('eta-target').oninput = () => $('eta-target').setCustomValidity('');
  $('eta-reset').onclick = () => {
    $('eta-target').value = '';
    saveSetting(`rbzk.eta.${state.etaSource}`, '');
    state.etaTarget = null;
    state.etaClock = null;
    updateEta();
  };

  $('campaign-plan-inputs').innerHTML = planFields.map(([name, label]) =>
    `<label>${esc(label)}${name === 'core' ? '' : ' (min)'}<input name="${name}" type="number" min="1" max="${name === 'core' ? 10000000 : 10080}" step="1" inputmode="numeric" value="${esc(campaignPlan[name] ?? '')}"></label>`
  ).join('');
  $('campaign-plan-form').onsubmit = event => {
    event.preventDefault();
    campaignPlan = Object.fromEntries([...new FormData(event.target)].filter(([, val]) => val !== '').map(([k, val]) => [k, Number(val)]));
    saveSetting(planKey, JSON.stringify(campaignPlan));
    updateCampaign();
  };
  $('clear-campaign-plan').onclick = () => {
    campaignPlan = {};
    for (const input of $('campaign-plan-inputs').querySelectorAll('input')) input.value = '';
    saveSetting(planKey, '{}');
    updateCampaign();
  };

  $('planner').onsubmit = e => { e.preventDefault(); runPlanner(); };
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.onclick = () => {
      const p = PRESETS[btn.dataset.preset];
      if (!p) return;
      document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const form = $('planner');
      for (const [k, v] of Object.entries(p)) {
        const el = form.elements[k];
        if (el) el.value = String(v);
      }
      runPlanner();
    };
  });

  // Boot
  applyMotion();
  initCompute();
  startAnimationLoop();
  render();
  fetchLiveOnce();
  fetchEvidence();
  connectStream();
  runPlanner();

  state.fallbackTimer = setInterval(() => {
    if (state.polling && !state.eventSource) fetchLiveOnce();
    if (Date.now() - state.lastReceived > 15000) render();
  }, 2500);
  state.evidenceTimer = setInterval(fetchEvidence, 12000);
  window.addEventListener('resize', drawHistory);
})();
