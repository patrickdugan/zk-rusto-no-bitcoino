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
    const {connected, paused, processObserved, setupRecorded, plan = {}} = options;
    const now = options.now ?? Date.now()/1000;
    const remainingToClose = arkDeadline-now;
    const latestStatus = typeof wsl.status === 'string' ? wsl.status : 'unknown';
    const waitingFor = latestStatus.startsWith('waiting_for_headroom_');
    const phase = waitingFor ? latestStatus.slice('waiting_for_headroom_'.length) : latestStatus;
    const waitingForSetup = phase === 'waiting_for_statement_bound_m14_setup';
    const checksPassed = phase === 'all_proof_checks_passed' && wsl.compressed_exists === true && wsl.wrap_v2_exists === true;
    const step = checksPassed ? coordinatorSteps.length :
      waitingForSetup ? coordinatorSteps.indexOf('m14claim') : coordinatorSteps.indexOf(phase);
    const setupReady = setupRecorded || (step >= coordinatorSteps.indexOf('m14claim') && !waitingForSetup);
    const resourceHold = waitingFor || phase === 'held_for_user_confirmation';
    const current = arkPhases.find(item => item.steps.includes(phase));
    const phaseObserved = connected && (current?.id === 'sp1' ? processObserved :
      finite(wsl.last_resource_age_s) && wsl.last_resource_age_s <= 15);
    const rows = arkPhases.map(item => {
      if(item.id === 'setup')return {...item,status:setupReady?'Setup verified':waitingForSetup?'Waiting for setup':'Pending',done:!!setupReady};
      if(item.id === 'delivery')return {...item,status:'Manual milestone',done:false};
      const done = step > coordinatorSteps.indexOf(item.steps.at(-1));
      const status = done ? 'Completed' : item === current ?
        waitingFor ? 'Resource wait' : phaseObserved ? 'In progress' : 'Last reported' : 'Pending';
      return {...item,done,status};
    });
    const progress = wsl.progress || {};
    const core = estimate(progress,{now,connected,paused,active:phase === 'gpu' && !waitingFor && processObserved,
      startedAt:wsl.phase_started_unix,target:plan.core});
    const corePending = !rows.find(row => row.id === 'sp1').done;
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
    if(connected && !paused && !resourceHold && step >= 0 && !missing.length) {
      if(!corePending) {
        if(checksPassed || phaseObserved || waitingForSetup)proofRange={fast:tailSeconds,slow:tailSeconds};
      } else if(target !== null && tracking) {
        proofRange={fast:core.fastSeconds+tailSeconds,slow:core.slowSeconds+tailSeconds};
      } else if(target === core.count && core.status === 'target_reached' && phaseObserved) {
        proofRange={fast:tailSeconds,slow:tailSeconds};
      }
    }
    const deliveryRange = proofRange && deliverySeconds !== null ?
      {fast:proofRange.fast+deliverySeconds,slow:proofRange.slow+deliverySeconds} : null;
    return {rows, phase, checksPassed, resourceHold, corePending, target, core, missing,
      proofRemaining:proofRange, proofFinish:project(proofRange), deliveryFinish:project(deliveryRange),
      coreCapacityUntilDeadline};
  }
  const cashuTrustMilestones = [
    {id:'backing',label:'Prove live backing and mint liabilities',
      detail:'Bind spendable Bitcoin or Ark collateral and outstanding Cashu claims to the same state. Detect spent collateral, expiry, reorgs and double-counted backing.'},
    {id:'issuance',label:'Enforce proof-bound Cashu issuance',
      detail:'Require a valid, unused authorization for each amount and mint keyset. Demonstrate that bypassing the desk or controlling one operator cannot produce extra valid tokens.'},
    {id:'redemption',label:'Fund redemption if the mint refuses',
      detail:'Fund a Bitcoin output and show a holder settling a valid Cashu claim to their own address while the mint refuses or stays offline. Record the timeout, fees and confirmed spend.'},
    {id:'adversarial',label:'Verify the end-to-end trust claim',
      detail:'Independently reproduce issuance and refusal-path settlement. Reject issuance replay, excess issuance and invalid or repeated redemption. State the remaining signer, setup and liveness assumptions.'},
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
      {id:'ark-proof',label:'Ark Nova → SP1 → M13 → BitVM3 off-chain proof',
        status:ark.checksPassed?'Checks reported · audit pending':'Conditional · finish unknown',done:false,
        detail:ark.checksPassed?
          'The coordinator reported all proof checks passed. Include this claim after auditing the statement and artifact hashes.':
          'Include the four-VTXO maintenance-policy proof if independent SP1 and M13 checks, honest M14 evaluation, full-circuit bit-flip rejection and the evidence audit finish by the cutoff.'},
    ];
    return {friday,trust:cashuTrustMilestones.map(item=>({...item,status:'Open · no ETA',done:false}))};
  }
  return {estimate,clock,arkCampaign,arkDeadline,arkBudgets,cashuRoadmap};
})();
if(typeof module!=='undefined' && module.exports)module.exports=ProofEta;
if(typeof document!=='undefined') (() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const esc = v => String(v ?? 'Unavailable').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const n = (v, digits=0) => typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString(undefined,{maximumFractionDigits:digits}) : '—';
  const gib = v => typeof v === 'number' ? `${n(v / 2**30,2)} GiB` : 'Unavailable';
  const time = t => typeof t === 'number' ? new Date(t*1000).toLocaleString() : 'Unavailable';
  const kv = (key,value) => `<div class="kv-item"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`;
  const state = {live:null, records:[], selected:null, userSelected:false, tab:'live', polling:true, timer:null, lastReceived:0, history:[], previous:new Map(), seen:new Set(), booted:false, etaClock:null, etaModel:null, etaSource:null, lastEventSeq:null, etaTarget:null, newEventSeqs:new Set()};
  const readSetting = key => {try{return localStorage.getItem(key);}catch{return null;}};
  const saveSetting = (key,value) => {try{localStorage.setItem(key,value);}catch{}};
  const planKey = 'rbzk.ark-campaign-plan.2026-11-23';
  const planFields = [['core','Expected total saved cores'], ...ProofEta.arkBudgets];
  let campaignPlan = {};
  try {campaignPlan = JSON.parse(readSetting(planKey)) || {};} catch {}
  const arkProcess = () => (state.live?.runtime?.ark_processes || [])
    .find(p=>p.executable==='/root/nb3-gpu-target/release/ark-prove-gpu-cached-gkr');
  const isCampaignRun = wsl => /(?:^|[\\/])ark-asp-full-20261117[\\/]?$/.test(wsl.base_dir || '');
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  let quietMotion = reducedMotion.matches || readSetting('rbzk.motion')==='still';
  function applyMotion() {
    document.documentElement.dataset.motion=quietMotion||reducedMotion.matches?'still':'subtle';
    $('toggle-motion').textContent=document.documentElement.dataset.motion==='still'?'MOTION: STILL':'MOTION: SUBTLE';
    $('toggle-motion').setAttribute('aria-pressed',document.documentElement.dataset.motion==='still'?'true':'false');
  }
  // Polling must preserve expanded evidence and keyboard focus.
  function setMarkup(id, markup) {
    const node=$(id);
    if(node.innerHTML===markup)return;
    const open=new Set([...node.querySelectorAll('details[open]')].map(d=>d.dataset.detailKey || d.querySelector('summary')?.textContent));
    const focused=node.contains(document.activeElement)?document.activeElement?.dataset.id:null;
    node.innerHTML=markup;
    node.querySelectorAll('details').forEach(d=>{d.open=open.has(d.dataset.detailKey || d.querySelector('summary')?.textContent);});
    if(focused)[...node.querySelectorAll('[data-id]')].find(b=>b.dataset.id===focused)?.focus({preventScroll:true});
  }
  function formatDuration(seconds) {
    if(typeof seconds!=='number'||!Number.isFinite(seconds))return '—';
    const s=Math.max(0,Math.ceil(seconds)),h=Math.floor(s/3600),m=Math.floor(s%3600/60);
    return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;
  }
  function planningDuration(seconds) {
    const minutes=Math.ceil(Math.max(0,seconds)/60);
    const days=Math.floor(minutes/1440),hours=Math.floor(minutes%1440/60);
    return [days&&`${days}d`,hours&&`${hours}h`,(minutes%60||!minutes)&&`${minutes%60}m`].filter(Boolean).join(' ');
  }
  const singaporeTime = new Intl.DateTimeFormat('en-SG',{
    timeZone:'Asia/Singapore',weekday:'short',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',hourCycle:'h23',
  });
  function finishLabel(range) {
    const fast=singaporeTime.format(range.fast*1000),slow=singaporeTime.format(range.slow*1000);
    return `${fast===slow?fast:`${fast} – ${slow}`} SGT`;
  }
  function milestoneMarkup({id,label,detail,status,done}) {
    return `<li class="campaign-milestone" data-stage="${id}"><div><strong>${esc(label)}</strong><p class="panel-sub">${esc(detail)}</p></div><span class="milestone-status${done?' is-done':''}">${esc(status)}</span></li>`;
  }
  function updateCampaign() {
    const observed=state.live?.wsl_prover || {};
    const wsl=isCampaignRun(observed)?observed:{};
    const processObserved=!!arkProcess();
    const setupRecorded=state.records.some(({title,summary})=>title==='m14-bounded-setup-20261123.json' &&
      summary?.schema==='ark-m14-bounded-setup-v1' && summary?.status==='statement_bound_setup_artifacts_verified');
    const connected=freshRuntime() && wsl.reachable===true;
    const campaign=ProofEta.arkCampaign(wsl,{connected,paused:!state.polling,processObserved,setupRecorded,plan:campaignPlan});
    const {checksPassed, proofRemaining, proofFinish, deliveryFinish, corePending, core, target, missing}=campaign;
    let headline='ETA needs a scenario';
    let basis='';
    if(checksPassed) {
      headline='Verifier checks passed';
      basis='Coordinator reported all Ark off-chain checks passed. Evidence audit and publication follow.';
    } else if(!connected) {
      headline=state.polling?'Waiting for telemetry':'Display paused';
      basis='The finish projection requires fresh campaign telemetry.';
    } else if(campaign.resourceHold || campaign.phase==='stopped') {
      headline=campaign.phase==='stopped'?'Coordinator stopped':'Waiting for resources';
      basis='The finish projection is held until the campaign can advance.';
    } else if(proofFinish) {
      const fast=planningDuration(proofRemaining.fast),slow=planningDuration(proofRemaining.slow);
      headline=`${fast===slow?fast:`${fast} – ${slow}`} remaining`;
      basis=`Scenario finish ${finishLabel(proofFinish)} using the entered budgets.`;
    } else if(corePending && target===null) {
      basis='The prover has not reported a final core count. Enter a planning target and stage budgets to project the full chain.';
    } else if(corePending && core.count>target) {
      basis='The run has passed the entered core total. Update the scenario to project the full chain.';
    } else if(missing.length) {
      basis=`Remaining budget needed for ${missing.length===1?missing[0]:`${missing.length} proof stages`}.`;
    } else {
      headline='Waiting for live progress';
      basis='The projection needs current proving pace or an observed verification phase.';
    }
    $('proof-finish').textContent=headline;
    $('proof-eta-basis').textContent=basis;
    let outlook='Deadline fit is undetermined.';
    if(deliveryFinish) {
      const cutoff=ProofEta.arkDeadline;
      const fit=deliveryFinish.slow<=cutoff?'Scenario fits the cutoff':
        deliveryFinish.fast>cutoff?'Scenario exceeds the cutoff':'Scenario overlaps the cutoff';
      outlook=`${fit} · package finish ${finishLabel(deliveryFinish)}`;
    } else if(proofFinish && !checksPassed) {
      outlook=proofFinish.fast>ProofEta.arkDeadline ? 'Proof scenario exceeds the cutoff before packaging.' :
        'Add an audit and demo budget to compare delivery against the cutoff.';
    } else if(target!==null && core.fastSeconds!==null && Date.now()/1000+core.fastSeconds>ProofEta.arkDeadline) {
      outlook='Even the faster core scenario exceeds the cutoff before verification and packaging.';
    } else if(campaign.coreCapacityUntilDeadline!==null) {
      outlook=`At ${n(core.rate,2)} cores/min, the deadline allows about ${n(campaign.coreCapacityUntilDeadline)} saved cores after entered reserves. Unbudgeted work and resource holds reduce that ceiling.`;
    }
    $('deadline-outlook').textContent=outlook;
    const summary=wsl.session_summary || {};
    const passReductions=summary.session_recursion_proved+summary.session_recursion_replayed;
    setMarkup('campaign-milestones',campaign.rows.map(row=>{
      let detail=row.detail;
      if(row.id==='sp1' && wsl.progress?.exists && !row.done) {
        detail=`${n(wsl.progress.unique_shards)} saved cores${Number.isSafeInteger(passReductions)&&processObserved?` · ${n(passReductions)} recursion checkpoints in the reported SP1 pass`:''}. ${detail}`;
      }
      if(row.id==='setup' && setupRecorded)detail=`785,442,492 ciphertexts generated and verified in 4m 32s. ${detail}`;
      const budget=campaignPlan[row.id];
      const remaining=Number.isFinite(budget)&&!row.done?` · ${planningDuration(budget*60)} budgeted`:'';
      return milestoneMarkup({...row,detail,status:row.status+remaining});
    }).join(''));
    const roadmap=ProofEta.cashuRoadmap(campaign,state.records);
    setMarkup('cashu-friday',roadmap.friday.map(milestoneMarkup).join(''));
    setMarkup('cashu-trust',roadmap.trust.map(milestoneMarkup).join(''));
    tickDeadline();
  }
  function tickDeadline() {
    const remaining=ProofEta.arkDeadline-Date.now()/1000;
    $('deadline-clock').textContent=remaining>0?`${planningDuration(remaining)} left`:'Submission closed';
  }
  function rememberEvents(progress) {
    const seq=Number(progress.seq)||0;
    state.newEventSeqs=new Set();
    if(state.lastEventSeq!==null && seq>=state.lastEventSeq && freshRuntime()) {
      for(const e of (progress.recent_events||[]).filter(e=>!e.replayed && e.seq>state.lastEventSeq).slice(-3))state.newEventSeqs.add(e.seq);
    }
    state.lastEventSeq=seq;
  }
  function updateEta() {
    const live=state.live||{},wsl=live.wsl_prover||{},progress=wsl.progress||{};
    const source=`${wsl.progress_source||progress.path||'unknown'}:${live.wsl_prover?.prover_binary_sha256||''}`;
    if(source!==state.etaSource) {
      state.etaSource=source;state.etaClock=null;
      $('eta-target').value=readSetting(`rbzk.eta.${source}`)||'';state.etaTarget=$('eta-target').value?Number($('eta-target').value):null;
    }
    const target=state.etaTarget;
    const active=freshRuntime() && !!arkProcess();
    const model=ProofEta.estimate(progress,{now:Date.now()/1000,target,active,connected:freshRuntime(),paused:!state.polling,startedAt:wsl.phase_started_unix});
    model.source=`${source}:${wsl.active_phase_dir||''}`;
    state.etaClock=ProofEta.clock(state.etaClock,model,performance.now()/1000);state.etaModel=model;
    document.documentElement.dataset.stream=active&&freshRuntime()?'live':'quiet';
    $('eta-scope').textContent=model.manual?'PLANNED CORE TARGET':'NEXT SAVED-CORE MILESTONE';
    $('eta-target-label').textContent=model.target?`${n(model.count)} → ${n(model.target)} saved cores`:'Waiting for a progress sample';
    $('eta-rate').textContent=model.rate?`${n(model.rate,2)} cores / min`:'Learning the current pace';
    $('eta-range').textContent=model.seconds!==null?`Recent-pace range ${formatDuration(model.fastSeconds)} – ${formatDuration(model.slowSeconds)}`:'A live completion rate is needed for an estimate.';
    $('eta-run-age').textContent=typeof wsl.latest_resource?.elapsed_s==='number'?`Phase elapsed ${formatDuration(wsl.latest_resource.elapsed_s)}`:'Phase elapsed unavailable';
    $('eta-proof-total').textContent=model.manual?'Core target projection · verification follows':'Core milestone estimate · full proof total not reported';
    const bar=$('eta-fill');bar.style.width=`${model.fraction*100}%`;
    $('eta-progress').setAttribute('aria-valuenow',String(Math.round(model.fraction*100)));
    $('eta-progress').setAttribute('aria-label',model.manual?'Progress to entered core target':'Progress to next saved-core milestone');
    const latest=(progress.recent_events||[]).filter(e=>!e.replayed).at(-1);
    $('eta-last-proof').textContent=latest?`Last ${latest.kind==='shard'?'core':'recursion'} proof · ${time(latest.t)}`:'Waiting for a new proof event';
    tickEta();
  }
  function tickEta() {
    const model=state.etaModel;if(!model)return;
    if(!state.polling || !freshRuntime()) {
      $('eta-clock').textContent=state.polling?'Signal stale':'Display paused';$('eta-finish').textContent='Estimate held';return;
    }
    const labels={paused:'Display paused',stale:'Signal stale',inactive:'Prover inactive',learning:'Learning pace',target_reached:'Target reached'};
    if(model.status!=='tracking') {
      $('eta-clock').textContent=labels[model.status]||'Waiting';
      $('eta-finish').textContent=model.status==='target_reached'?'Planning target reached; proving may continue':'Waiting for live proof progress';return;
    }
    const seconds=Math.max(0,state.etaClock.deadline-performance.now()/1000);
    $('eta-clock').textContent=seconds>0?`~ ${formatDuration(seconds)}`:'Awaiting checkpoint';
    $('eta-finish').textContent=seconds>0?`Estimated milestone ${new Date(Date.now()+seconds*1000).toLocaleTimeString()}`:'Estimate will refresh with the next saved core';
  }
  const statusClass = s => s === 'running' ? 'live' : s === 'verified receipt' ? 'cyan' : '';
  function freshRuntime() {
    const rt = state.live?.runtime || {};
    return state.polling && rt.fresh && Date.now()-state.lastReceived < 15000;
  }
  function jobs() {
    const rt=state.live?.runtime || {}, wsl=state.live?.wsl_prover || {};
    const observed=[...(rt.jobs || [])];
    const measured=freshRuntime() && typeof wsl.last_resource_age_s==='number' && wsl.last_resource_age_s<=15 && wsl.phase_running;
    const resources=measured ? (wsl.latest_resource || {}) : {};
    const process=arkProcess();
    if(process || isCampaignRun(wsl)) {
      const ark=ProofEta.arkCampaign(wsl);
      const phase=ark.rows.find(row=>row.steps.includes(ark.phase))?.label;
      const status=ark.checksPassed?'checks passed':process?'running':ark.resourceHold?'resource wait':
        ark.phase==='stopped'?'stopped':'coordinator observed';
      observed.push({id:'ark-sp1:campaign',title:'Ark ASP · SP1 → BitVM3',
        network:'ARK ASP POLICY CAMPAIGN',backend:'SP1 / CUDA',running:!!process,status,process,
        phase:phase || 'Ark proof and evidence delivery',checksPassed:ark.checksPassed,
        ram_bytes:typeof resources.cgroup_ram_mib==='number'?resources.cgroup_ram_mib*2**20:null,
        swap_bytes:typeof resources.cgroup_swap_mib==='number'?resources.cgroup_swap_mib*2**20:null,
        unit:wsl.active_phase_dir || 'Observed native process',
        log_tail:String(wsl.phase_log_tail || '').replace(/\x1b\[[0-9;]*m/g,'').split('\n').slice(-6),
        audit:{present:false,valid:false}});
    }
    return observed.map(j => freshRuntime() ? j : {...j,running:false,status:state.polling?'stale / unknown':'display paused'});
  }
  function select(id) { state.selected=id; state.userSelected=true; render(); }
  function drawHistory() {
    const canvas=$('observations'), ctx=canvas.getContext('2d'), width=canvas.clientWidth || 600;
    canvas.width=width*devicePixelRatio; canvas.height=150*devicePixelRatio;
    ctx.scale(devicePixelRatio,devicePixelRatio); ctx.clearRect(0,0,width,150);
    ctx.strokeStyle='rgba(150,150,150,.18)';
    for(let y=15;y<150;y+=30){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(width,y);ctx.stroke();}
    const rows=state.history, first=rows[0]?.t, last=rows.at(-1)?.t;
    [['cpu','#f5f5f5'],['ram','#9a9da6'],['gpu','#e60e1b']].forEach(([key,color])=>{
      ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=1.5;let moving=false;
      rows.forEach(row=>{if(typeof row[key]!=='number'){moving=false;return;}
        const x=(row.t-first)/Math.max(last-first,1)*(width-8)+4, y=145-Math.min(100,Math.max(0,row[key]))*1.3;
        if(moving)ctx.lineTo(x,y);else ctx.moveTo(x,y);moving=true;});ctx.stroke();
    });
    $('history-caption').textContent=`${rows.length} observed samples · white: proof CPU (% of 2 cores) · gray: Windows physical RAM % · red: total GPU compute %`;
  }
  function rememberSample(live) {
    const rt=live.runtime || {}, t=rt.sampled_at_unix;
    if(!rt.fresh || typeof t!=='number' || state.history.at(-1)?.t===t)return;
    let cpu=0, measured=false;
    for(const job of rt.jobs||[]){
      if(!job.running||!job.process||typeof job.cpu_seconds!=='number')continue;
      const key=`${job.process.pid}:${job.process.start_ticks}`, prev=state.previous.get(key);
      if(prev && t>prev.t && job.cpu_seconds>=prev.cpu){cpu+=(job.cpu_seconds-prev.cpu)/(t-prev.t)*50;measured=true;}
      state.previous.set(key,{t,cpu:job.cpu_seconds});
    }
    state.history.push({t,cpu:measured?cpu:null,ram:live.host_memory?.load_percent,gpu:live.gpu?.util_gpu_pct});
    if(state.history.length>180)state.history.shift();
  }
  function render() {
    const live=state.live||{}, rt=live.runtime||{}, gpu=live.gpu||{}, host=live.host_memory||{}, all=jobs().sort((a,b)=>Number(b.id.startsWith('ark-sp1:'))-Number(a.id.startsWith('ark-sp1:')));
    if(!state.userSelected || !state.selected || !all.some(j=>j.id===state.selected))state.selected=all.find(j=>j.running)?.id || all[0]?.id;
    const selected=all.find(j=>j.id===state.selected);
    setMarkup('campaign-list',all.map(j=>`<button class="campaign-btn ${j.id===state.selected?'active':''}" data-id="${esc(j.id)}"><div class="campaign-btn-top">${esc(j.title)}</div><span class="campaign-btn-sub">${esc(j.status)} · ${esc(j.backend)}</span></button>`).join('') || '<p class="panel-sub">Waiting for the machine…</p>');
    $('campaign-list').querySelectorAll('button').forEach(b=>b.onclick=()=>select(b.dataset.id));
    $('campaign-title').textContent=selected?.title || 'ZK RAITO NO BITCOINO';
    $('campaign-network').textContent=selected?.network || 'LIVE PROVER OBSERVATIONS';
    $('campaign-subtitle').textContent=selected?.phase || selected?.backend || 'Waiting for an observed proof process';
    $('campaign-eta-pill').textContent=selected?.status || 'CONNECTING';
    $('campaign-badge').textContent=selected?.checksPassed?'OFF-CHAIN CHECKS PASSED':
      selected?.audit?.valid?'RECORDED AUDIT · HASH MATCHES':'NO VERIFIED RECEIPT';
    $('campaign-eta-pill').className=`status-pill ${statusClass(selected?.status)}`;
    $('campaign-hw').textContent=selected?.running ? `PID ${selected.process.pid} · ${selected.backend}` : 'No running process established for this job';
    const stale=Date.now()-state.lastReceived>15000;
    $('poll-label').textContent=!state.polling?'DISPLAY PAUSED':stale?'DISCONNECTED / STALE':`LIVE · ${new Date(live.sampled_at_unix*1000).toLocaleTimeString()}`;
    $('live-dot').classList.toggle('live',state.polling&&!stale);
    $('hardware-ribbon').innerHTML=[
      ['GPU',gpu.available?gpu.name:'Unavailable',gpu.available?`${n(gpu.util_gpu_pct)}% compute · ${gib(gpu.vram_used_mib==null?null:gpu.vram_used_mib*2**20)} VRAM used`:'No GPU measurement'],
      ['WINDOWS MEMORY',gib(host.used_phys_bytes),`${gib(host.avail_phys_bytes)} free · ${n(host.load_percent)}% used`],
      ['WSL MEMORY',gib(host.vmmem_wsl?.working_set_bytes),`${gib(host.vmmem_wsl?.private_commit_bytes)} private commit`],
      ['PROVER',freshRuntime()?`${all.filter(j=>j.running&&j.backend!=='SP1 / CUDA').length} CPU · ${(rt.ark_processes||[]).length} Ark processes`:'Unknown',freshRuntime()?'From process identity':'Waiting for a fresh runtime observation']
    ].map(([label,value,detail])=>`<article class="ribbon-card"><div class="ribbon-head">${esc(label)}</div><div class="ribbon-main"><span class="ribbon-val runtime-value">${esc(value)}</span></div><div class="ribbon-sub">${esc(detail)}</div></article>`).join('');
    $('live-kpis').innerHTML=[['PROCESS',selected?.process?`PID ${selected.process.pid}`:'Inactive'],['CPU TIME',`${n(selected?.cpu_seconds,1)} s`],['PROOF RAM',gib(selected?.ram_bytes)],['SWAP',gib(selected?.swap_bytes)],['VERIFICATION',selected?.audit?.valid?'Hash-bound audit':'Not established']].map(([label,value])=>`<article class="kpi-card"><span class="kpi-label">${esc(label)}</span><strong class="kpi-value runtime-value">${esc(value)}</strong></article>`).join('');
    $('runtime-age').textContent=`${freshRuntime()?'FRESH':'STALE / UNKNOWN'} · sample ${time(rt.sampled_at_unix)}`;
    setMarkup('jobs',all.map(j=>`<article class="observed-job ${j.id===state.selected?'selected-job':''}"><div class="panel-head"><h3>${esc(j.title)}</h3><span class="status-pill ${statusClass(j.status)}">${esc(j.status)}</span></div><div class="kv-grid">${kv('Backend',j.backend)}${kv('Process identity',j.process?`${j.process.pid} / start ${j.process.start_ticks}`:'Not observed')}${kv('Current stage',j.phase || 'No stage observed')}${kv('RAM cap',gib(j.ram_limit_bytes))}${kv('CPU seconds',n(j.cpu_seconds,1))}${kv('Independent audit',j.audit?.valid?`${j.audit.negative_controls_passed}/${j.audit.negative_controls_total} negative controls · proof hash matches`:j.audit?.present?'Receipt present; verification not established':'Not present')}</div><details data-detail-key="${esc(j.id)}"><summary>Observed journal and evidence source</summary><code>${esc(j.unit)}</code><pre>${esc((j.log_tail||[]).join('\n') || 'No journal entries available')}</pre><p class="source-path">${esc(j.audit?.path)}</p><code>${esc(j.audit?.proof_sha256 || 'No audited proof hash')}</code></details></article>`).join('') || '<p>No runtime observations available.</p>');
    const ark=live.wsl_prover||{}, progress=ark.progress||{};
    $('ark-state').textContent=freshRuntime()?(rt.ark_processes?.length?'PROCESS OBSERVED':'INACTIVE · CACHE HISTORY'):'UNKNOWN';
    $('shard-metrics').innerHTML=kv('Unique cached core shards',progress.exists?n(progress.unique_shards):'Unavailable')+kv('Unique cached reductions',progress.exists?n(progress.unique_reduces):'Unavailable')+kv('Cache source',ark.progress_source || ark.base_dir || 'Unavailable')+kv('ETA basis','Measured core throughput · tracker above');
    const events=progress.recent_events||[];
    setMarkup('shard-events',events.slice(-24).map(ev=>`<span class="observed-tile ${state.newEventSeqs.has(ev.seq)?'checkpoint-new':''}" data-seq="${esc(ev.seq)}" title="${esc(ev.key)}">${esc(ev.kind)} · ${ev.replayed?'replayed':'proved'} · ${n(ev.ms/1000,1)}s</span>`).join('') || '<p class="panel-sub">No shard completion events observed.</p>');
    $('claims-list').innerHTML=all.filter(j=>j.audit?.statement).map(j=>`<article class="observed-job"><h3>${esc(j.title)} · ${esc(j.audit.valid?'audited historical claim':'unconfirmed receipt')}</h3><pre>${esc(JSON.stringify(j.audit.statement,null,2))}</pre></article>`).join('') || '<p>No payment claim receipt observed.</p>';
    const show={live:['eta-panel','runtime-panel','shard-panel'],blocks:['evidence-panel'],
      utxos:['claims-panel'],estimator:['planner-panel'],cashu:['cashu-panel']};
    Object.values(show).flat().forEach(id=>$(id).hidden=!show[state.tab].includes(id));
    updateCampaign();updateEta();drawHistory();
  }
  async function poll() {
    if(!state.polling)return;
    try {
      const response=await fetch('/api/live',{cache:'no-store',signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw new Error(`Telemetry HTTP ${response.status}`);
      state.live=await response.json();state.lastReceived=Date.now();rememberSample(state.live);rememberEvents(state.live.wsl_prover?.progress||{});render();
      const evidence=await fetch('/api/campaigns',{cache:'no-store',signal:AbortSignal.timeout(5000)});
      if(!evidence.ok)throw new Error(`Evidence HTTP ${evidence.status}`);
      const inventory=await evidence.json();state.records=inventory.campaigns||[];
      updateCampaign();
      $('evidence-source').textContent=`${inventory.available?'DISK':'UNAVAILABLE'} · ${state.records.length} reports`;
      setMarkup('evidence-list',state.records.map(r=>`<details class="observed-job"><summary>${esc(r.title)} · ${esc(r.summary?.status || 'recorded evidence')}</summary><p class="source-path">${esc(r.path)}</p><div class="kv-grid">${kv('Modified',time(r.modified_at_unix))}${kv('File SHA-256',r.sha256)}${kv('Report size',`${n(r.bytes)} bytes`)}</div><pre>${esc(JSON.stringify(r.summary,null,2))}</pre></details>`).join('') || '<p>No local result reports found.</p>');
    } catch(error) { $('poll-label').textContent=`CONNECTION LOST · ${error.message}`; $('live-dot').classList.remove('live'); }
    finally { if(state.polling)state.timer=setTimeout(poll,2000); }
  }
  document.querySelectorAll('.nav-btn').forEach(b=>b.onclick=()=>{state.tab=b.dataset.tab;document.querySelectorAll('.nav-btn').forEach(x=>{x.classList.toggle('active',x===b);x.setAttribute('aria-selected',x===b?'true':'false');});render();const panels=document.querySelectorAll('.panel:not([hidden])');panels.forEach(p=>{p.classList.remove('view-enter');void p.offsetWidth;p.classList.add('view-enter');setTimeout(()=>p.classList.remove('view-enter'),220);});});
  $('open-cashu-roadmap').onclick=()=>{
    const tab=$('cashu-tab');
    tab.click();
    $('cashu-heading').focus();
  };
  $('toggle-poll').onclick=()=>{state.polling=!state.polling;if(state.polling)state.lastReceived=0;clearTimeout(state.timer);$('toggle-poll').textContent=state.polling?'PAUSE':'RESUME';render();if(state.polling)poll();};
  $('toggle-theme').onclick=()=>{const dark=document.documentElement.dataset.theme==='dark';document.documentElement.dataset.theme=dark?'grove':'dark';};
  $('planner').onsubmit=async event=>{event.preventDefault();const input=Object.fromEntries([...new FormData(event.target)].map(([k,v])=>[k,Number(v)]));input.hardware_profile='rtx5080_bounded_2gib';try{const response=await fetch('/api/correlate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});const result=await response.json();$('planner-result').textContent=`PROJECTION ONLY\n${JSON.stringify(result,null,2)}`;}catch(error){$('planner-result').textContent=error.message;}};
  $('toggle-motion').onclick=()=>{quietMotion=!quietMotion;saveSetting('rbzk.motion',quietMotion?'still':'subtle');applyMotion();};
  reducedMotion.addEventListener('change',applyMotion);
  $('eta-target-form').onsubmit=event=>{event.preventDefault();const raw=$('eta-target').value.trim(),value=Number(raw);if(raw&&(!Number.isSafeInteger(value)||value<1||value>10000000)){$('eta-target').setCustomValidity('Enter a whole core target between 1 and 10,000,000.');$('eta-target').reportValidity();return;}$('eta-target').setCustomValidity('');saveSetting(`rbzk.eta.${state.etaSource}`,raw);state.etaTarget=raw?value:null;state.etaClock=null;updateEta();};
  $('eta-target').oninput=()=> $('eta-target').setCustomValidity('');
  $('eta-reset').onclick=()=>{$('eta-target').value='';saveSetting(`rbzk.eta.${state.etaSource}`,'');state.etaTarget=null;state.etaClock=null;updateEta();};
  $('campaign-plan-inputs').innerHTML=planFields.map(([name,label])=>
    `<label>${esc(label)}${name==='core'?'':' (min)'}<input name="${name}" type="number" min="1" max="${name==='core'?10000000:10080}" step="1" inputmode="numeric" value="${esc(campaignPlan[name] ?? '')}"></label>`).join('');
  $('campaign-plan-form').onsubmit=event=>{
    event.preventDefault();
    campaignPlan=Object.fromEntries([...new FormData(event.target)].filter(([,value])=>value!=='').map(([key,value])=>[key,Number(value)]));
    saveSetting(planKey,JSON.stringify(campaignPlan));
    updateCampaign();
  };
  $('clear-campaign-plan').onclick=()=>{
    campaignPlan={};
    for(const input of $('campaign-plan-inputs').querySelectorAll('input'))input.value='';
    saveSetting(planKey,'{}');
    updateCampaign();
  };
  applyMotion();
  setInterval(()=>{if(Date.now()-state.lastReceived>15000)render();tickEta();tickDeadline();},1000);
  window.addEventListener('resize',drawHistory);render();poll();
})();
