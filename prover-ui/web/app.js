(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const esc = v => String(v ?? 'Unavailable').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const n = (v, digits=0) => typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString(undefined,{maximumFractionDigits:digits}) : '—';
  const gib = v => typeof v === 'number' ? `${n(v / 2**30,2)} GiB` : 'Unavailable';
  const time = t => typeof t === 'number' ? new Date(t*1000).toLocaleString() : 'Unavailable';
  const kv = (key,value) => `<div class="kv-item"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`;
  const state = {live:null, records:[], selected:null, userSelected:false, tab:'live', polling:true, timer:null, lastReceived:0, history:[], previous:new Map(), seen:new Set(), booted:false};
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
    for(const process of rt.ark_processes || []) {
      if(process.executable!=='/root/nb3-gpu-target/release/ark-prove-gpu-cached-gkr')continue;
      observed.push({id:`ark-sp1:${process.pid}:${process.start_ticks}`,title:'Ark ASP · SP1 GPU',
        network:'ARK ASP POLICY CAMPAIGN',backend:'SP1 / CUDA',running:true,status:'running',process,
        phase:'Core and recursive proving',
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
    const live=state.live||{}, rt=live.runtime||{}, gpu=live.gpu||{}, host=live.host_memory||{}, all=jobs();
    if(!state.userSelected || !state.selected || !all.some(j=>j.id===state.selected))state.selected=all.find(j=>j.running)?.id || all[0]?.id;
    const selected=all.find(j=>j.id===state.selected);
    $('campaign-list').innerHTML=all.map(j=>`<button class="campaign-btn ${j.id===state.selected?'active':''}" data-id="${esc(j.id)}"><div class="campaign-btn-top">${esc(j.title)}</div><span class="campaign-btn-sub">${esc(j.status)} · ${esc(j.backend)}</span></button>`).join('') || '<p class="panel-sub">Waiting for the machine…</p>';
    $('campaign-list').querySelectorAll('button').forEach(b=>b.onclick=()=>select(b.dataset.id));
    $('campaign-title').textContent=selected?.title || 'ZK RAITO NO BITCOINO';
    $('campaign-network').textContent=selected?.network || 'LIVE PROVER OBSERVATIONS';
    $('campaign-subtitle').textContent=selected?.phase || selected?.backend || 'Waiting for an observed proof process';
    $('campaign-eta-pill').textContent=selected?.status || 'CONNECTING';
    $('campaign-badge').textContent=selected?.audit?.valid ? 'RECORDED AUDIT · HASH MATCHES' : 'NO VERIFIED RECEIPT';
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
    $('jobs').innerHTML=all.map(j=>`<article class="observed-job ${j.id===state.selected?'selected-job':''}"><div class="panel-head"><h3>${esc(j.title)}</h3><span class="status-pill ${statusClass(j.status)}">${esc(j.status)}</span></div><div class="kv-grid">${kv('Backend',j.backend)}${kv('Process identity',j.process?`${j.process.pid} / start ${j.process.start_ticks}`:'Not observed')}${kv('Current stage',j.phase || 'No stage observed')}${kv('RAM cap',gib(j.ram_limit_bytes))}${kv('CPU seconds',n(j.cpu_seconds,1))}${kv('Independent audit',j.audit?.valid?`${j.audit.negative_controls_passed}/${j.audit.negative_controls_total} negative controls · proof hash matches`:j.audit?.present?'Receipt present; verification not established':'Not present')}</div><details><summary>Observed journal and evidence source</summary><code>${esc(j.unit)}</code><pre>${esc((j.log_tail||[]).join('\n') || 'No journal entries available')}</pre><p class="source-path">${esc(j.audit?.path)}</p><code>${esc(j.audit?.proof_sha256 || 'No audited proof hash')}</code></details></article>`).join('') || '<p>No runtime observations available.</p>';
    const ark=live.wsl_prover||{}, progress=ark.progress||{};
    $('ark-state').textContent=freshRuntime()?(rt.ark_processes?.length?'PROCESS OBSERVED':'INACTIVE · CACHE HISTORY'):'UNKNOWN';
    $('shard-metrics').innerHTML=kv('Unique cached core shards',progress.exists?n(progress.unique_shards):'Unavailable')+kv('Unique cached reductions',progress.exists?n(progress.unique_reduces):'Unavailable')+kv('Cache source',ark.progress_source || ark.base_dir || 'Unavailable')+kv('ETA','Not established from this run');
    const events=progress.recent_events||[];
    $('shard-events').innerHTML=events.slice(-24).map(ev=>`<span class="observed-tile" title="${esc(ev.key)}">${esc(ev.kind)} · ${ev.replayed?'replayed':'proved'} · ${n(ev.ms/1000,1)}s</span>`).join('') || '<p class="panel-sub">No shard completion events observed.</p>';
    $('claims-list').innerHTML=all.filter(j=>j.audit?.statement).map(j=>`<article class="observed-job"><h3>${esc(j.title)} · ${esc(j.audit.valid?'audited historical claim':'unconfirmed receipt')}</h3><pre>${esc(JSON.stringify(j.audit.statement,null,2))}</pre></article>`).join('') || '<p>No payment claim receipt observed.</p>';
    const show={live:['runtime-panel','shard-panel'],blocks:['evidence-panel'],utxos:['claims-panel'],estimator:['planner-panel']};
    ['runtime-panel','shard-panel','evidence-panel','claims-panel','planner-panel'].forEach(id=>$(id).hidden=!show[state.tab].includes(id));
    drawHistory();
  }
  async function poll() {
    if(!state.polling)return;
    try {
      const response=await fetch('/api/live',{cache:'no-store',signal:AbortSignal.timeout(10000)});
      if(!response.ok)throw new Error(`Telemetry HTTP ${response.status}`);
      state.live=await response.json();state.lastReceived=Date.now();rememberSample(state.live);render();
      const evidence=await fetch('/api/campaigns',{cache:'no-store',signal:AbortSignal.timeout(5000)});
      if(!evidence.ok)throw new Error(`Evidence HTTP ${evidence.status}`);
      const inventory=await evidence.json();state.records=inventory.campaigns||[];
      $('evidence-source').textContent=`${inventory.available?'DISK':'UNAVAILABLE'} · ${state.records.length} reports`;
      $('evidence-list').innerHTML=state.records.map(r=>`<details class="observed-job"><summary>${esc(r.title)} · ${esc(r.summary?.status || 'recorded evidence')}</summary><p class="source-path">${esc(r.path)}</p><div class="kv-grid">${kv('Modified',time(r.modified_at_unix))}${kv('File SHA-256',r.sha256)}${kv('Report size',`${n(r.bytes)} bytes`)}</div><pre>${esc(JSON.stringify(r.summary,null,2))}</pre></details>`).join('') || '<p>No local result reports found.</p>';
    } catch(error) { $('poll-label').textContent=`CONNECTION LOST · ${error.message}`; $('live-dot').classList.remove('live'); }
    finally { if(state.polling)state.timer=setTimeout(poll,2000); }
  }
  document.querySelectorAll('.nav-btn').forEach(b=>b.onclick=()=>{state.tab=b.dataset.tab;document.querySelectorAll('.nav-btn').forEach(x=>{x.classList.toggle('active',x===b);x.setAttribute('aria-selected',x===b?'true':'false');});render();});
  $('toggle-poll').onclick=()=>{state.polling=!state.polling;if(state.polling)state.lastReceived=0;clearTimeout(state.timer);$('toggle-poll').textContent=state.polling?'PAUSE':'RESUME';render();if(state.polling)poll();};
  $('toggle-theme').onclick=()=>{const dark=document.documentElement.dataset.theme==='dark';document.documentElement.dataset.theme=dark?'grove':'dark';};
  $('planner').onsubmit=async event=>{event.preventDefault();const input=Object.fromEntries([...new FormData(event.target)].map(([k,v])=>[k,Number(v)]));input.hardware_profile='rtx5080_bounded_2gib';try{const response=await fetch('/api/correlate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});const result=await response.json();$('planner-result').textContent=`PROJECTION ONLY\n${JSON.stringify(result,null,2)}`;}catch(error){$('planner-result').textContent=error.message;}};
  setInterval(()=>{if(Date.now()-state.lastReceived>15000)render();},1000);
  window.addEventListener('resize',drawHistory);render();poll();
})();
