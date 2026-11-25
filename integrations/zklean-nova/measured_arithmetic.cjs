// Evaluate actual imported certificates with the unchanged authenticated matrix.
// This adapter exports the source function without running its fixed-fixture CLI.
// It generates/checks assignments in memory and does not create Nova proofs.
'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),Module=require('node:module');
const PIN={frontier:'2612b10cce2f337c24e6fe8b531328504f0b3c78993c9c95c9bdb2258eb82fc3',
  environment:'0958bdf88979960e47d4b872cddfe698735822554603f5c3a2037dc8fcaa2253',
  kernel:'484237e893bb6357737e30fb5354f72dadb8f67186a78835604bc64993b833b1',
  sample:'fb7e2ef68dbf19ebb2d8be57ae14eb7c2e844bc4b5aa61208724b80bcd2a6dfc',
  poseidon:'b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67',
  matrix:'c583f594c0757e1910ec667c13e27ca081778e4167fed58188d1ea9d1dc12c04'};
const SCHEMA='zkl-nova-18/corpus-arithmetic-receipt-v1';
const INITIAL_IMPORTER={sha256:'67e66923693ed0f6a390eba27a34b13a7903b7f2330449c58d29a31a024c6bcd',bytes:42962,
  source:'https://raw.githubusercontent.com/patrickdugan/zk-rusto-no-bitcoino/8c9d7ae/integrations/zklean-nova/corpus_import.cjs'};
const need=(ok,message)=>{if(!ok)throw Error(message);};
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const same=(a,b,label)=>assert.deepStrictEqual(a,b,label);
const memo=new Map();
function digest(file){const resolved=path.resolve(file);if(memo.has(resolved))return memo.get(resolved);
  const stat=fs.lstatSync(resolved);need(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=512*1024*1024,'bounded regular file: '+resolved);
  const h=crypto.createHash('sha256'),fd=fs.openSync(resolved,'r'),buf=Buffer.alloc(1048576);
  try{for(;;){const n=fs.readSync(fd,buf,0,buf.length,null);if(!n)break;h.update(buf.subarray(0,n));}}finally{fs.closeSync(fd);}
  const result={path:resolved,bytes:stat.size,sha256:h.digest('hex')};memo.set(resolved,result);return result;
}
function json(file){digest(file);return JSON.parse(fs.readFileSync(file,'utf8'));}
function* lines(file){const fd=fs.openSync(file,'r'),buf=Buffer.alloc(262144);let carry=Buffer.alloc(0);
  try{for(;;){const n=fs.readSync(fd,buf,0,buf.length,null);if(!n)break;
    const bytes=carry.length?Buffer.concat([carry,buf.subarray(0,n)]):buf.subarray(0,n);let start=0,end;
    while((end=bytes.indexOf(10,start))!==-1){let line=bytes.subarray(start,end);if(line.at(-1)===13)line=line.subarray(0,line.length-1);
      need(line.length<=64*1024*1024,'JSONL record limit');yield line.toString('utf8');start=end+1;}
    carry=Buffer.from(bytes.subarray(start));need(carry.length<=64*1024*1024,'JSONL record limit');
  }if(carry.length)yield carry.toString('utf8');}finally{fs.closeSync(fd);}
}
function declarationLine(file,number){let i=0;for(const line of lines(file))if(++i===number)return line;throw Error('source declaration line absent');}
function payloadMatches(actual,expected,label){same(actual.sha256,expected.sha256,label+' SHA256');same(actual.bytes,expected.bytes,label+' length');}
function sources(){const files={frontier:path.join(__dirname,'equality_frontier.cjs'),environment:path.join(__dirname,'equality_environment.cjs'),
  kernel:path.join(__dirname,'equality.cjs'),sample:path.join(__dirname,'equality_frontier_sample.json'),
  poseidon:path.join(__dirname,'../bitvm2-nova/fixtures/nht4-genesis-0-2020-k5.poseidon.json'),
  importer:path.join(__dirname,'corpus_import.cjs'),helper:__filename};
  const evidence=Object.fromEntries(Object.entries(files).map(([k,f])=>[k,digest(f)]));
  for(const k of Object.keys(PIN).filter(k=>k!=='matrix'))same(evidence[k].sha256,PIN[k],k+' source pin');
  return {files,evidence};
}
function loadArithmetic(file){const source=fs.readFileSync(file,'utf8'),marker="\nlet fixtures=JSON.parse(fs.readFileSync(path.join(__dirname,'equality_fixtures.json'),'utf8'));";
  const at=source.indexOf(marker);need(at>0&&source.indexOf(marker,at+1)===-1,'fixed-fixture CLI boundary');
  const prefix=source.slice(0,at);need(prefix.includes('function arithmetic(fixtures,profile,mode,sink,coverageFixture)'), 'arithmetic entry point');
  const m=new Module(file);m.filename=file;m.paths=Module._nodeModulePaths(path.dirname(file));
  m._compile(prefix+'\nmodule.exports={arithmetic};\n',file);
  return {arithmetic:m.exports.arithmetic,loaded_prefix_sha256:hash(prefix)};
}
function validateCertificate(record,importDir,sourcePins,kernel,selection){
  need(record.eligible_native_accepted===true&&record.native_certificate_accepted===true,'eligible native certificate required');
  for(const key of ['fresh_source_build','kernel_rechecked','safe_declaration','axiom_audit_complete','axiom_eligible'])same(record.eligibility[key],true,'eligibility '+key);
  same(record.eligibility.contains_sorry_ax,false,'sorry exclusion');same(record.eligibility.source_binding.verified,true,'source binding');
  need(/^[0-9a-f]{64}\.json$/.test(record.certificate.file),'certificate basename');
  const file=path.join(importDir,'certificates',record.certificate.file),info=digest(file);payloadMatches(info,record.certificate,'certificate');
  const cert=json(file);same(cert.schema,'zkl-nova-18/imported-native-certificate-v1','certificate schema');
  same(cert.name,record.name,'declaration name');same(cert.source,record.source,'declaration source');
  same(cert.raw_goal_sha256,record.original.raw_goal.sha256,'original goal');same(cert.raw_proof_sha256,record.original.raw_proof.sha256,'original proof');
  same(cert.goal,record.lowered_goal,'lowered goal');same(cert.proof,record.lowered_proof,'lowered proof');same(cert.lowerings,record.lowering.events,'recorded lowerings');
  need(Array.isArray(cert.rows)&&cert.rows.length>1&&cert.rows.length<20000,'native row count');
  same(cert.rows.length,record.native.rows,'native rows');same(cert.rows.length,record.certificate.rows,'certificate rows');
  same(record.native.current_arithmetic_capacity,cert.rows.length<1024,'strict arithmetic capacity');
  same(record.native.rows_le_1024,cert.rows.length<=1024,'nominal row capacity');
  const id=hash(JSON.stringify([record.lane,record.name,info.sha256]));
  const chosen=cert.rows.length<1024&&(!selection||selection.has(info.sha256));
  const targetInfo=digest(record.source.input.path);payloadMatches(targetInfo,record.source.input,'target export');
  if(chosen){const line=declarationLine(record.source.input.path,record.source.line);same(hash(line),record.source.line_sha256,'source declaration line hash');
    same(JSON.parse(line).name,record.name,'original declaration name');
    need(kernel.reference(cert.goal,['S',0])&&kernel.reference(cert.proof,cert.goal),'independent native reference');
    const replay=kernel.replay(cert.rows,cert.goal);need(replay.accepted,'native certificate replay');same(replay.proof,cert.proof,'native replay subject');}
  return {id,lane:record.lane,name:record.name,steps:cert.rows.length,
    source:{target_export:targetInfo,line:record.source.line,line_sha256:record.source.line_sha256,
      raw_goal_sha256:cert.raw_goal_sha256,raw_proof_sha256:cert.raw_proof_sha256,
      lowered_goal_sha256:record.lowered_goal_sha256,lowered_proof_sha256:record.lowered_proof_sha256},
    certificate:info,strict_whole_declaration_accepted:record.strict_whole_declaration_accepted,
    lowerings:cert.lowerings,eligibility:record.eligibility,native_rechecked_for_arithmetic:chosen,
    fixture:chosen?{name:'corpus_'+id,proof:cert.proof,goal:cert.goal,rows:cert.rows}:undefined};
}
function collect(root,pins,selection){const kernel=require('./equality.cjs'),candidates=[],groups=[],incomplete=[];
  const entries=fs.readdirSync(root,{withFileTypes:true}).filter(x=>x.isDirectory()&&!x.isSymbolicLink()).map(x=>x.name).sort();
  for(const lane of entries){const dir=path.join(root,lane,'import'),sf=path.join(dir,'summary.json'),rf=path.join(dir,'results.jsonl');
    if(!fs.existsSync(sf)||!fs.existsSync(rf)){incomplete.push(lane);continue;}
    const summary=json(sf);same(summary.schema,'zkl-nova-18/corpus-import-summary-v1','import summary schema');
    payloadMatches(digest(rf),summary.results_file,'import result set');
    for(const [key,pin] of [['kernel','kernel'],['fixed_environment','environment']])payloadMatches(pins[pin],summary.inputs[key],key+' version');
    const importer=summary.inputs.importer,allowed=[INITIAL_IMPORTER,pins.importer].find(p=>p.sha256===importer.sha256&&p.bytes===importer.bytes);
    need(allowed,'unreviewed importer source version');let eligible=0;
    for(const line of lines(rf)){if(!line)continue;const record=JSON.parse(line);if(record.eligible_native_accepted===true){eligible++;candidates.push(validateCertificate(record,dir,pins,kernel,selection));}}
    same(eligible,summary.counts.eligible_native_accepted,'eligible summary count');
    groups.push({lane,summary:digest(sf),results:digest(rf),eligible_native_certificates:eligible,source_build:summary.inputs.build_receipt,importer_source:importer});
  }
  need(new Set(candidates.map(c=>c.id)).size===candidates.length,'duplicate certificate identity');
  return {candidates,groups,incomplete};
}
function run(opts){const src=sources(),registration=opts.selection?json(opts.selection):null;
  if(registration){same(registration.schema,'zkl-nova-18/arithmetic-selection-v1','selection schema');need(Array.isArray(registration.certificates)&&registration.certificates.length>0,'registered certificates');}
  const selection=registration?new Set(registration.certificates.map(c=>c.sha256)):null;
  const found=collect(opts.imports,src.evidence,selection),eligible=found.candidates.filter(c=>c.steps<1024),excluded=found.candidates.filter(c=>c.steps>=1024);
  const selectedCandidates=eligible.filter(c=>!selection||selection.has(c.certificate.sha256));
  if(selection){same(selectedCandidates.length,selection.size,'all registered certificates found');for(const c of selectedCandidates){const declared=registration.certificates.find(x=>x.sha256===c.certificate.sha256);same(c.name,declared.name,'registered declaration');same(c.steps,declared.steps,'registered row count');}}
  const previous=fs.existsSync(opts.output)?json(opts.output):null,cache=new Map();
  if(previous){same(previous.schema,SCHEMA,'resume receipt schema');
    for(const key of ['frontier','environment','kernel','sample','poseidon','helper'])same(previous.sources[key],src.evidence[key],'resume source version '+key);
    if(previous.matrix)same(previous.matrix.sha256,PIN.matrix,'resume matrix pin');else same(previous.cases.length,0,'no checked cases without a matrix');
    for(const c of previous.cases){need(c.passed===true&&c.matrices_checked===c.steps,'resume checked case');cache.set(c.id,c);}}
  const pending=selectedCandidates.filter(c=>!cache.has(c.id)).sort((a,b)=>a.steps-b.steps||a.id.localeCompare(b.id)),selected=[];let selectedRows=0;
  for(const c of pending)if(selectedRows+c.steps<=opts.maxNewRows){selected.push(c);selectedRows+=c.steps;}
  let matrix=previous?.matrix||null,loadedPrefix=previous?.loaded_prefix_sha256||null,batch=null;
  if(selected.length){const loaded=loadArithmetic(src.files.frontier);loadedPrefix=loaded.loaded_prefix_sha256;
    const sample=json(src.files.sample),profile=json(src.files.poseidon).secondary.narrow,counts=new Map(),cases=new Map();
    const byAlias=new Map(selected.map(c=>[c.fixture.name,c]));let matrixCalls=0;
    const sink={matrix(value){matrixCalls++;same(value.schema,'zkl-nova-17/equality-frontier-v1','matrix schema');
        for(const [k,v] of Object.entries(value.summary))same(v,sample[k],'pinned matrix summary '+k);
        const h=crypto.createHash('sha256');let bytes=0;const add=s=>{h.update(s);bytes+=Buffer.byteLength(s);};
        add('{"schema":'+JSON.stringify(value.schema)+',"summary":'+JSON.stringify(value.summary)+',"rows":[');
        value.rows.forEach((row,i)=>{if(i)add(',');add(JSON.stringify(row));});add(']}');
        const actual=h.digest('hex');same(actual,PIN.matrix,'complete arithmetic matrix SHA256');
        matrix={sha256:actual,bytes,...value.summary};
        process.stderr.write(JSON.stringify({phase:'matrix_ready',cases:selected.length,rows:selectedRows,matrix_sha256:actual})+'\n');},
      step(name,index,witness){const c=byAlias.get(name);need(c,'unexpected witness case');const n=counts.get(name)||0;same(index,n,'ordered actual witness row');
        same(witness.length,matrix.wires,'witness arity');same(witness[0],1n,'constant wire');counts.set(name,n+1);},
      case(value){const c=byAlias.get(value.info.name);need(c,'unexpected case completion');same(value.info.steps,c.steps,'arithmetic steps');
        same(value.info.matrices_checked,c.steps,'all actual row assignments checked');same(counts.get(value.info.name),c.steps,'delivered checked witness count');
        same(value.info.goal,c.fixture.goal,'arithmetic goal');same(value.states.length,c.steps+1,'public state count');
        same(value.states[0],value.info.initial,'initial public state');same(value.states.at(-1),value.info.terminal,'terminal public state');
        same(value.info.initial[1],'0','initial transition count');same(value.info.terminal[1],String(c.steps),'terminal transition count');
        same(value.info.initial[3],'0','initial unsealed state');same(value.info.terminal[3],'1','terminal sealed state');
        cases.set(c.id,{...c,fixture:undefined,passed:true,arithmetic_status:'all_actual_rows_checked',matrices_checked:c.steps,
          public_state_sequence_sha256:hash(JSON.stringify(value.states)),arithmetic_case:value.info});
        process.stderr.write(JSON.stringify({phase:'case_checked',name:c.name,rows:c.steps})+'\n');}};
    const fixtures=selected.map(c=>c.fixture),control={...fixtures[0],name:'repeat_of_actual_case_for_coverage'};
    const started=process.hrtime.bigint();
    const result=loaded.arithmetic(fixtures,profile,'full',sink,control).summary;
    same(matrixCalls,1,'one shared matrix construction');same(result.mode,'full','full arithmetic mode');same(result.total_steps,selectedRows,'batch transition count');
    same(result.total_checked,selectedRows,'batch matrix checks');same(cases.size,selected.length,'completed case count');
    same(result.coverage.matrices_checked,0,'supplementary control repeats an already checked actual certificate');
    for(const c of cases.values())cache.set(c.id,c);
    batch={case_ids:selected.map(c=>c.id),cases:selected.length,rows:selectedRows,
      elapsed_seconds:Number(process.hrtime.bigint()-started)/1e9,
      max_rss_kib:process.resourceUsage().maxRSS,summary:result};
  }
  const checked=eligible.filter(c=>cache.has(c.id)).map(c=>cache.get(c.id)),waiting=eligible.filter(c=>!cache.has(c.id));
  const clean=c=>{const out={...c};delete out.fixture;return out;};
  const selectedWaiting=selectedCandidates.filter(c=>!cache.has(c.id));
  const receipt={schema:SCHEMA,passed:selectedWaiting.length===0,all_observed_in_capacity_cases_checked:waiting.length===0,
    scope:'Full authenticated R1CS assignment evaluation for actual source-bound native certificates observed in completed importer groups.',
    nova_proofs_generated:0,coverage_scope:'Completed importer groups observed at this invocation; export sweep completion is reported separately.',
    export_sweep_complete:opts.complete&&found.incomplete.length===0,source_export_root:path.resolve(opts.imports),sources:src.evidence,
    reviewed_initial_importer:INITIAL_IMPORTER,
    preregistered_selection:registration?{manifest:digest(opts.selection),...registration}:null,
    loaded_prefix_sha256:loadedPrefix,matrix,observed_groups:found.groups,incomplete_import_groups:found.incomplete,
    totals:{eligible_native_certificates:found.candidates.length,in_capacity_certificates:eligible.length,
      actually_arithmetic_checked:checked.length,actual_arithmetic_row_checks:checked.reduce((s,c)=>s+c.steps,0),
      selected_arithmetic_candidates:selectedCandidates.length,capacity_only_not_selected:eligible.length-selectedCandidates.length,
      capacity_excluded:excluded.length,pending_arithmetic_checks:waiting.length},
    capacity_policy:{nominal_rows_le:1024,current_generator_rows_strictly_less_than:1024},
    cases:checked,capacity_excluded:excluded.map(c=>({...clean(c),arithmetic_status:'not_checked_exceeds_current_row_capacity'})),
    pending:waiting.map(c=>({...clean(c),arithmetic_status:selection&&!selection.has(c.certificate.sha256)?'capacity_only_outside_preregistered_selection':'capacity_only_pending_row_budget'})),
    batches:[...(previous?.batches||[]),...(batch?[batch]:[])]};
  fs.mkdirSync(path.dirname(path.resolve(opts.output)),{recursive:true});fs.writeFileSync(opts.output,JSON.stringify(receipt,null,2)+'\n');
  return receipt;
}
function cli(args){const opts={maxNewRows:10000,complete:false};for(let i=0;i<args.length;i++){const a=args[i];
    if(a==='--complete'){opts.complete=true;continue;}
    const key={'--imports':'imports','--output':'output','--max-new-rows':'maxNewRows','--selection':'selection'}[a];need(key&&i+1<args.length,'usage: measured_arithmetic.cjs --imports EXPORT_ROOT --output RECEIPT.json [--selection MANIFEST.json] [--max-new-rows N] [--complete]');opts[key]=args[++i];}
  need(opts.imports&&opts.output,'--imports and --output are required');opts.maxNewRows=Number(opts.maxNewRows);
  need(Number.isSafeInteger(opts.maxNewRows)&&opts.maxNewRows>=0&&opts.maxNewRows<=100000,'bounded new-row budget');return opts;
}
if(require.main===module){try{const r=run(cli(process.argv.slice(2)));process.stdout.write(JSON.stringify({schema:r.schema,passed:r.passed,export_sweep_complete:r.export_sweep_complete,totals:r.totals,matrix_sha256:r.matrix?.sha256,nova_proofs_generated:0},null,2)+'\n');}
  catch(e){process.stderr.write('corpus arithmetic: '+e.message+'\n');process.exitCode=1;}}
module.exports={run,collect,validateCertificate,loadArithmetic,PIN};
