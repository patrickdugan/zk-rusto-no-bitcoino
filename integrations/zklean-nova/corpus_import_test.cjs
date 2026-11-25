// Unit fixtures exercise the importer only; they are excluded from corpus data.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const I=require('./corpus_import.cjs');
const limits={...I.DEFAULTS},build={status:'passed',exit_code:0,lane:'synthetic_unit_test',requested_modules:['SyntheticUnitTest'],
  source_files:[{path:'synthetic-unit-fixture',module:'SyntheticUnitTest',sha256:'0'.repeat(64)}]};
const provenance={module:'SyntheticUnitTest',unsafe:false,partial:false,kernel_check:{status:'passed'},
  axiom_dependencies:{status:'complete',axioms:[],pending_queue_entries:0,missing_constants:[],resource_limited_edges:0,contains_sorry_ax:false}};
const G=['forall',['sort',0],['forall',['bvar',0],['bvar',1]]];
const P=['lam',['sort',0],['lam',['bvar',0],['bvar',0]]];
function record(name,goal,proof,extra={}){
 const expr_nodes=[],level_nodes=[],levels=new Map();
 const level=n=>{if(levels.has(n))return levels.get(n);let node;if(typeof n==='string')node={tag:'param',name:n};else node=n===0?{tag:'zero'}:{tag:'succ',of:level(n-1)};const i=level_nodes.length;level_nodes.push(node);levels.set(n,i);return i};
 function expr(t){const [tag,a,b,c]=t;let node={tag};
  if(tag==='sort')node.level=level(a);else if(tag==='bvar')node.index=a;
  else if(tag==='const'){node.name=a;node.levels=(b||[]).map(level);node.name_parts=a.split('.').map(value=>({kind:'string',value}));}
  else if(tag==='app'){node.fn=expr(a);node.arg=expr(b);}
  else if(tag==='lam'||tag==='forall'){node.name='x';node.binder_info='default';node.type=expr(a);node.body=expr(b);}
  else if(tag==='let'){node.name='x';node.type=expr(a);node.value=expr(b);node.body=expr(c);node.non_dep=false;}
  else if(tag==='mdata'){node.expr=expr(a);node.metadata=[];}
  else if(tag==='lit'){node.literal_kind='nat';node.value=String(a);}
  else if(tag==='proj'){node.type_name=a;node.index=b;node.expr=expr(c);}
  else if(tag==='fvar'||tag==='mvar')node.name=a;
  else throw Error(tag);
  const i=expr_nodes.length;expr_nodes.push(node);return i;
 }
 const type_root=expr(goal),proof_root=proof===null?null:expr(proof);
 return {schema:'zkl-nova-18/lean-expr-v1',name,kind:'theorem',role:'target',status:'ok',safety:'safe',is_proof:true,
  level_params:[],expr_nodes,level_nodes,type_root,proof_root,constants:[],provenance:structuredClone(provenance),...extra};
}
const source={input:{path:'synthetic-unit-fixture',sha256:'1'.repeat(64)},line:1,line_sha256:'2'.repeat(64)};
function dependencies(...rs){return new Map(rs.map(r=>[r.name,{record:{...r,role:'dependency'},source}]));}
function analyze(r,deps=new Map(),b=build,l=limits){return I.analyze(r,source,{deps,limits:l,build:b,budget:{used:0},lane:'synthetic_unit_test'});}
function lower(r,deps=new Map(),b=build,l=limits){I.assertDag(r,l);return I.lower(r,deps,l,I.bindBuild(r,b,{lane:'synthetic_unit_test'}));}
const passed=[];async function test(name,fn){await fn();passed.push(name);}
(async()=>{
 await test('closed Prop identity passes independent reference and replay',()=>{const r=analyze(record('Synthetic.id',G,P));assert.equal(r.native_certificate_accepted,true);assert.equal(r.strict_whole_declaration_accepted,true);assert.equal(r.native.current_arithmetic_capacity,true);assert.ok(r.certificate.rows>0);});
 await test('metadata lowering remains separate from strict coverage',()=>{const r=analyze(record('Synthetic.meta',G,['mdata',P]));assert.equal(r.transparent_lowering_accepted,true);assert.equal(r.strict_whole_declaration_accepted,false);assert.ok(r.original_blockers.includes('metadata_erasure'));});
 await test('let substitution avoids capture under a new binder',()=>{
  const goal=['forall',['sort',0],['forall',['bvar',0],['forall',['bvar',1],['bvar',2]]]];
  const proof=['lam',['sort',0],['lam',['bvar',0],['let',['bvar',1],['bvar',0],['lam',['bvar',2],['bvar',1]]]]];
  const r=analyze(record('Synthetic.capture',goal,proof));assert.equal(r.native_certificate_accepted,true);
  assert.deepEqual(r.lowered_proof,['L',['S',0],['L',['B',0],['L',['B',1],['B',1]]]]);
 });
 await test('dead let values stay in original feature counts',()=>{const r=analyze(record('Synthetic.dead',G,['let',['const','Bool'],['const','Bool.true'],P]));assert.equal(r.native_certificate_accepted,true);assert.ok(r.original_blockers.includes('unknown_constant'));assert.equal(r.remaining_blockers.length,0);assert.equal(r.lowering.events[0].unused_value_erased,true);});
 await test('symbolic theorem parameters never become closed-instance success',()=>{const r=analyze(record('Synthetic.poly',G,P,{level_params:['u']}));assert.equal(r.native_certificate_accepted,false);assert.ok(r.remaining_blockers.includes('symbolic_universe'));});
 await test('primitive Nat signature is compared to fixed ENV',()=>{const nat=record('Nat',['sort',1],null,{kind:'inductive',is_proof:false});const r=lower(record('Synthetic.nat',['const','Nat'],['const','Nat']),dependencies(nat));assert.deepEqual(r.goal,['C',0]);assert.equal(r.representable,true);});
 await test('changed primitive signature is rejected',()=>{const nat=record('Nat',['sort',0],null,{kind:'inductive',is_proof:false});const r=lower(record('Synthetic.nat',['const','Nat'],['const','Nat']),dependencies(nat));assert.ok(r.blockers.includes('primitive_signature_mismatch'));});
 await test('primitive Name components cannot alias another Lean name',()=>{const r=record('Synthetic.nat',['const','Nat'],['const','Nat']);r.expr_nodes[0].name_parts=[{kind:'string',value:'Different'}];assert.throws(()=>I.assertDag(r,limits),/Name components/);});
 await test('Eq carrier universe is checked through the exact signature',()=>{const eq=record('Eq',['forall',['sort','u'],['forall',['bvar',0],['forall',['bvar',1],['sort',0]]]],null,{kind:'inductive',is_proof:false,level_params:['u']});
  assert.equal(lower(record('Synthetic.eq',['const','Eq',[1]],['const','Eq',[1]]),dependencies(eq)).representable,true);
  assert.ok(lower(record('Synthetic.eq',['const','Eq',[0]],['const','Eq',[0]]),dependencies(eq)).blockers.includes('unsupported_universe_instance'));
 });
 await test('bounded Nat literal lowering validates constructor signatures',()=>{
  const nat=record('Nat',['sort',1],null,{kind:'inductive',is_proof:false}),zero=record('Nat.zero',['const','Nat'],null,{kind:'constructor',is_proof:false}),succ=record('Nat.succ',['forall',['const','Nat'],['const','Nat']],null,{kind:'constructor',is_proof:false});
  const deps=dependencies(nat,zero,succ),r=lower(record('Synthetic.literal',['const','Nat'],['lit',2]),deps);assert.deepEqual(r.proof,['A',['C',2],['A',['C',2],['C',1]]]);
  assert.ok(lower(record('Synthetic.large',['const','Nat'],['lit',33]),deps).blockers.includes('nat_literal_limit'));
 });
 await test('closed definition expansion still requires native checking',()=>{const def=record('Synthetic.alias',G,P,{kind:'definition'});const r=analyze(record('Synthetic.use',G,['const','Synthetic.alias']),dependencies(def));assert.equal(r.native_certificate_accepted,true);assert.equal(r.strict_whole_declaration_accepted,false);assert.equal(r.transparent_lowering_accepted,true);});
 await test('definition expansion needs successful source evidence',()=>{const def=record('Synthetic.alias',G,P,{kind:'definition'});assert.ok(lower(record('Synthetic.use',G,['const','Synthetic.alias']),dependencies(def),null).blockers.includes('missing_build_evidence'));});
 await test('theorem bodies do not silently expand as definitions',()=>{const def=record('Synthetic.alias',G,P);assert.ok(lower(record('Synthetic.use',G,['const','Synthetic.alias']),dependencies(def)).blockers.includes('unknown_constant'));});
 await test('recursive definition closure is bounded',()=>{const def=record('Synthetic.loop',G,['const','Synthetic.loop'],{kind:'definition'});assert.ok(lower(record('Synthetic.use',G,['const','Synthetic.loop']),dependencies(def)).blockers.includes('definition_cycle'));});
 await test('unsupported features use multiple labels',()=>{const r=record('Synthetic.features',['const','Quot'],['proj','Structure',0,['mvar','m']]);r.constants=[{name:'Quot',kind:'quotient'}];const s=I.scan(r,new Map(),limits);for(const f of ['unknown_constant','quotient','projection','metavariable'])assert.ok(s.features.includes(f));});
 await test('DAG cycles and forward references fail closed',()=>{const r=record('Synthetic.id',G,P);r.expr_nodes[0]={tag:'app',fn:0,arg:0};assert.throws(()=>I.assertDag(r,limits),/precede parent/);});
 await test('200k bounded nodes use iterative depth maxima',()=>{const r=record('Synthetic.large',G,P);r.expr_nodes=Array.from({length:200000},()=>({tag:'sort',level:0}));r.type_root=199998;r.proof_root=199999;assert.equal(I.assertDag(r,limits).max_expr_depth,1);});
 await test('native acceptance does not override transitive axiom policy',()=>{const r=record('Synthetic.axiom',G,P);r.provenance.axiom_dependencies.axioms=['Classical.choice'];const a=analyze(r);assert.equal(a.native_certificate_accepted,true);assert.equal(a.eligible_native_accepted,false);const s=I.summarize([a],{limits});assert.equal(s.transitive_axioms.declaration_histogram['Classical.choice'],1);});
 await test('a reference type mismatch cannot produce native success',()=>{const r=analyze(record('Synthetic.bad',G,['sort',0]));assert.equal(r.representable,true);assert.equal(r.native_certificate_accepted,false);assert.ok(r.remaining_blockers.includes('native_reference_rejection'));});
 await test('native row resource limits remain distinct from typing',()=>{const r=analyze(record('Synthetic.small',G,P),new Map(),build,{...limits,nativeRows:2});assert.equal(r.native.reference_accepted,true);assert.equal(r.native_certificate_accepted,false);assert.ok(r.remaining_blockers.includes('native_resource_limit'));});
 await test('missing axiom audit fields fail closed',()=>{const r=record('Synthetic.audit',G,P);r.provenance.axiom_dependencies={status:'complete'};const a=analyze(r);assert.equal(a.native_certificate_accepted,true);assert.equal(a.eligibility.axiom_eligible,false);assert.equal(a.eligible_native_accepted,false);});
 await test('resource-limited axiom edges prevent eligibility',()=>{const r=record('Synthetic.audit',G,P);r.provenance.axiom_dependencies.resource_limited_edges=1;assert.equal(analyze(r).eligibility.axiom_eligible,false);});
 await test('unsafe provenance cannot be masked by safety safe',()=>{const r=record('Synthetic.safety',G,P);r.provenance.unsafe=true;assert.equal(analyze(r).eligibility.safe_declaration,false);});
 await test('native proof classification independently checks Prop',()=>{const r=I.nativeWorker({proof:['C',1],goal:['C',0],limits});assert.equal(r.native_certificate_accepted,false);assert.equal(r.goal_is_prop,false);assert.ok(r.blockers.includes('proof_classification_mismatch'));});
 await test('another lane or module cannot confer source eligibility',()=>{const r=record('Synthetic.owner',G,P);assert.equal(analyze(r,new Map(),{...build,lane:'other'}).eligibility.fresh_source_build,false);assert.equal(analyze(r,new Map(),{...build,source_files:[{...build.source_files[0],module:'OtherModule'}]}).eligibility.fresh_source_build,false);});
 await test('fixed cohort binds every source pin and selected name',()=>{const r=record('Synthetic.owner',G,P),receipt={...build,selected_names:[r.name]},cohortLane={id:build.lane,modules:build.requested_modules,names:[r.name],source_files:build.source_files};
  const run=b=>I.analyze(r,source,{deps:new Map(),limits,build:b,budget:{used:0},lane:build.lane,cohortLane});
  assert.equal(run(receipt).eligibility.fresh_source_build,true);
  assert.equal(run({...receipt,source_files:[{...receipt.source_files[0],sha256:'9'.repeat(64)}]}).eligibility.fresh_source_build,false);
  assert.equal(run({...receipt,selected_names:['Other.name']}).eligibility.fresh_source_build,false);
 });
 await test('non-object JSON records retain failed candidate coverage',async()=>{const dir=fs.mkdtempSync(path.join(os.tmpdir(),'corpus-import-malformed-'));try{const input=path.join(dir,'input.jsonl'),receipt=path.join(dir,'build.json');fs.writeFileSync(input,'null\n[]\n42\n');fs.writeFileSync(receipt,JSON.stringify({...build,selected_names:['Synthetic.missing']}));const result=await I.importCorpus({input,buildReceipt:receipt,output:path.join(dir,'out'),lane:build.lane,limits});assert.equal(result.input_errors.length,3);assert.equal(result.denominators.selected_inventory_candidates,1);assert.equal(result.missing_candidates.length,1);assert.equal(result.scan_complete,false);}finally{fs.rmSync(dir,{recursive:true,force:true});}});
 await test('failed cohort retains all 511 selected theorem candidates',async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'corpus-import-unit-'));try{
   const cohort={schema:'synthetic-unit-cohort',source:{classification:'unit test only'},lanes:[{id:'a',names:Array.from({length:161},(_,i)=>'A.t'+i)},{id:'b',names:Array.from({length:350},(_,i)=>'B.t'+i)}]};
   const cohortFile=path.join(dir,'cohort.json');fs.writeFileSync(cohortFile,JSON.stringify(cohort));const dirs=[];
   for(const lane of cohort.lanes){const receipt=path.join(dir,lane.id+'.json');fs.writeFileSync(receipt,JSON.stringify({status:'failed',exit_code:1,selected_names:lane.names}));const out=path.join(dir,lane.id);dirs.push(out);await I.importCorpus({output:out,cohort:cohortFile,buildReceipt:receipt,lane:lane.id,limits});}
   const agg=I.aggregate({cohort:cohortFile,inputs:dirs,output:path.join(dir,'aggregate.json')});assert.equal(agg.denominators.selected_inventory_candidates,511);assert.equal(agg.denominators.unclassified_candidates,511);assert.equal(agg.counts.native_certificate_accepted,0);assert.equal(agg.missing_candidates.length,511);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
 });
 console.log(JSON.stringify({schema:'zkl-nova-18/importer-unit-tests-v1',passed:true,tests:passed.length,test_names:passed,corpus_observations:0,fixture_scope:'synthetic implementation tests only'},null,2));
})().catch(e=>{console.error(e);process.exitCode=1;});
