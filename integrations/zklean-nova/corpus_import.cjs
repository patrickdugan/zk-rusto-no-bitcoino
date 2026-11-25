// ZKL-NOVA-18: bounded import of actual Lean Expr exports into the fixed kernel.
// Source inventory, source eligibility, representation and native acceptance
// have separate denominators. The importer does not extend the 30-rule relation.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const readline = require('node:readline');
const {spawnSync} = require('node:child_process');

const IR = 'zkl-nova-18/lean-expr-v1';
const RESULT = 'zkl-nova-18/corpus-import-result-v1';
const SUMMARY = 'zkl-nova-18/corpus-import-summary-v1';
const BOUND_BUILD = Symbol('verified source receipt binding');
const FIXED = Object.freeze({Nat:[0], 'Nat.zero':[1], 'Nat.succ':[2], 'Nat.rec':[3,4,5], Eq:[6], 'Eq.refl':[7], 'Eq.rec':[8,9,10]});
const DEFAULTS = Object.freeze({fileBytes:536870912, recordBytes:67108864, records:100000,
  exprNodes:200000, levelNodes:20000, rawDepth:256, lowerSteps:200000,
  termNodes:10000, termDepth:72, natLiteral:32, expansionDepth:16,
  dependencyNodes:2000000, nativeRows:20000, nativeMs:3000,
  nativeTotalMs:120000, nativeMemoryMb:384, goalSnapshotBytes:1048576});
const BLOCKERS = ['unknown_constant','unsupported_inductive','unsupported_constructor',
  'unsupported_recursor','quotient','projection','proof_irrelevance','eta',
  'propositional_extensionality','function_extensionality','axiom',
  'symbolic_universe','universe_metavariable','universe_level_limit',
  'unsupported_universe_instance','missing_primitive_signature','primitive_signature_mismatch',
  'free_variable','metavariable','open_expression','unsupported_literal','string_literal',
  'nat_literal_lowering','nat_literal_limit','let_lowering','metadata_erasure',
  'definition_expansion','definition_unavailable','definition_not_closed','definition_cycle',
  'unsafe_or_partial','missing_build_evidence','missing_kernel_check','sorry_axiom',
  'incomplete_axiom_audit','source_axioms','resource_limit','invalid_ir',
  'unsupported_expression','source_build_failure','export_failure','not_exported',
  'native_reference_rejection','certificate_generation_failure','certificate_replay_rejection',
  'unresolved_conversion','native_resource_limit','native_budget_exhausted','proof_classification_mismatch'];
const EXPR_CHILDREN = {bvar:[],sort:[],const:[],app:['fn','arg'],lam:['type','body'],
  forall:['type','body'],let:['type','value','body'],lit:[],proj:['expr'],mdata:['expr'],fvar:[],mvar:[]};
const LEVEL_CHILDREN = {zero:[],succ:['of'],param:[],max:['left','right'],imax:['left','right'],mvar:[]};
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const stable = value => JSON.stringify(value);
const same = (a,b) => stable(a) === stable(b);
const ensure = (ok,message) => { if (!ok) throw Error(message); };
const isInt = n => Number.isSafeInteger(n) && n >= 0;
const bump = (o,k,n=1) => { o[k]=(o[k]||0)+n; };
const sorted = xs => [...xs].sort();
const unique = xs => [...new Set(xs)];
const sum = xs => xs.reduce((a,b)=>a+b,0);
function fileInfo(file,max=DEFAULTS.fileBytes) {
  const s=fs.statSync(file); ensure(s.isFile()&&s.size<=max,`file resource limit: ${file}`);
  const h=crypto.createHash('sha256'),fd=fs.openSync(file,'r'),buf=Buffer.alloc(1048576);
  try { for(;;){const n=fs.readSync(fd,buf,0,buf.length,null);if(!n)break;h.update(buf.subarray(0,n));} }
  finally {fs.closeSync(fd);}
  return {path:path.resolve(file),bytes:s.size,sha256:h.digest('hex')};
}
function readJson(file) {if(!file)return null;fileInfo(file);return JSON.parse(fs.readFileSync(file,'utf8'));}
async function readLines(file,limits,callback) {
  const info=fileInfo(file,limits.fileBytes);let number=0,complete=true;
  const input=fs.createReadStream(file,{encoding:'utf8'}),lines=readline.createInterface({input,crlfDelay:Infinity});
  try {for await(const line of lines){number++;if(number>limits.records){complete=false;break;}
    const evidence={input:info,line:number,line_sha256:sha(line),line_bytes:Buffer.byteLength(line)};
    if(evidence.line_bytes>limits.recordBytes){await callback(null,evidence,'record_bytes_limit');continue;}
    if(line.trim()===''){await callback(null,evidence,'empty_record');continue;}
    let record;try{record=JSON.parse(line);}catch(e){await callback(null,evidence,'invalid_json: '+e.message);continue;}
    await callback(record,evidence,null);
  }} finally {lines.close();input.destroy();}
  return {file:info,lines_seen:Math.min(number,limits.records),complete};
}
function assertDag(record,limits) {
  ensure(record&&record.schema===IR,'IR schema');
  ensure(typeof record.name==='string'&&record.name.length>0&&record.name.length<8192,'declaration name');
  if(Object.hasOwn(FIXED,record.name)&&record.name_parts)ensure(same(record.name_parts,record.name.split('.').map(value=>({kind:'string',value}))),'primitive declaration Name components');
  ensure(['target','dependency'].includes(record.role),'declaration role');
  ensure(record.is_proof===true||record.is_proof===false||record.is_proof===null,'proof classification field');
  ensure(Array.isArray(record.level_params)&&record.level_params.every(x=>typeof x==='string'),'universe parameters');
  ensure(unique(record.level_params).length===record.level_params.length,'duplicate universe parameter');
  ensure(Array.isArray(record.expr_nodes)&&record.expr_nodes.length<=limits.exprNodes,'expression node limit');
  ensure(Array.isArray(record.level_nodes)&&record.level_nodes.length<=limits.levelNodes,'level node limit');
  const expr=record.expr_nodes,levels=record.level_nodes,ed=[],ld=[];
  const ref=(x,n,label)=>ensure(isInt(x)&&x<n,label);
  levels.forEach((node,i)=>{ensure(node&&Object.hasOwn(LEVEL_CHILDREN,node.tag),'unknown level tag');
    for(const k of LEVEL_CHILDREN[node.tag])ref(node[k],i,'level references must precede parent');
    if(node.tag==='param'||node.tag==='mvar')ensure(typeof node.name==='string','level name');
    ld[i]=1+Math.max(0,...LEVEL_CHILDREN[node.tag].map(k=>ld[node[k]]));
  });
  expr.forEach((node,i)=>{ensure(node&&Object.hasOwn(EXPR_CHILDREN,node.tag),'unknown expression tag');
    for(const k of EXPR_CHILDREN[node.tag])ref(node[k],i,'expression references must precede parent');
    if(node.tag==='sort')ref(node.level,levels.length,'sort level');
    if(node.tag==='const'){ensure(typeof node.name==='string'&&Array.isArray(node.levels)&&node.levels.length<=64,'constant fields');node.levels.forEach(x=>ref(x,levels.length,'constant level'));
      if(Object.hasOwn(FIXED,node.name)&&node.name_parts)ensure(same(node.name_parts,node.name.split('.').map(value=>({kind:'string',value}))),'primitive constant Name components');}
    if(node.tag==='bvar')ensure(isInt(node.index),'bound variable index');
    if(node.tag==='proj')ensure(typeof node.type_name==='string'&&isInt(node.index),'projection fields');
    if(node.tag==='lit')ensure(['nat','string'].includes(node.literal_kind)&&typeof node.value==='string','literal fields');
    if(node.tag==='fvar'||node.tag==='mvar')ensure(typeof node.name==='string','variable name');
    ed[i]=1+Math.max(0,...EXPR_CHILDREN[node.tag].map(k=>ed[node[k]]));
  });
  ref(record.type_root,expr.length,'type root');
  if(record.proof_root!==null)ref(record.proof_root,expr.length,'proof root');
  return {max_expr_depth:ed.reduce((m,x)=>Math.max(m,x),0),max_level_depth:ld.reduce((m,x)=>Math.max(m,x),0)};
}
function reachable(record,roots) {
  const expr=new Set(),levels=new Set(),stack=roots.filter(x=>x!==null&&x!==undefined);
  while(stack.length){const i=stack.pop();if(expr.has(i))continue;expr.add(i);const n=record.expr_nodes[i];
    for(const k of EXPR_CHILDREN[n.tag]||[])stack.push(n[k]);
    if(n.tag==='sort')levels.add(n.level);if(n.tag==='const')n.levels.forEach(x=>levels.add(x));
  }
  const todo=[...levels];while(todo.length){const i=todo.pop(),n=record.level_nodes[i];for(const k of LEVEL_CHILDREN[n.tag]||[]){if(!levels.has(n[k])){levels.add(n[k]);todo.push(n[k]);}}}
  return {expr:sorted([...expr]).map(Number).sort((a,b)=>a-b),levels:[...levels].sort((a,b)=>a-b)};
}
function rawView(record,root,limits,includeSnapshot=false) {
  if(root===null)return null;const r=reachable(record,[root]);
  const value={root,expr_nodes:r.expr.map(id=>({id,node:record.expr_nodes[id]})),level_nodes:r.levels.map(id=>({id,node:record.level_nodes[id]}))};
  const encoded=stable(value),out={root,sha256:sha(encoded),expression_nodes:r.expr.length,level_nodes:r.levels.length};
  if(includeSnapshot&&Buffer.byteLength(encoded)<=limits.goalSnapshotBytes)out.snapshot=value;
  return out;
}
function constantKind(record,name,deps) {
  return record.constants?.find(c=>c.name===name)?.kind||deps.get(name)?.record.kind||'unknown';
}
function constantFeatures(name,kind) {
  const out=[];if(Object.hasOwn(FIXED,name))return out;
  out.push('unknown_constant');
  if(kind==='inductive')out.push('unsupported_inductive');
  if(kind==='constructor')out.push('unsupported_constructor','unsupported_inductive');
  if(kind==='recursor')out.push('unsupported_recursor','unsupported_inductive');
  if(kind==='quotient'||/^Quot(?:\.|$)/.test(name))out.push('quotient');
  if(kind==='axiom')out.push('axiom');
  if(name==='proof_irrelheq'||name==='proof_irrel')out.push('proof_irrelevance');
  if(name==='propext')out.push('propositional_extensionality');
  if(name==='funext')out.push('function_extensionality');
  if(kind==='definition')out.push('definition_expansion');
  return unique(out);
}
function scan(record,deps,limits) {
  const seen=reachable(record,[record.type_root,record.proof_root]),exprTags={},levelTags={},constants={},features=new Set();
  const goal=reachable(record,[record.type_root]),proof=reachable(record,[record.proof_root]);
  for(const i of seen.expr){const n=record.expr_nodes[i];bump(exprTags,n.tag);
    if(n.tag==='const'){const kind=constantKind(record,n.name,deps);bump(constants,n.name);constantFeatures(n.name,kind).forEach(x=>features.add(x));}
    if(n.tag==='proj')features.add('projection');
    if(n.tag==='fvar')features.add('free_variable');if(n.tag==='mvar')features.add('metavariable');
    if(n.tag==='let')features.add('let_lowering');if(n.tag==='mdata')features.add('metadata_erasure');
    if(n.tag==='lit'){if(n.literal_kind==='string'){features.add('unsupported_literal');features.add('string_literal');}
      else{features.add('nat_literal_lowering');if(!/^(0|[1-9][0-9]*)$/.test(n.value)||n.value.length>12||BigInt(n.value)>BigInt(limits.natLiteral))features.add('nat_literal_limit');}}
  }
  for(const i of seen.levels){const n=record.level_nodes[i];bump(levelTags,n.tag);if(n.tag==='param')features.add('symbolic_universe');if(n.tag==='mvar')features.add('universe_metavariable');}
  if(record.level_params.length)features.add('symbolic_universe');
  for(const diagnostic of record.diagnostics||[])if(diagnostic&&diagnostic.required===true&&['eta','proof_irrelevance'].includes(diagnostic.feature))features.add(diagnostic.feature);
  return {expression_nodes:seen.expr.length,level_nodes:seen.levels.length,goal_expression_nodes:goal.expr.length,
    proof_expression_nodes:proof.expr.length,expression_tags:exprTags,level_tags:levelTags,constant_occurrences:constants,features:sorted(features)};
}
function safeDeclaration(r) {return (!r.safety||r.safety==='safe')&&r.provenance?.unsafe===false&&r.provenance?.partial===false;}
function buildFormat(build) {return build?.status==='passed'&&build.exit_code===0&&Array.isArray(build.source_files)&&build.source_files.length>0&&build.source_files.every(f=>typeof f.path==='string'&&typeof f.sha256==='string'&&/^[a-f0-9]{64}$/.test(f.sha256));}
function buildEligible(build) {return buildFormat(build)&&build[BOUND_BUILD]===true;}
function bindBuild(record,build,scope={}) {
  const reasons=[],module=record.provenance?.module,cohort=scope.cohortLane;
  if(!buildFormat(build))reasons.push('missing_or_failed_build_receipt');
  if(typeof module!=='string'||!module)reasons.push('missing_declaration_module');
  if(build?.lane&&scope.lane&&build.lane!==scope.lane)reasons.push('build_lane_mismatch');
  if(!Array.isArray(build?.requested_modules)||!build.requested_modules.includes(module))reasons.push('defining_module_not_built');
  if(Array.isArray(build?.selected_names)&&build.selected_names.length&&!build.selected_names.includes(record.name))reasons.push('declaration_not_in_build_selection');
  const tuples=xs=>sorted(xs.map(x=>stable([x.path,x.sha256])));
  if(cohort){
    if(build?.lane!==cohort.id)reasons.push('cohort_lane_mismatch');
    if(!same(sorted(build?.requested_modules||[]),sorted(cohort.modules||[])))reasons.push('cohort_modules_mismatch');
    if(!same(sorted(build?.selected_names||[]),sorted(cohort.names||[])))reasons.push('cohort_selection_mismatch');
    if(!Array.isArray(cohort.source_files)||!same(tuples(build?.source_files||[]),tuples(cohort.source_files)))reasons.push('cohort_source_pins_mismatch');
    if(!(cohort.source_files||[]).some(f=>f.module===module))reasons.push('defining_module_missing_from_cohort_sources');
  }else if(!(build?.source_files||[]).some(f=>f.module===module))reasons.push('defining_module_missing_from_build_sources');
  const bound={...(build||{}),import_source_binding:{verified:reasons.length===0,mode:cohort?'fixed_cohort_source_pins':'receipt_module_source_join',declaration:record.name,module,reasons}};
  Object.defineProperty(bound,BOUND_BUILD,{value:reasons.length===0});return bound;
}
function lower(record,deps,limits,build) {
  const kernel=require('./equality.cjs'),blockers=new Set(),details=[],events=new Map(),sizes=new WeakMap(),cache=new Map(),active=new Set();let steps=0;
  const fail=(tag,detail)=>{blockers.add(tag);if(details.length<200)details.push({tag,...detail});return null;};
  const tick=()=>{if(++steps>limits.lowerSteps){blockers.add('resource_limit');throw Error('lowering operation limit');}};
  const event=(r,id,kind,extra={})=>{const key=stable([r.name,id,kind,extra]);if(events.has(key))events.get(key).occurrences++;else events.set(key,{declaration:r.name,node_id:id,kind,...extra,occurrences:1});};
  function term(tag,a,b){tick();if(a===null||b===null)return null;const t=b===undefined?[tag,a]:[tag,a,b];
    const sa=Array.isArray(a)?sizes.get(a):null,sb=Array.isArray(b)?sizes.get(b):null;
    const info={nodes:1+(sa?.nodes||0)+(sb?.nodes||0),depth:1+Math.max(sa?.depth||0,sb?.depth||0)};
    if(info.nodes>limits.termNodes||info.depth>limits.termDepth){fail('resource_limit',{reason:'lowered_term_size_or_depth',...info});return null;}
    sizes.set(t,info);return t;
  }
  function shift(t,amount,cutoff=0){tick();if(!t||amount===0)return t;
    if(t[0]==='B'){const i=t[1]>=cutoff?t[1]+amount:t[1];if(i>255)return fail('resource_limit',{reason:'bound_index',index:i});return term('B',i);}
    if(!['A','P','L'].includes(t[0]))return t;
    return term(t[0],shift(t[1],amount,cutoff),shift(t[2],amount,cutoff+(t[0]==='P'||t[0]==='L'?1:0)));
  }
  function level(r,id,env,memo=new Map()){tick();if(memo.has(id))return memo.get(id);const n=r.level_nodes[id];let v;
    if(n.tag==='zero')v=0;
    else if(n.tag==='param'){if(env.has(n.name))v=env.get(n.name);else v=fail('symbolic_universe',{declaration:r.name,parameter:n.name});}
    else if(n.tag==='mvar')v=fail('universe_metavariable',{declaration:r.name,name:n.name});
    else if(n.tag==='succ'){const x=level(r,n.of,env,memo);v=x===null?null:x+1;}
    else{const a=level(r,n.left,env,memo),b=level(r,n.right,env,memo);v=a===null||b===null?null:n.tag==='imax'&&b===0?0:Math.max(a,b);}
    if(v!==null&&v>8)v=fail('universe_level_limit',{declaration:r.name,value:v});memo.set(id,v);return v;
  }
  function constant(r,id,node,env,expansionDepth){
    const levels=node.levels.map(x=>level(r,x,env)),kind=constantKind(r,node.name,deps);
    if(levels.some(x=>x===null))return null;
    const key=stable([node.name,levels]);if(cache.has(key))return cache.get(key);
    const dep=deps.get(node.name)?.record;
    if(!dep||dep.status!=='ok'){constantFeatures(node.name,kind).forEach(x=>blockers.add(x));return fail(Object.hasOwn(FIXED,node.name)?'missing_primitive_signature':'definition_unavailable',{name:node.name,kind});}
    if(dep.level_params.length!==levels.length)return fail('invalid_ir',{reason:'constant_universe_arity',name:node.name});
    const denv=new Map(dep.level_params.map((x,i)=>[x,levels[i]]));
    if(active.has(key))return fail('definition_cycle',{name:node.name});
    if(expansionDepth>limits.expansionDepth)return fail('resource_limit',{reason:'definition_expansion_depth',name:node.name});
    active.add(key);let out=null;
    try{
      if(Object.hasOwn(FIXED,node.name)){
        const signature=visit(dep,dep.type_root,[],0,denv,expansionDepth+1);
        if(signature){const index=FIXED[node.name].find(i=>same(signature,kernel.environment[i]));
          if(index===undefined){fail('unsupported_universe_instance',{name:node.name,levels});fail('primitive_signature_mismatch',{name:node.name,levels,signature_sha256:sha(stable(signature))});}
          else out=term('C',index);
        }
      }else if(dep.kind==='definition'&&safeDeclaration(dep)&&dep.proof_root!==null){
        const checked=dep.provenance?.kernel_check?.status;
        if(!buildEligible(build)||!['passed','imported_compiled_declaration'].includes(checked)){
          constantFeatures(node.name,kind).forEach(x=>blockers.add(x));fail('missing_build_evidence',{name:node.name});
        }else{
          event(r,id,'closed_definition_expansion',{name:node.name,levels,dependency_record_sha256:deps.get(node.name).source.line_sha256,
            evidence:checked,build_source_files:build.source_files.map(x=>({path:x.path,sha256:x.sha256}))});
          out=visit(dep,dep.proof_root,[],0,denv,expansionDepth+1);
        }
      }else{constantFeatures(node.name,kind).forEach(x=>blockers.add(x));
        if(!safeDeclaration(dep))fail('unsafe_or_partial',{name:node.name});else fail('definition_unavailable',{name:node.name,kind:dep.kind,value_status:dep.value_status});}
    }finally{active.delete(key);}
    cache.set(key,out);return out;
  }
  function visit(r,id,stack,depth,env,expansionDepth=0){tick();const n=r.expr_nodes[id];
    if(n.tag==='bvar'){
      if(n.index>=stack.length)return fail('open_expression',{declaration:r.name,node:id,index:n.index});
      const binding=stack[n.index];if(binding.kind==='variable'){const i=depth-1-binding.level;return i<=255?term('B',i):fail('resource_limit',{reason:'bound_index',index:i});}
      binding.used=true;if(!binding.done){binding.term=visit(binding.record,binding.value,binding.stack,binding.depth,binding.env,expansionDepth);binding.done=true;}
      return shift(binding.term,depth-binding.depth);
    }
    if(n.tag==='sort'){const v=level(r,n.level,env);return v===null?null:term('S',v);}
    if(n.tag==='const')return constant(r,id,n,env,expansionDepth);
    if(n.tag==='app')return term('A',visit(r,n.fn,stack,depth,env,expansionDepth),visit(r,n.arg,stack,depth,env,expansionDepth));
    if(n.tag==='lam'||n.tag==='forall'){
      const domain=visit(r,n.type,stack,depth,env,expansionDepth);
      const body=visit(r,n.body,[{kind:'variable',level:depth},...stack],depth+1,env,expansionDepth);
      return term(n.tag==='lam'?'L':'P',domain,body);
    }
    if(n.tag==='let'){
      const binding={kind:'let',record:r,value:n.value,stack,depth,env,done:false,used:false};
      const body=visit(r,n.body,[binding,...stack],depth,env,expansionDepth);
      event(r,id,'let_zeta',{unused_value_erased:!binding.used});return body;
    }
    if(n.tag==='mdata'){event(r,id,'metadata_erasure');return visit(r,n.expr,stack,depth,env,expansionDepth);}
    if(n.tag==='lit'){
      if(n.literal_kind!=='nat'){fail('string_literal',{declaration:r.name,node:id});return fail('unsupported_literal',{literal_kind:n.literal_kind});}
      if(!/^(0|[1-9][0-9]*)$/.test(n.value)||n.value.length>12||BigInt(n.value)>BigInt(limits.natLiteral))return fail('nat_literal_limit',{value:n.value.slice(0,80),limit:limits.natLiteral});
      event(r,id,'nat_literal_to_constructors',{value:n.value});let t=constant(r,id,{name:'Nat.zero',levels:[]},env,expansionDepth);
      const successor=Number(n.value)>0?constant(r,id,{name:'Nat.succ',levels:[]},env,expansionDepth):null;
      for(let i=0;i<Number(n.value);i++)t=term('A',successor,t);return t;
    }
    if(n.tag==='proj'){visit(r,n.expr,stack,depth,env,expansionDepth);return fail('projection',{type_name:n.type_name,index:n.index});}
    if(n.tag==='fvar')return fail('free_variable',{name:n.name});if(n.tag==='mvar')return fail('metavariable',{name:n.name});
    return fail('unsupported_expression',{tag:n.tag});
  }
  if(record.level_params.length)blockers.add('symbolic_universe');
  let goal=null,proof=null;try{goal=visit(record,record.type_root,[],0,new Map());if(record.proof_root!==null)proof=visit(record,record.proof_root,[],0,new Map());}
  catch(e){if(e instanceof RangeError||/limit/.test(e.message))fail('resource_limit',{reason:e.message});else fail('invalid_ir',{reason:e.message});}
  return {representable:!!goal&&!!proof&&blockers.size===0,goal,proof,blockers:sorted(blockers),details,
    lowerings:[...events.values()],lowering_operations:steps,goal_size:goal?sizes.get(goal):null,proof_size:proof?sizes.get(proof):null};
}
function nativeWorker(input) {
  const k=require('./equality.cjs'),{proof,goal,limits}=input,out={reference_accepted:false,certificate_replay_accepted:false,native_certificate_accepted:false};
  out.goal_is_prop=k.reference(goal,['S',0]);
  if(!out.goal_is_prop)return {...out,blockers:['proof_classification_mismatch']};
  out.reference_accepted=k.reference(proof,goal);if(!out.reference_accepted)return {...out,blockers:['native_reference_rejection','unresolved_conversion']};
  try{
    const b=new k.Builder(),add=b.r.add.bind(b.r);b.r.add=row=>{if(b.r.rows.length>=limits.nativeRows)throw Error('import native row resource limit');return add(row);};
    const raw=b.prove(proof,goal),rawReplay=k.replay(raw,goal);ensure(rawReplay.accepted&&same(rawReplay.proof,proof),'raw replay subject mismatch');
    const semantic=k.dedup(raw,goal,true),rows=k.prune(semantic,goal),checked=k.replay(rows,goal);
    out.raw_rows=raw.length;out.semantic_rows=semantic.length;out.rows=rows.length;
    out.certificate_replay_accepted=checked.accepted&&same(checked.proof,proof)&&k.reference(checked.proof,goal);
    if(!out.certificate_replay_accepted)return {...out,blockers:['certificate_replay_rejection']};
    out.native_certificate_accepted=true;out.rows_le_1024=rows.length<=1024;out.current_arithmetic_capacity=rows.length<1024;
    out.rule_histogram={};rows.forEach(r=>bump(out.rule_histogram,r[0]));out.certificate={proof,goal,rows};return {...out,blockers:[]};
  }catch(e){return {...out,error:e.message,blockers:[/resource|stack|allocation/i.test(e.message)?'native_resource_limit':'certificate_generation_failure']};}
}
function runNative(proof,goal,limits,budget) {
  if(budget.used>=limits.nativeTotalMs)return {reference_accepted:null,native_certificate_accepted:false,blockers:['native_budget_exhausted','native_resource_limit']};
  const before=Date.now(),timeout=Math.max(1,Math.min(limits.nativeMs,limits.nativeTotalMs-budget.used));
  const p=spawnSync(process.execPath,[`--max-old-space-size=${limits.nativeMemoryMb}`,__filename,'_native'],
    {input:stable({proof,goal,limits}),encoding:'utf8',timeout,maxBuffer:16*1024*1024,killSignal:'SIGKILL'});budget.used+=Date.now()-before;
  if(p.error||p.signal||p.status!==0)return {reference_accepted:null,native_certificate_accepted:false,blockers:['native_resource_limit'],error:p.error?.message||p.signal||p.stderr.slice(0,1000)};
  try{return JSON.parse(p.stdout);}catch(e){return {reference_accepted:null,native_certificate_accepted:false,blockers:['certificate_generation_failure'],error:'native worker JSON: '+e.message};}
}
function eligibility(record,build) {
  const audit=record.provenance?.axiom_dependencies;
  const stringArray=xs=>Array.isArray(xs)&&xs.every(x=>typeof x==='string');
  const axioms=stringArray(audit?.axioms)?audit.axioms:[];
  const complete=audit?.status==='complete'&&stringArray(audit.axioms)&&audit.pending_queue_entries===0&&
    stringArray(audit.missing_constants)&&audit.missing_constants.length===0&&audit.resource_limited_edges===0&&typeof audit.contains_sorry_ax==='boolean';
  const sorry=audit?.contains_sorry_ax===true||axioms.some(n=>/(^|\.)sorryAx$/.test(n));
  return {fresh_source_build:buildEligible(build),kernel_rechecked:record.provenance?.kernel_check?.status==='passed',
    safe_declaration:safeDeclaration(record),axiom_audit_complete:complete,axioms,contains_sorry_ax:sorry,
    axiom_eligible:complete&&!sorry&&axioms.length===0,source_binding:build?.import_source_binding||{verified:false,reasons:['source_receipt_not_bound']}};
}
function sourceRecord(record,source,limits) {
  return {name:record.name,name_parts:record.name_parts,module:record.provenance?.module,kind:record.kind,
    role:record.role,is_proof:record.is_proof,level_params:record.level_params,export_status:record.status,
    provenance:record.provenance,source,raw_goal:rawView(record,record.type_root,limits,true),raw_proof:rawView(record,record.proof_root,limits)};
}
function analyze(record,source,context) {
  const {deps,limits,budget}=context,build=bindBuild(record,context.build,context);
  const base={schema:RESULT,lane:context.lane,name:record.name,is_proof:record.is_proof??null,
    kind:record.kind,source,status:'unprocessed',original_blockers:[],remaining_blockers:[],representable:false,
    native_certificate_accepted:false,eligible_native_accepted:false,strict_whole_declaration_accepted:false,transparent_lowering_accepted:false};
  base.eligibility=eligibility(record,build);
  base.eligibility_blockers=[];
  if(!base.eligibility.fresh_source_build)base.eligibility_blockers.push('missing_build_evidence');
  if(!base.eligibility.kernel_rechecked)base.eligibility_blockers.push('missing_kernel_check');
  if(!base.eligibility.safe_declaration)base.eligibility_blockers.push('unsafe_or_partial');
  if(!base.eligibility.axiom_audit_complete)base.eligibility_blockers.push('incomplete_axiom_audit');
  if(base.eligibility.axioms.length)base.eligibility_blockers.push('source_axioms');
  if(base.eligibility.contains_sorry_ax)base.eligibility_blockers.push('sorry_axiom');
  if(record.status!=='ok')return {...base,status:record.status==='resource_limit'?'export_resource_limit':'export_error',remaining_blockers:[record.status==='resource_limit'?'resource_limit':'export_failure'],diagnostics:record.diagnostics||record.error};
  let depth;try{depth=assertDag(record,limits);}catch(e){return {...base,status:'invalid_ir',remaining_blockers:[/limit/.test(e.message)?'resource_limit':'invalid_ir'],error:e.message};}
  base.original=sourceRecord(record,source,limits);base.node_counts=scan(record,deps,limits);base.original_blockers=base.node_counts.features;
  base.eligibility=eligibility(record,build);
  if(record.is_proof!==true)return {...base,status:record.is_proof===false?'non_proof_declaration':'proof_classification_unknown'};
  if(record.proof_root===null)return {...base,status:'no_proof_body',remaining_blockers:['definition_unavailable']};
  if(depth.max_expr_depth>limits.rawDepth||depth.max_level_depth>limits.rawDepth)return {...base,status:'lowering_resource_limit',remaining_blockers:['resource_limit'],depth};
  const lowered=lower(record,deps,limits,build);base.lowering={events:lowered.lowerings,operations:lowered.lowering_operations,
    goal_size:lowered.goal_size,proof_size:lowered.proof_size,details:lowered.details};
  base.representable=lowered.representable;base.remaining_blockers=lowered.blockers;
  if(!lowered.representable)return {...base,status:'unrepresentable'};
  base.lowered_goal=lowered.goal;base.lowered_proof=lowered.proof;base.lowered_goal_sha256=sha(stable(lowered.goal));base.lowered_proof_sha256=sha(stable(lowered.proof));
  const native=runNative(lowered.proof,lowered.goal,limits,budget);base.native=native;base.native_certificate_accepted=native.native_certificate_accepted;
  base.remaining_blockers=unique([...base.remaining_blockers,...native.blockers]);
  const eligible=Object.values({fresh:base.eligibility.fresh_source_build,kernel:base.eligibility.kernel_rechecked,safe:base.eligibility.safe_declaration,axioms:base.eligibility.axiom_eligible}).every(Boolean);
  base.eligible_native_accepted=eligible&&native.native_certificate_accepted;
  base.transparent_lowering_accepted=base.eligible_native_accepted;
  base.strict_whole_declaration_accepted=base.eligible_native_accepted&&lowered.lowerings.length===0&&base.original_blockers.length===0;
  if(native.certificate){const artifact={schema:'zkl-nova-18/imported-native-certificate-v1',name:record.name,source,raw_goal_sha256:base.original.raw_goal.sha256,
    raw_proof_sha256:base.original.raw_proof.sha256,lowerings:lowered.lowerings,...native.certificate};
    const bytes=stable(artifact)+'\n';base.certificate={sha256:sha(bytes),bytes:Buffer.byteLength(bytes),rows:native.rows};
    if(context.certificates){const name=sha(stable([context.lane,record.name,source.line_sha256]))+'.json';fs.writeFileSync(path.join(context.certificates,name),bytes);base.certificate.file=name;}
    delete native.certificate;
  }
  return {...base,status:native.native_certificate_accepted?'native_accepted':'native_rejected'};
}
function summarize(results,details) {
  const proofs=results.filter(r=>r.is_proof===true),identified=results.filter(r=>r.is_proof===true||r.is_proof===false),accepted=results.filter(r=>r.eligible_native_accepted);
  const histogram=field=>{const h=Object.fromEntries(BLOCKERS.map(x=>[x,0]));for(const r of proofs)for(const x of unique(r[field]||[]))bump(h,x);return h;};
  const statuses={},exprTags={},levelTags={},constantOccurrences={},constantDeclarations={},loweringEvents={};let expr=0,levels=0,goal=0,proof=0;
  for(const r of results)bump(statuses,r.status);
  for(const r of proofs){const n=r.node_counts;if(n){expr+=n.expression_nodes;levels+=n.level_nodes;goal+=n.goal_expression_nodes;proof+=n.proof_expression_nodes;
    for(const [k,v] of Object.entries(n.expression_tags))bump(exprTags,k,v);for(const [k,v] of Object.entries(n.level_tags))bump(levelTags,k,v);
    for(const [k,v] of Object.entries(n.constant_occurrences)){bump(constantOccurrences,k,v);bump(constantDeclarations,k);}}
    for(const e of r.lowering?.events||[])bump(loweringEvents,e.kind,e.occurrences);
  }
  const count=fn=>results.filter(fn).length,pct=(n,d)=>({numerator:n,denominator:d,percent:d?100*n/d:null});
  const targetCount=details.expected_names?.length??details.export_manifest?.target_records??results.length;
  const proofCandidates=results.filter(r=>r.is_proof===true||r.kind==='theorem');
  const transitiveAxioms={'propext':0,'Quot.sound':0,'Classical.choice':0,'sorryAx':0};
  for(const r of proofCandidates)for(const name of unique(r.eligibility?.axioms||[]))bump(transitiveAxioms,name);
  return {schema:SUMMARY,...details,denominators:{selected_inventory_candidates:targetCount,observed_result_records:results.length,
      identified_declaration_types:identified.length,identified_proof_declarations:proofs.length,identified_non_proof_declarations:identified.length-proofs.length,
      unclassified_candidates:Math.max(0,targetCount-identified.length),known_theorem_declarations:count(r=>r.kind==='theorem'),
      theorem_declarations_with_unresolved_proof_classification:count(r=>r.kind==='theorem'&&r.is_proof!==true&&r.is_proof!==false),
      exported_proof_bodies:count(r=>r.is_proof===true&&r.original?.raw_proof!==null&&r.original?.raw_proof!==undefined)},
    counts:{representable_proof_declarations:count(r=>r.is_proof===true&&r.representable),reference_accepted:count(r=>r.native?.reference_accepted===true),
      replay_accepted:count(r=>r.native?.certificate_replay_accepted===true),native_certificate_accepted:count(r=>r.native_certificate_accepted),
      eligible_native_accepted:accepted.length,strict_whole_declaration_accepted:count(r=>r.strict_whole_declaration_accepted),
      transparent_lowering_accepted:count(r=>r.transparent_lowering_accepted),native_rows_le_1024:count(r=>r.native_certificate_accepted&&r.native?.rows_le_1024),
      current_arithmetic_capacity:count(r=>r.native_certificate_accepted&&r.native?.current_arithmetic_capacity),
      eligible_current_arithmetic_capacity:count(r=>r.eligible_native_accepted&&r.native?.current_arithmetic_capacity),
      source_build_eligible_proofs:count(r=>r.is_proof===true&&r.eligibility?.fresh_source_build),axiom_eligible_proofs:count(r=>r.is_proof===true&&r.eligibility?.axiom_eligible)},
    coverage:{strict_over_selected:pct(count(r=>r.strict_whole_declaration_accepted),targetCount),transparent_over_selected:pct(accepted.length,targetCount),
      strict_over_identified_proofs:pct(count(r=>r.strict_whole_declaration_accepted),proofs.length),transparent_over_identified_proofs:pct(accepted.length,proofs.length)},
    statuses,blocker_denominator:{description:'Unique freshly identified target proof declarations; labels overlap and sums may exceed the denominator.',count:proofs.length},
    original_blocker_histogram:histogram('original_blockers'),remaining_blocker_histogram:histogram('remaining_blockers'),
    eligibility_blocker_histogram:histogram('eligibility_blockers'),
    transitive_axioms:{description:'Per-declaration transitive axiom audit; includes known theorem declarations with unresolved is_proof classification. Labels overlap.',
      proof_or_known_theorem_denominator:proofCandidates.length,complete_audits:proofCandidates.filter(r=>r.eligibility?.axiom_audit_complete).length,
      incomplete_or_missing_audits:proofCandidates.filter(r=>!r.eligibility?.axiom_audit_complete).length,declaration_histogram:transitiveAxioms},
    conversion_feature_assessment:{description:'Expr has no eta/proof-irrelevance use node; explicit diagnostics/constants are counted, other cases remain unassessed.',
      eta_unassessed:proofs.filter(r=>!(r.original_blockers||[]).includes('eta')).length,
      proof_irrelevance_unassessed:proofs.filter(r=>!(r.original_blockers||[]).includes('proof_irrelevance')).length},
    expression_nodes:{description:'Declaration-local DAG nodes reachable from original proof/type roots, counted once per declaration. Goal/proof columns overlap.',
      proof_declaration_count:proofs.filter(r=>r.node_counts).length,reachable_unique:expr,level_nodes:levels,goal_reachable:goal,proof_reachable:proof,
      tags:exprTags,level_tags:levelTags,constant_occurrences:constantOccurrences,constant_declarations:constantDeclarations},lowering_events:loweringEvents,
    capacity_policy:{nominal_rows_le:1024,current_generator_rows_strictly_less_than:1024,native_relation_row_limit:details.limits?.nativeRows||DEFAULTS.nativeRows},
    missing_candidates:results.filter(r=>r.status==='not_exported'||r.status==='source_build_failed').map(r=>r.name)};
}
function options(args) {
  const out={limits:{...DEFAULTS},inputs:[]};const flags={'--input':'input','--dependencies':'dependencies','--manifest':'manifest','--build-receipt':'buildReceipt','--cohort':'cohort','--lane':'lane','--output':'output'};
  for(let i=0;i<args.length;i++){const a=args[i];if(a==='--certificates'){out.certificates=true;continue;}
    if(a==='--inputs'){while(i+1<args.length&&!args[i+1].startsWith('--'))out.inputs.push(args[++i]);continue;}
    if(Object.hasOwn(flags,a)){ensure(i+1<args.length,'missing value for '+a);out[flags[a]]=args[++i];continue;}
    if(a.startsWith('--limit-')){const k=a.slice(8);ensure(Object.hasOwn(DEFAULTS,k),'unknown limit '+k);const v=Number(args[++i]);ensure(isInt(v)&&v>0&&v<=DEFAULTS[k]*16,'invalid bounded limit '+k);out.limits[k]=v;continue;}
    throw Error('unknown argument '+a);
  }
  ensure(out.output,'--output is required');return out;
}
async function importCorpus(opts) {
  const output=path.resolve(opts.output);fs.mkdirSync(output,{recursive:true});
  const manifest=readJson(opts.manifest),build=readJson(opts.buildReceipt),cohort=readJson(opts.cohort),lane=opts.lane||build?.lane||'default';
  const selectedLane=cohort?.lanes?.find(x=>x.id===lane);if(cohort)ensure(selectedLane,'lane missing from cohort');
  const expectedNames=selectedLane?.names||build?.selected_names||manifest?.selected_names||null;
  if(expectedNames)ensure(Array.isArray(expectedNames)&&unique(expectedNames).length===expectedNames.length,'duplicate cohort names');
  const deps=new Map(),dependencyErrors=[];let dependencyNodes=0,dependencyScan=null;
  if(opts.dependencies)dependencyScan=await readLines(opts.dependencies,opts.limits,async(record,source,error)=>{
    if(error){dependencyErrors.push({source,error});return;}
    try{ensure(record.role==='dependency','dependency role');if(record.status==='ok'){assertDag(record,opts.limits);dependencyNodes+=record.expr_nodes.length;ensure(dependencyNodes<=opts.limits.dependencyNodes,'dependency node budget');}
      ensure(!deps.has(record.name),'duplicate dependency '+record.name);deps.set(record.name,{record,source});
    }catch(e){if(dependencyErrors.length<1000)dependencyErrors.push({name:record?.name,source,error:e.message});}
  });
  const context={deps,limits:opts.limits,build,budget:{used:0},lane,cohortLane:selectedLane,certificates:null};
  if(opts.certificates){context.certificates=path.join(output,'certificates');fs.mkdirSync(context.certificates,{recursive:true});}
  const results=[],inputErrors=[],duplicates=[],outside=[],seen=new Set();let inputScan=null;
  if(opts.input)inputScan=await readLines(opts.input,opts.limits,async(record,source,error)=>{
    if(error){inputErrors.push({source,error});return;}
    if(!record||typeof record!=='object'||Array.isArray(record)){inputErrors.push({source,error:'invalid_ir: record must be an object'});return;}
    if(record.role!=='target'){inputErrors.push({source,error:'non-target record in target input'});return;}
    if(expectedNames&&!expectedNames.includes(record.name)){outside.push({name:record.name,source});return;}
    if(seen.has(record.name)){duplicates.push({name:record.name,source});return;}seen.add(record.name);
    results.push(analyze(record,source,context));
  });
  for(const name of expectedNames||[])if(!seen.has(name))results.push({schema:RESULT,lane,name,is_proof:null,kind:null,
    candidate_source:'fixed_upstream_inventory',status:build?.status&&build.status!=='passed'?'source_build_failed':'not_exported',
    original_blockers:[],remaining_blockers:[build?.status&&build.status!=='passed'?'source_build_failure':'not_exported'],
    representable:false,native_certificate_accepted:false,eligible_native_accepted:false,strict_whole_declaration_accepted:false,transparent_lowering_accepted:false});
  if(expectedNames){const order=new Map(expectedNames.map((n,i)=>[n,i]));results.sort((a,b)=>order.get(a.name)-order.get(b.name));}
  const resultFile=path.join(output,'results.jsonl');fs.writeFileSync(resultFile,results.map(r=>stable(r)).join('\n')+(results.length?'\n':''));
  const inputs={targets:inputScan?.file||null,dependencies:dependencyScan?.file||null,
    manifest:opts.manifest?fileInfo(opts.manifest):null,build_receipt:opts.buildReceipt?fileInfo(opts.buildReceipt):null,cohort:opts.cohort?fileInfo(opts.cohort):null,
    importer:fileInfo(__filename),kernel:fileInfo(path.join(__dirname,'equality.cjs')),fixed_environment:fileInfo(path.join(__dirname,'equality_environment.cjs'))};
  const summary=summarize(results,{lane,expected_names:expectedNames,cohort_source:cohort?.source||null,upstream_theorem_inventory_count:selectedLane?.theorem_inventory_count??null,
    limits:opts.limits,inputs,scan_complete:(inputScan?.complete??!opts.input)&&(dependencyScan?.complete??true)&&inputErrors.length===0&&dependencyErrors.length===0,
    source_build:build,export_manifest:manifest,dependency_records_loaded:deps.size,dependency_errors:dependencyErrors,
    input_errors:inputErrors,duplicate_targets:duplicates,outside_cohort_targets:outside,native_worker_wall_ms:context.budget.used,
    results_file:fileInfo(resultFile)});
  fs.writeFileSync(path.join(output,'summary.json'),JSON.stringify(summary,null,2)+'\n');return summary;
}
function aggregate(opts) {
  ensure(opts.cohort&&opts.inputs.length,'aggregate requires --cohort and --inputs');const cohort=readJson(opts.cohort),results=[],lanes=[];
  ensure(Array.isArray(cohort.lanes)&&unique(cohort.lanes.map(l=>l.id)).length===cohort.lanes.length,'cohort lanes');
  for(const directory of opts.inputs){const summary=readJson(path.join(directory,'summary.json'));ensure(summary.schema===SUMMARY,'lane summary schema');
    const file=path.join(directory,'results.jsonl');ensure(same({...fileInfo(file),path:summary.results_file.path},summary.results_file),'lane results hash');
    ensure(!lanes.some(l=>l.lane===summary.lane),'duplicate lane');lanes.push(summary);
    const found=fs.readFileSync(file,'utf8').split('\n').filter(Boolean).map(x=>JSON.parse(x));
    const lane=cohort.lanes.find(l=>l.id===summary.lane);ensure(lane,'unexpected lane');ensure(same(found.map(r=>r.name),lane.names),'fixed lane candidate coverage');results.push(...found);
  }
  for(const lane of cohort.lanes)if(!lanes.some(x=>x.lane===lane.id))for(const name of lane.names)results.push({schema:RESULT,lane:lane.id,name,is_proof:null,status:'not_exported',original_blockers:[],remaining_blockers:['not_exported']});
  const expected=cohort.lanes.flatMap(l=>l.names),summary=summarize(results,{lane:'aggregate',expected_names:expected,cohort_source:cohort.source,
    cohort:fileInfo(opts.cohort),limits:DEFAULTS,lanes,scan_complete:lanes.length===cohort.lanes.length&&lanes.every(l=>l.scan_complete),
    missing_lanes:cohort.lanes.filter(l=>!lanes.some(s=>s.lane===l.id)).map(l=>l.id)});
  fs.writeFileSync(opts.output,JSON.stringify(summary,null,2)+'\n');return summary;
}
if(require.main===module){
  if(process.argv[2]==='_native'){
    try{const input=fs.readFileSync(0,'utf8');ensure(Buffer.byteLength(input)<=8*1024*1024,'worker input limit');process.stdout.write(stable(nativeWorker(JSON.parse(input))));}
    catch(e){process.stderr.write(e.message+'\n');process.exitCode=1;}
  }else{
    const args=process.argv.slice(2),command=args[0]==='aggregate'?args.shift():'import';
    Promise.resolve().then(()=>{const opts=options(args);return command==='aggregate'?aggregate(opts):importCorpus(opts);})
      .then(summary=>process.stdout.write(JSON.stringify({schema:summary.schema,lane:summary.lane,denominators:summary.denominators,counts:summary.counts,coverage:summary.coverage,scan_complete:summary.scan_complete},null,2)+'\n'))
      .catch(e=>{process.stderr.write('corpus importer: '+e.message+'\n');process.exitCode=1;});
  }
}
module.exports={DEFAULTS,FIXED,assertDag,scan,lower,analyze,nativeWorker,runNative,eligibility,bindBuild,summarize,importCorpus,aggregate};
