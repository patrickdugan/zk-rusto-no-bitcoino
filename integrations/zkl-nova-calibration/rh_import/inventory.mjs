// Original diagnostic reader for Lean 4.35.0 NDJSON (format 3.1.0).
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {createInterface} from 'node:readline';
async function inventory(lines,{roots=[],terms=false,rh=false,maxRows=25000000}={}){
  // Diagnostic reader for the pinned Lean 4.35.0 export writer, not a kernel.
  const fail=m=>{throw new Error(m)};
  const need=(x,m)=>{if(!x)fail(m)};
  const nat=x=>Number.isSafeInteger(x)&&x>=0;
  const obj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
  const one=(r,k)=>{const a=Object.keys(r).filter(x=>x!==k);need(a.length===1,"expected one payload");return a[0]};
  const arr=x=>{need(Array.isArray(x),"expected array");return x};
  const ns=[null],ls=[["zero",null]],es=terms?[]:null,ds=new Map(),refs=new Set(),literals=new Set();
  let ne=0,nr=0,meta=null;
  const kinds={},levelKinds={},declKinds={};
  const add=(o,k)=>o[k]=(o[k]||0)+1;
  const name=i=>{need(nat(i)&&i<ns.length,"bad name reference");return i};
  const level=i=>{need(nat(i)&&i<ls.length,"bad level reference");return i};
  const expr=i=>{need(nat(i)&&i<ne,"bad expression reference");return i};
  const ref=i=>{name(i);need(i!==0,"anonymous constant");refs.add(i)};
  const path=i=>{let a=[];while(i!==0){let [p,k,v]=ns[i];a.push([k,v]);i=p;}return a.reverse()};
  const key=i=>JSON.stringify(path(i));
  const textName=i=>path(i).map(([k,v])=>k==="num"?`#${v}`:v).join(".");
  const plainName=s=>JSON.stringify(s.split(".").map(v=>["str",v]));
  const decl=(kind,v)=>{
    need(obj(v),"invalid declaration");
    const id=name(v.name);need(id!==0&&!ds.has(id),"duplicate declaration");
    arr(v.levelParams).forEach(name);
    need(new Set(v.levelParams).size===v.levelParams.length,"duplicate universe parameter");
    expr(v.type);
    if(["def","opaque","thm"].includes(kind))expr(v.value);
    if(v.rules!==undefined)for(const q of arr(v.rules)){ref(q.ctor);expr(q.rhs);}
    if(v.induct!==undefined)ref(v.induct);
    if(v.ctors!==undefined)arr(v.ctors).forEach(ref);
    if(["inductive","recursor"].includes(kind)&&v.all!==undefined)arr(v.all).forEach(ref);
    if(v.isUnsafe===true||v.safety==="unsafe"||v.safety==="partial")add(declKinds,"unsafe_or_partial");
    ds.set(id,{kind,params:v.levelParams,type:v.type,value:v.value});add(declKinds,kind);
  };
  for await(const line of lines){
    nr++;need(nr<=maxRows,"record cap exceeded");need(line.length<=16777216,"line cap exceeded");
    let r=JSON.parse(line);need(obj(r),"nonobject row");
    if(nr===1){need(Object.keys(r).length===1&&obj(r.meta)&&r.meta.format?.version==="3.1.0"&&r.meta.lean?.version==="4.35.0","wrong metadata/version");meta=r.meta;continue}
    if("in" in r){
      const k=one(r,"in"),v=r[k];need(r.in===ns.length&&obj(v),"name order");
      const p=name(v.pre);need((k==="str"&&typeof v.str==="string")||(k==="num"&&nat(v.i)),"name tag");
      ns.push([p,k,k==="str"?v.str:v.i]);continue
    }
    if("il" in r){
      const k=one(r,"il"),v=r[k];need(r.il===ls.length,"level order");
      if(k==="succ")level(v);else if(k==="max"||k==="imax"){need(arr(v).length===2,"level arity");v.forEach(level)}
      else if(k==="param")name(v);else fail("unsupported level tag "+k);
      ls.push([k,v]);add(levelKinds,k);continue
    }
    if("ie" in r){
      const k=one(r,"ie"),v=r[k];need(r.ie===ne,"expression order");
      if(k==="bvar")need(nat(v),"bad bound variable");
      else if(k==="sort")level(v);
      else if(k==="const"){ref(v.name);arr(v.us).forEach(level)}
      else if(k==="app"){expr(v.fn);expr(v.arg)}
      else if(k==="lam"||k==="forallE"){name(v.name);expr(v.type);expr(v.body)}
      else if(k==="letE"){name(v.name);expr(v.type);expr(v.value);expr(v.body)}
      else if(k==="proj"){ref(v.typeName);need(nat(v.idx),"bad projection");expr(v.struct)}
      else if(k==="natVal"){need(typeof v==="string"&&/^(0|[1-9][0-9]*)$/.test(v),"bad nat");literals.add("Nat")}
      else if(k==="strVal"){need(typeof v==="string","bad string");literals.add("Char.ofNat");literals.add("String.ofList")}
      else if(k==="mdata")expr(v.expr);
      else fail("unsupported expression tag "+k);
      if(es){need(ne<100000,"small import expression cap");es.push([k,v])}
      ne++;add(kinds,k);continue
    }
    const k=one(r,""),v=r[k];
    if(k==="inductive"){
      need(obj(v),"inductive group");
      arr(v.types).forEach(x=>decl("inductive",x));arr(v.ctors).forEach(x=>decl("constructor",x));arr(v.recs).forEach(x=>decl("recursor",x));
    }else if(["axiom","def","opaque","thm","quot"].includes(k))decl(k,v);
    else fail("unsupported declaration tag "+k);
  }
  need(meta!==null,"empty export");
  const namesByKey=new Map();for(const i of ds.keys()){const s=key(i);need(!namesByKey.has(s),"duplicate structural declaration name");namesByKey.set(s,i)}
  const missing=[...refs].filter(i=>!ds.has(i)).map(textName);
  for(const n of literals)if(!namesByKey.has(plainName(n)))missing.push(n);
  need(missing.length===0,"missing declarations: "+missing.slice(0,10).join(", "));
  const ax=[...ds].filter(([,d])=>d.kind==="axiom").map(([i])=>textName(i)).sort();
  if(rh){
    const allowed=new Set(["propext","Quot.sound","Classical.choice"].map(plainName));
    need([...ds].filter(([,d])=>d.kind==="axiom").every(([i])=>allowed.has(key(i))),"unpermitted axiom");
    need(!declKinds.unsafe_or_partial,"unsafe or partial declaration");
  }
  const targets=roots.map(n=>{const i=namesByKey.get(plainName(n));need(i!==undefined,"missing root "+n);
    const d=ds.get(i);if(rh)need(d.kind==="thm","RH root not a theorem");return {name:n,...d}});
  const report={schema:"zkl-lean-export-inventory-v1",meta,records:nr,names:ns.length-1,levels:ls.length-1,expressions:ne,
    declarations:ds.size,expression_kinds:kinds,level_kinds:levelKinds,declaration_kinds:declKinds,axioms:ax,targets,
    syntactic_references_closed:true,kernel_verified:false};
  if(terms){
    report.admission=[];
    for(const d of targets)for(const instance of [0,1]){
      let budget=4096;
      const l=(i,depth=0)=>{
        need(depth<=64&&--budget>=0,"expansion budget");const [k,v]=ls[i];let n;
        if(k==="zero")n=0;
        else if(k==="param"){need(d.params.includes(v),"unbound universe parameter");n=instance}
        else if(k==="succ")n=1+l(v,depth+1);
        else if(k==="max")n=Math.max(l(v[0],depth+1),l(v[1],depth+1));
        else if(k==="imax"){const u=l(v[0],depth+1),w=l(v[1],depth+1);n=w===0?0:Math.max(u,w)}
        else fail("unsupported universe");
        need(n<=7,"universe bound");return n
      };
      const e=(i,binders=0,depth=0)=>{
        need(depth<=64&&--budget>=0,"expansion budget");const [k,v]=es[i];
        if(k==="sort")return [0,l(v)];
        if(k==="bvar"){need(v<binders&&v<=65535,"unbound term variable");return [1,v]}
        if(k==="forallE"||k==="lam")return [k==="forallE"?2:3,e(v.type,binders,depth+1),e(v.body,binders+1,depth+1)];
        if(k==="app")return [4,e(v.fn,binders,depth+1),e(v.arg,binders,depth+1)];
        fail("outside constant-free fragment: "+k)
      };
      let row={name:d.name,instance,universe_arguments:d.params.map(()=>instance)};
      try{need(["def","thm"].includes(d.kind)&&d.value!==undefined,"no supported body");
        row.type=e(d.type);row.term=e(d.value);row.status="syntax_admitted"}
      catch(err){row.status="rejected";row.reason=String(err.message)}
      report.admission.push(row);
    }
  }
  return report
}
async function selfTest(){
 const meta={meta:{format:{version:"3.1.0"},lean:{version:"4.35.0"},exporter:{version:"3.1.0"}}};
 const fixture=[meta,{in:1,str:{pre:0,str:"id"}},{in:2,str:{pre:0,str:"u"}},{in:3,str:{pre:0,str:"x"}},
 {il:1,param:2},{ie:0,sort:1},{ie:1,bvar:0},{ie:2,bvar:1},
 {ie:3,forallE:{name:3,type:1,body:2,binderInfo:"default"}},
 {ie:4,forallE:{name:3,type:0,body:3,binderInfo:"implicit"}},
 {ie:5,lam:{name:3,type:1,body:1,binderInfo:"default"}},
 {ie:6,lam:{name:3,type:0,body:5,binderInfo:"implicit"}},
 {def:{name:1,levelParams:[2],type:4,value:6,hints:"abbrev",safety:"safe",all:[1]}}];
 const call=(f,o={roots:["id"],terms:true})=>inventory(f.map(v=>JSON.stringify(v)),o);
 const assert=(x,m)=>{if(!x)throw Error(m)};
 let r=await call(fixture);
 assert(r.admission.every(x=>x.status==="syntax_admitted"),"identity admitted");
 assert(JSON.stringify(r.admission[1].term)==="[3,[0,1],[3,[1,0],[1,0]]]","specialization");
 let tests=2;
 const mutations=[
   f=>{f[0].meta.lean.version="wrong"},
   f=>{f[1].in=0},
   f=>{f[4].param=5},
   f=>{f[8].forallE.body=100},
   f=>{f.push(f.at(-1))},
   f=>{f.pop()},
   f=>{f[7]={ie:2,const:{name:3,us:[]}}},
   f=>{f[6].ie=5},
   f=>{f[5]={ie:0,unknown:0}},
 ];
 for(const change of mutations){
   const f=JSON.parse(JSON.stringify(fixture));change(f);let rejected=false;
   try{await call(f)}catch{rejected=true}assert(rejected,"mutation must reject");tests++;
 }
 const badScope=JSON.parse(JSON.stringify(fixture));badScope[6].bvar=3;
 r=await call(badScope);assert(r.admission.every(x=>x.status==="rejected"),"open term rejected");tests++;
 const a=[meta,{in:1,str:{pre:0,str:"bad"}},{ie:0,sort:0},{axiom:{name:1,type:0,levelParams:[],isUnsafe:false}}];
 let rejected=false;try{await call(a,{rh:true,roots:["bad"]})}catch{rejected=true}assert(rejected,"axiom rejection");tests++;
 return {tests_passed:tests,scope:"synthetic export-reader and syntax admission tests",kernel_verified:false};
}
const args=process.argv.slice(2);
if(args[0]==='--self-test'){console.log(JSON.stringify(await selfTest()));}
else{
  const input=args.shift();if(!input)throw Error('usage: inventory.mjs EXPORT [--terms] [--rh] ROOT...');
  const terms=args.includes('--terms'),rh=args.includes('--rh');
  const roots=args.filter(x=>!x.startsWith('--'));
  if(!roots.length)throw Error('at least one registered root required');
  const stream=createReadStream(input);const hash=createHash('sha256');stream.on('data',c=>hash.update(c));
  const result=await inventory(createInterface({input:stream,crlfDelay:Infinity}),{roots,terms,rh});
  result.export_sha256=hash.digest('hex');console.log(JSON.stringify(result,null,2));
}
