'use strict';
// PNS-PIPE-01 exact committed Boolean trace fraud reference.
function traceLibrary(){
"use strict";
const ck=(b,m)=>{if(!b)throw Error(m)},A=(n,f)=>Array.from({length:n},(_,i)=>f(i));
const U64=1n<<64n,M=U64-1n,RC=["1","8082","800000000000808a","8000000080008000","808b","80000001","8000000080008081","8000000000008009","8a","88","80008009","8000000a","8000808b","800000000000008b","8000000000008089","8000000000008003","8000000000008002","8000000000000080","800a","800000008000000a","8000000080008081","8000000000008080","80000001","8000000080008008"].map(x=>BigInt("0x"+x));
// Round 22 is 0x0000000080000001.
const ROT=[0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
const rot=(x,n)=>n===0?x:((x<<BigInt(n))|(x>>BigInt(64-n)))&M;
const concat=(...a)=>Uint8Array.from(a.flatMap(x=>Array.from(x)));
const eq=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
const hex=a=>Array.from(a,x=>x.toString(16).padStart(2,"0")).join("");
const fromHex=s=>{ck(/^(?:[0-9a-f]{2})*$/.test(s),"hex");return Uint8Array.from(s.match(/../g)||[],x=>parseInt(x,16))};
const le=(v,n=8)=>{v=BigInt(v);ck(v>=0n&&v<(1n<<BigInt(8*n)),"integer width");return Uint8Array.from(A(n,i=>Number(v>>BigInt(i*8)&255n)))};
const read=(b)=>b.reduceRight((s,x)=>s*256n+BigInt(x),0n);
const ascii=s=>Uint8Array.from(s,c=>c.charCodeAt(0));
function hash(msg){
 const RATE=136,raw=new Uint8Array(Math.ceil((msg.length+1)/RATE)*RATE);raw.set(msg);raw[msg.length]=1;raw[raw.length-1]|=128;let s=A(25,()=>0n);
 for(let off=0;off<raw.length;off+=RATE){
  for(let i=0;i<17;i++)s[i]^=read(raw.slice(off+8*i,off+8*i+8));
  for(const r of RC){
   let c=A(5,x=>s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20]),d=A(5,x=>c[(x+4)%5]^rot(c[(x+1)%5],1)),b=A(25,()=>0n);
   for(let y=0;y<5;y++)for(let x=0;x<5;x++){let i=x+5*y;b[y+5*((2*x+3*y)%5)]=rot(s[i]^d[x],ROT[i])}
   for(let y=0;y<5;y++)for(let x=0;x<5;x++)s[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
   s[0]^=r;
  }
 }return concat(...s.slice(0,4).map(x=>le(x)));
}
const H32=x=>{ck(x instanceof Uint8Array&&x.length===32,"32-byte digest");return x};
function session(ctx){
 return hash(concat(ascii("PNS-PIPE-CONTEXT/v1\0"),H32(ctx.genesis),H32(ctx.bondTxid),le(ctx.vout,4),le(ctx.epoch),
 H32(ctx.verifier),H32(ctx.statement),H32(ctx.proof),H32(ctx.policy),H32(ctx.disproveSighash)));
}
const depth=n=>{ck(Number.isSafeInteger(n)&&n>0,"count");return Math.ceil(Math.log2(n))};
const ROW=16,TRACE=32;
const hLeaf=(tag,s,v)=>hash(concat(Uint8Array.of(tag),H32(s),H32(v)));
const hNode=(tag,s,l,r)=>hash(concat(Uint8Array.of(tag+1),H32(s),H32(l),H32(r)));
function tree(tag,s,leaves){
 ck(leaves.length>0,"empty tree");let h=depth(leaves.length),n=2**h;
 const layer=A(n,i=>hLeaf(tag,s,i<leaves.length?leaves[i]:new Uint8Array(32))),levels=[layer];
 for(let l=0;l<h;l++){const x=levels[l];levels.push(A(x.length/2,i=>hNode(tag,s,x[i*2],x[i*2+1])))}
 return {root:levels.at(-1)[0],path:i=>{ck(Number.isSafeInteger(i)&&i>=0&&i<leaves.length,"opening range");let p=[];for(let j=0;j<h;j++){p.push(levels[j][i%2===0?i+1:i-1]);i=Math.floor(i/2)}return p}};
}
function open(tag,s,root,leaf,index,n,path){
 if(!Number.isSafeInteger(index)||index<0||index>=n||path.length!==depth(n))return false;
 let h=hLeaf(tag,s,leaf),i=index;
 for(const sib of path){h=i%2===0?hNode(tag,s,h,sib):hNode(tag,s,sib,h);i=Math.floor(i/2)}
 return eq(h,root);
}
function row(a,b,z,t){
 ck([a,b,z].every(x=>Number.isSafeInteger(x)&&x>=0)&&Number.isInteger(t)&&t>=0&&t<16,"row");
 return concat(le(a),le(b),le(z),Uint8Array.of(t),new Uint8Array(7));
}
function decode(r){
 ck(r.length===32&&r[24]<16&&r.slice(25).every(x=>x===0),"canonical row");
 let a=read(r.slice(0,8)),b=read(r.slice(8,16)),z=read(r.slice(16,24));ck([a,b,z].every(i=>i<=BigInt(Number.MAX_SAFE_INTEGER)),"safe slot");
 return {a:Number(a),b:Number(b),z:Number(z),t:r[24]};
}
const pin=(i,v)=>row(0,0,i,v?15:0);
const result=(r,a,b)=>(r.t>>(2*a+b))&1;
function passes(rec,values){const r=decode(rec);return values[r.z]===result(r,values[r.a],values[r.b])}
function pages(bits){
 ck(bits.length>0&&Array.from(bits).every(v=>v===0||v===1),"bit assignment");
 return A(Math.ceil(bits.length/256),j=>{let p=new Uint8Array(32);for(let i=0;i<256&&j*256+i<bits.length;i++)p[i>>3]|=bits[j*256+i]<<(i%8);return p});
}
function commit(ctx,rows,bits){
 const s=session(ctx),p=pages(bits);for(const rec of rows){let r=decode(rec);ck(Math.max(r.a,r.b,r.z)<bits.length,"row references padding")}
 const rt=tree(ROW,s,rows),vt=tree(TRACE,s,p);
 const inst={s,rowRoot:rt.root,traceRoot:vt.root,rowCount:rows.length,slotCount:bits.length};
 return {inst,witness:i=>{const r=decode(rows[i]);return {rowIndex:i,row:rows[i],rowPath:rt.path(i),slots:[r.a,r.b,r.z].map(j=>({page:p[Math.floor(j/256)],path:vt.path(Math.floor(j/256))}))}}};
}
// Public WE instance uses the actual roots, fixed sizes, and a session digest.
// Independent setup must authenticate the row root, including proof-input pins.
function verify(inst,w){
 try{
  H32(inst.s);H32(inst.rowRoot);H32(inst.traceRoot);
  if(!open(ROW,inst.s,inst.rowRoot,w.row,w.rowIndex,inst.rowCount,w.rowPath))return false;
  const r=decode(w.row),indices=[r.a,r.b,r.z];
  if(w.slots.length!==3||indices.some(i=>i>=inst.slotCount))return false;
  const bits=indices.map((j,k)=>{
   const v=w.slots[k],i=Math.floor(j/256);
   ck(open(TRACE,inst.s,inst.traceRoot,v.page,i,Math.ceil(inst.slotCount/256),v.path),"trace opening");
   return(v.page[(j%256)>>3]>>(j%8))&1;
  });
  return bits[2]!==result(r,bits[0],bits[1]);
 }catch(e){return false}
}
function statement(inst){
 return concat(ascii("PNS-PIPE-FRAUD/v1\0"),H32(inst.s),H32(inst.rowRoot),H32(inst.traceRoot),le(inst.rowCount),le(inst.slotCount));
}
function context(){
 const h=x=>hash(ascii(x));
 return {genesis:h("TEST genesis"),bondTxid:h("TEST outpoint"),vout:3,epoch:7,verifier:h("TEST verifier"),statement:h("TEST statement"),proof:h("TEST proof"),policy:h("TEST policy"),disproveSighash:h("TEST sighash")};
}
// Independent fixed netlist assembly: every external input must be pinned,
// every internal wire has one acyclic definition, acceptance is a final pin.
function assemble(n,inputPins,gates,accept){
 ck(n>=2&&n<=Number.MAX_SAFE_INTEGER,"slots");let assigned=new Set([0,1]),rows=[pin(0,1),pin(1,0)];
 for(const [i,v] of inputPins){ck(i>=2&&i<n&&!assigned.has(i)&&(v===0||v===1),"input pin");assigned.add(i);rows.push(pin(i,v))}
 for(const rec of gates){let r=decode(rec);ck(assigned.has(r.a)&&assigned.has(r.b)&&r.z>=2&&r.z<n&&!assigned.has(r.z),"acyclic definition");assigned.add(r.z);rows.push(rec)}
 ck(assigned.size===n&&assigned.has(accept),"complete graph");rows.push(pin(accept,1));return rows;
}
function selftest(){
 ck(hex(hash(new Uint8Array()))==="c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470","Keccak empty vector");
 ck(hex(hash(ascii("abc")))==="4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45","Keccak abc vector");
 const ctx=context(),g=[row(2,3,4,6),row(4,0,5,8),row(5,1,6,14)],rows=assemble(7,[[2,1],[3,0]],g,6);
 const correct=[1,0,1,0,1,1,1];
 ck(rows.every(r=>passes(r,correct)),"honest trace");
 // Exhaust every bit assignment, including both constants. Exactly one passes.
 let accepted=0,violating=0,localChecks=0;
 for(let i=0;i<128;i++){
  let bits=A(7,j=>(i>>j)&1),fault=rows.findIndex(r=>!passes(r,bits)),c=commit(ctx,rows,bits);
  if(fault<0){accepted++;for(let j=0;j<rows.length;j++){ck(!verify(c.inst,c.witness(j)),"false fraud");localChecks++}}
  else {violating++;ck(verify(c.inst,c.witness(fault)),"missing fraud witness");localChecks++}
 }
 ck(accepted===1&&violating===127,"exhaustive coverage");
 // Different gate operands cross three trace pages. All unreferenced
 // coordinates in this sparse fixture are just padding test data, not a full DAG.
 let b=A(520,i=>+(i===0||i===2||i===256));b[519]=0;
 const rr=[pin(0,1),pin(1,0),row(2,256,519,8)],c=commit(ctx,rr,b),w=c.witness(2);
 ck(verify(c.inst,w),"cross-page valid fraud");
 const bad=[];
 const reject=(name,i,v)=>{ck(!verify(i,v),name);bad.push(name)};
 const flip=x=>{let y=x.slice();y[0]^=1;return y};
 reject("row substitution",c.inst,{...w,row:row(2,256,519,6)});
 reject("row index substitution",c.inst,{...w,rowIndex:1});
 reject("padded row",c.inst,{...w,rowIndex:3});
 reject("row path truncated",c.inst,{...w,rowPath:w.rowPath.slice(1)});
 reject("row sibling mutation",c.inst,{...w,rowPath:[flip(w.rowPath[0]),...w.rowPath.slice(1)]});
 reject("wire page substitution",c.inst,{...w,slots:[w.slots[1],w.slots[0],w.slots[2]]});
 reject("wire page bit mutation",c.inst,{...w,slots:[{...w.slots[0],page:flip(w.slots[0].page)},...w.slots.slice(1)]});
 reject("wire path mutation",c.inst,{...w,slots:[{...w.slots[0],path:[flip(w.slots[0].path[0]),...w.slots[0].path.slice(1)]},...w.slots.slice(1)]});
 reject("wrong row root",{...c.inst,rowRoot:flip(c.inst.rowRoot)},w);
 reject("wrong trace root",{...c.inst,traceRoot:flip(c.inst.traceRoot)},w);
 reject("padded wire index",{...c.inst,slotCount:519},w);
 const contextFields=[];
 for(const [key,val] of Object.entries(ctx)){
  let alt={...ctx,[key]:typeof val==="number"?val+1:flip(val)};
  reject("context "+key,{...c.inst,s:session(alt)},w);contextFields.push(key);
 }
 const honest=commit(ctx,rr,b.map((x,i)=>i===519?1:x));reject("honest row",honest.inst,honest.witness(2));
 // A rejecting computation with a consistent internal trace violates only
 // the output pin. A forged accept bit instead violates the defining gate.
 let rr2=assemble(5,[[2,1],[3,1]],[row(2,3,4,6)],4);
 let out0=[1,0,1,1,0],z=commit(ctx,rr2,out0);
 ck(rr2.slice(0,-1).every(r=>passes(r,out0))&&verify(z.inst,z.witness(rr2.length-1)),"rejecting final pin");
 let out1=[1,0,1,1,1],z1=commit(ctx,rr2,out1);
 ck(verify(z1.inst,z1.witness(rr2.length-2)),"forged accept gate");
 return {scope:"Committed Boolean gate trace relation; test fixtures only; no WE, Nova full verifier or on-chain authorization",exhaustive_assignments:128,honest:accepted,fraud_detected:violating,authenticated_checks:localChecks,cross_page_fraud:true,rejecting_output_and_forged_accept:true,negative_controls:bad.length,negative_control_names:bad,context_fields_bound:contextFields,example:{session:hex(c.inst.s),row_root:hex(c.inst.rowRoot),trace_root:hex(c.inst.traceRoot),statement_hash:hex(hash(statement(c.inst))),row_count:c.inst.rowCount,slot_count:c.inst.slotCount,witness_bytes:8+32+32*w.rowPath.length+3*(32+32*w.slots[0].path.length)}};
}
return {hash,hex,fromHex,eq,concat,le,read,row,decode,pin,passes,tree,pages,commit,verify,session,statement,context,assemble,selftest,depth,ROW,TRACE,ck};
}
module.exports=traceLibrary();
if(require.main===module)console.log(JSON.stringify(module.exports.selftest(),null,2));
