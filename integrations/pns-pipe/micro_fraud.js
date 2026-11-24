'use strict';
// PNS-PIPE-02: exact Fr micro-operation fraud relation; test only.
function microLibrary(trace,ipa,params){
"use strict";
const {ck,Q,Bqs,PALLAS,VESTA,mod}=ipa,{hash,concat,le,read,hex}=trace;
const A=(n,f)=>Array.from({length:n},(_,i)=>f(i)),f=x=>mod(x,Q),con=x=>x?[[0,f(x)]]:[],lc=i=>[[i,1n]];
const sc=(a,k)=>a.map(([i,c])=>[i,f(c*k)]),add=(...a)=>a.flat();
const clean=a=>{let m=new Map();for(const [i,c] of a)m.set(i,f((m.get(i)||0n)+c));return [...m].filter(([,v])=>v!==0n).sort((a,b)=>a[0]-b[0])};
const ascii=s=>Uint8Array.from(s,c=>c.charCodeAt(0));
const sets=Object.fromEntries(Object.entries(params.sets).map(([t,s])=>[t,{...s,C:s.C.map(BigInt),M:s.M.map(a=>a.map(BigInt))}]));
for(const [t,s] of Object.entries(sets)){ck(s.C.length===(s.full+s.partial)*Number(t)&&s.M.length===Number(t)&&s.M.every(a=>a.length===Number(t)),"parameter shape");ck([...s.C,...s.M.flat()].every(x=>x>=0n&&x<Q),"parameter range")}
const pow=(a,n)=>{let x=f(a),z=1n;for(;n;n>>=1n,x=f(x*x))if(n&1n)z=f(z*x);return z};
function poseidon(init,inputs){
 const t=inputs.length+1,s=sets[t];ck(s,"arity");let st=[init,...inputs].map(f);
 for(let r=0;r<s.full+s.partial;r++){
   st=st.map((v,i)=>f(v+s.C[r*t+i]));
   const full=r<4||r>=4+s.partial;st=st.map((v,i)=>full||i===0?pow(v,5n):v);
   st=s.M.map(row=>f(row.reduce((v,c,i)=>v+c*st[i],0n)));
 }return st[0];
}
const fieldWord=(g,v)=>g.lcBits(g.bits(f(v),254));
const value=(g,a)=>f(g.eval(a));
function mul(g,a,b){const out=fieldWord(g,value(g,a)*value(g,b));g.row([[a,b]],out,"Fr mul");return out}
function materialize(g,a){const w=fieldWord(g,value(g,a));g.eq(w,a);return w}
function poseidonBqs(g,init,inputs){
 const t=inputs.length+1,s=sets[t];ck(s,"arity");let st=[con(init),...inputs];
 for(let r=0;r<s.full+s.partial;r++){
   st=st.map((v,i)=>clean(add(v,con(s.C[r*t+i]))));
   const full=r<4||r>=4+s.partial;
   st=st.map((a,i)=>{if(!full&&i!==0)return a;let b=mul(g,a,a),c=mul(g,b,b);return mul(g,c,a)});
   st=s.M.map(row=>clean(add(...row.map((k,i)=>sc(st[i],k)))));
   // Deterministic periodic materialization bounds coefficient density.
   if((r+1)%8===0&&r+1<s.full+s.partial)st=st.map(a=>materialize(g,a));
 }return st[0];
}
function tag(s,t){return read(hash(concat(ascii("PNS-PIPE-POSEIDON/v1\0"),s,Uint8Array.of(t))))%Q}
const BIT=1,PIN=2,MAC=4,MUL=8;
function record(op,a,b,z,c=0n){ck([BIT,PIN,MAC,MUL].includes(op),"op");return concat(Uint8Array.of(op),new Uint8Array(7),le(a),le(b),le(z),le(f(c),32))}
function decode(r){
 ck(r.length===64&&[BIT,PIN,MAC,MUL].includes(r[0])&&r.slice(1,8).every(v=>v===0),"row encoding");
 const idx=[8,16,24].map(i=>read(r.slice(i,i+8)));
 ck(idx.every(v=>v<=BigInt(Number.MAX_SAFE_INTEGER)),"index bound");
 const c=read(r.slice(32));ck(c<Q,"canonical coeff");
 return {op:r[0],a:Number(idx[0]),b:Number(idx[1]),z:Number(idx[2]),c}
}
function residual(r,w){const {op,a,b,z,c}=decode(r);let x=w[a],y=w[b],v=w[z];return f(op===BIT?v*v-v:op===PIN?v-c:op===MAC?v-x-c*y:v-x*y)}
// Every original Boolean slot gets a bit check. Constants and public bits
// are pinned independently. A fresh output is allocated for every derived
// accumulator or product. The source rows and pins, not a prover-selected
// netlist, determine this program.
function compile(rows,values,pins=[]){
 const w=values.map(BigInt),n=w.length,ops=[];ck(n>=2&&w.every(x=>x>=0n&&x<Q),"field trace");
 for(let i=0;i<n;i++)ops.push(record(BIT,0,0,i));
 ops.push(record(PIN,0,0,0,1n),record(PIN,0,0,1,0n));
 for(const [i,b] of pins){ck(Number.isInteger(i)&&i>=2&&i<n&&(b===0||b===1),"input pin");ops.push(record(PIN,0,0,i,BigInt(b)))}
 const derive=(op,a,b,c=0n)=>{ck(a<w.length&&b<w.length,"topology");const z=w.length;w.push(f(op===MAC?w[a]+c*w[b]:w[a]*w[b]));ops.push(record(op,a,b,z,c));return z};
 function linear(l){let z=1;for(const [i,c] of l){ck(Number.isInteger(i)&&i>=0&&i<n,"source wire");z=derive(MAC,z,i,c)}return z}
 const boundaries=[];
 for(const r of rows){let sum=1;for(const [a,b] of r.ab){const z=derive(MUL,linear(a),linear(b));sum=derive(MAC,sum,z,1n)}
   const rhs=linear(r.c),diff=derive(MAC,sum,rhs,-1n);ops.push(record(PIN,0,0,diff));boundaries.push(ops.length-1);
 }
 return {ops,w,original:n,boundaries}
}
function tree(s,kind,items){
 const count=items.length;ck(count>0,"empty");let len=2**Math.ceil(Math.log2(count));
 const leaf=kind===0?(x=>poseidon(tag(s,40),A(4,i=>read(x.slice(16*i,16*i+16))))):(x=>poseidon(tag(s,42),[x,0n]));
 const node=(a,b)=>poseidon(tag(s,kind===0?41:43),[a,b]);
 const l=A(len,i=>leaf(i<count?items[i]:kind===0?new Uint8Array(64):0n)),layers=[l];
 while(layers.at(-1).length>1){let p=layers.at(-1);layers.push(A(p.length/2,i=>node(p[i*2],p[i*2+1])))}
 return {root:layers.at(-1)[0],path:i=>{ck(i>=0&&i<count,"range");let p=[];for(let j=0;j<layers.length-1;j++){p.push(layers[j][i^1]);i=Math.floor(i/2)}return p}}
}
function depth(n){ck(n>0&&Number.isSafeInteger(n),"count");return Math.ceil(Math.log2(n))}
function open(s,kind,root,v,index,n,path){
 if(!Number.isSafeInteger(index)||index<0||index>=n||path.length!==depth(n)||path.some(x=>typeof x!=="bigint"||x<0n||x>=Q))return false;
 let h=kind===0?poseidon(tag(s,40),A(4,i=>read(v.slice(16*i,16*i+16)))):poseidon(tag(s,42),[v,0n]);
 for(const b of path){h=index%2===0?poseidon(tag(s,kind===0?41:43),[h,b]):poseidon(tag(s,kind===0?41:43),[b,h]);index=Math.floor(index/2)}
 return h===root;
}
function commit(s,prog){
 const rt=tree(s,0,prog.ops),vt=tree(s,1,prog.w),inst={s,rowRoot:rt.root,traceRoot:vt.root,rows:prog.ops.length,slots:prog.w.length};
 return {inst,witness:i=>{let row=prog.ops[i],r=decode(row);return {i,row,path:rt.path(i),values:[r.a,r.b,r.z].map(j=>({v:prog.w[j],path:vt.path(j)}))}}}
}
function verify(x,w){
 try{
  if(w.row.length!==64||!open(x.s,0,x.rowRoot,w.row,w.i,x.rows,w.path)||w.values.length!==3)return false;
  const r=decode(w.row),ids=[r.a,r.b,r.z];
  if(!ids.every((j,i)=>{let p=w.values[i];return typeof p.v==="bigint"&&p.v>=0n&&p.v<Q&&open(x.s,1,x.traceRoot,p.v,j,x.slots,p.path)}))return false;
  const [a,b,z]=w.values.map(p=>p.v);return f(r.op===BIT?z*z-z:r.op===PIN?z-r.c:r.op===MAC?z-a-r.c*b:z-a*b)!==0n;
 }catch{return false}
}
function range(g,bits,n){
 const v=g.number(bits),sl=v<BigInt(n)?BigInt(n)-1n-v:0n;
 g.eq(add(g.lcBits(bits),g.lcBits(g.bits(sl,64))),con(BigInt(n)-1n));
}
function pathBqs(g,s,kind,root,h,ids,path){
 for(let j=0;j<path.length;j++){
  const p=fieldWord(g,path[j]),q=lc(ids[j]);
  const l=fieldWord(g,g.val(ids[j])?value(g,p):value(g,h));
  g.row([[q,clean(add(p,sc(h,-1n)))]],clean(add(l,sc(h,-1n))),"direction");
  const r=clean(add(h,p,sc(l,-1n)));
  h=poseidonBqs(g,tag(s,kind===0?41:43),[l,r]);
 }
 g.eq(h,con(root));
}
function bqs(x,w){
 ck(w.path.length===depth(x.rows)&&w.values.length===3&&w.values.every(a=>a.path.length===depth(x.slots))&&w.row.length===64,"framing");
 let terms=0,maxTerms=0;const g=new Bqs(null,false,(ab,c)=>{let m=c.length+ab.reduce((n,[a,b])=>n+a.length+b.length,0);terms+=m;maxTerms=Math.max(m,maxTerms)});
 const ix=g.bits(BigInt(w.i),64),rb=Array.from(w.row).flatMap(b=>A(8,i=>g.bit(BigInt(b>>i&1))));
 range(g,ix,x.rows);
 let leaf=poseidonBqs(g,tag(x.s,40),A(4,i=>g.lcBits(rb.slice(128*i,128*i+128))));
 pathBqs(g,x.s,0,x.rowRoot,leaf,ix,w.path);
 // Four one-hot opcode bits, remaining header bytes zero.
 const op=rb.slice(0,4);g.eq(op.map(i=>[i,1n]),con(1n));g.lin(rb.slice(4,64).map(i=>[i,1n]));
 const ids=A(3,i=>rb.slice(64+64*i,128+64*i)),coeff=rb.slice(256,512);
 g.lin(lc(coeff[255]));g.canonical(g.number(coeff.slice(0,255)),Q,coeff.slice(0,255));
 const c=g.lcBits(coeff),v=[];
 for(let i=0;i<3;i++){
  range(g,ids[i],x.slots);
  const p=fieldWord(g,w.values[i].v);v.push(p);
  const h=poseidonBqs(g,tag(x.s,42),[p,[]]);
  pathBqs(g,x.s,1,x.traceRoot,h,ids[i],w.values[i].path);
 }
 const [a,b,z]=v,zz=mul(g,z,z),cb=mul(g,c,b),ab=mul(g,a,b);
 const rs=[clean(add(zz,sc(z,-1n))),clean(add(z,sc(c,-1n))),clean(add(z,sc(a,-1n),sc(cb,-1n))),clean(add(z,sc(ab,-1n)))];
 const result=f(rs.reduce((s,r,i)=>s+value(g,r)*g.val(op[i]),0n)),r=fieldWord(g,result);
 g.row(rs.map((a,i)=>[lc(op[i]),a]),r,"select residual");
 const inv=fieldWord(g,result===0n?0n:pow(result,Q-2n));
 g.row([[r,inv]],con(1n),"nonzero fault");
 return {...g.stats(),linear_form_terms:terms,max_row_terms:maxTerms,accepted:g.failed===0,hashes:4+depth(x.rows)+3*depth(x.slots)};
}
function selftest(){
 ck(poseidon(0n,[1n,2n])===0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189an,"upstream t3 vector");
 ck(poseidon(0n,[1n,2n,3n,4n])===0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465n,"upstream t5 vector");
 ck(poseidon(7n,[1n,2n,3n,4n])===1569211601569591254857354699102545060324851338714426496554851741114291465006n,"upstream initState vector");
 const hashes=[];
 for(const inputs of [[1n,2n],[1n,2n,3n,4n]]){let g=new Bqs(),ws=inputs.map(x=>fieldWord(g,x)),b=g.stats(),h=poseidonBqs(g,0n,ws);g.eq(h,con(poseidon(0n,inputs)));ck(g.failed===0,"BQS hash");let a=g.stats();hashes.push({arity:inputs.length,boolean_unknowns:a.boolean_unknowns-b.boolean_unknowns,equations:a.equations-b.equations})}
 const rows=[{ab:[[[[2,1n]],[[3,1n]]]],c:[[4,1n]]}],s=hash(ascii("PNS PIPE micro-op test")),pins=[[2,1],[3,1]];
 let honest=compile(rows,[1,0,1,1,1],pins),bad=compile(rows,[1,0,1,1,0],pins);
 ck(honest.ops.every(r=>residual(r,honest.w)===0n),"honest microops");
 const fault=bad.ops.findIndex(r=>residual(r,bad.w)!==0n);ck(fault===bad.boundaries[0],"terminal fault");
 const c=commit(s,bad),w=c.witness(fault),ok=verify(c.inst,w);ck(ok,"native fault");
 let nativeControls=0;
 for(const [inst,ww] of [[{...c.inst,rowRoot:f(c.inst.rowRoot+1n)},w],[{...c.inst,traceRoot:f(c.inst.traceRoot+1n)},w],[{...c.inst,s:hash(ascii("wrong session"))},w],[c.inst,{...w,i:(w.i+1)%c.inst.rows}],[c.inst,{...w,values:[w.values[0],w.values[2],w.values[1]]}],[c.inst,{...w,values:[...w.values.slice(0,2),{...w.values[2],v:f(w.values[2].v+1n)}]}]]){
   ck(!verify(inst,ww),"wrong opening");nativeControls++;
 }
 const good=commit(s,honest),goodW=good.witness(fault);ck(!verify(good.inst,goodW),"honest no fraud");nativeControls++;
 const p=bqs(c.inst,w);ck(p.accepted,"BQS fraud");
 const n=bqs(good.inst,goodW);ck(!n.accepted&&n.failed_rows===1,"BQS honest");
 ck(p.boolean_unknowns===n.boolean_unknowns&&p.equations===n.equations,"fixed shape size");
 // Verify the transformation on a real Pallas/Vesta arithmetic component
 // (the same exact sparse rows used by PNS-04C), without generating a huge
 // Merkle tree or encrypting it. Trace an honest assignment and one mutation.
 const arithmetic=[];
 for(const [name,prime] of [["PallasBase",PALLAS],["VestaBase",VESTA]]){
  let g=new Bqs(null,true),a=g.scalar(prime-1n,prime),b=g.scalar(123456789n,prime);
  g.mul(a,b,prime);ck(g.failed===0,"native sparse rows");
  let bits=A(g.w.n,i=>g.w.at(i)),h=compile(g.saved,bits);
  ck(h.ops.every(r=>residual(r,h.w)===0n),"actual sparse conversion");
  let mutated=bits.slice();mutated[a.ids[0]]^=1;let h2=compile(g.saved,mutated);
  ck(h.ops.every((r,i)=>trace.eq(r,h2.ops[i])),"witness-independent program");
  let fail=h2.ops.filter(r=>residual(r,h2.w)!==0n).length;ck(fail>0,"actual corrupted trace");
  arithmetic.push({field:name,original_rows:g.nrows,original_slots:bits.length,micro_ops:h.ops.length,trace_slots:h.w.length,field_trace_bytes:32*h.w.length,program_bytes:64*h.ops.length,mutated_failed_rows:fail});
 }
 return {scope:"Pinned Poseidon arithmetic hash and fixed sparse-row micro-op fraud prototype; no complete Nova trace or WE",upstream_vectors:3,hashes,local:{rows:c.inst.rows,slots:c.inst.slots,witness_native_rejections:nativeControls,positive:p,negative:n},arithmetic};
}
return {poseidon,poseidonBqs,compile,commit,verify,bqs,residual,selftest};
}
module.exports=microLibrary(require('./trace_fraud.js'),require('../praxis-nova/bqs/ipa_bqs.js'),require('./poseidon-params.json'));
if(require.main===module)console.log(JSON.stringify(module.exports.selftest(),null,2));
