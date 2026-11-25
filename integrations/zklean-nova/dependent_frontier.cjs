// ZKL-NOVA-14: single-pass append frontier with shared-path dependent admission.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function arithmetic(fixtures,profile,mode,sink){
"use strict";
const P=28948022309329048855892746252171976963363056481941647379679742748393362948097n;
const mod=x=>((x%P)+P)%P,req=(v,m="constraint check")=>{if(!v)throw Error(m)};
const tags=["S","B","F","P","L","A","E","X","Q0","Q1","I0","I2","VR","VS","VT","VB","VA","VP","VL","JS","JV","JP","JL","JA","JC"];
const id=t=>{let i=tags.indexOf(t);req(i>=0);return i+1};
const arity=[1,1,1,2,2,2,0,3,3,4,4,6,1,1,2,3,4,7,7,3,4,7,8,6,6];
const T=tags.slice(0,6),C=["E","X"],Q=["Q0","Q1"],I=["I0","I2"],V=tags.slice(12,19),J=tags.slice(19);
const W=14,D=10,K=10,F=9,G=10,DEP=11,LEFT=12,RIGHT=13;
const constant=x=>[[0,mod(BigInt(x))]],add=(...xs)=>{let m=new Map;for(const x of xs)for(const [i,a] of x)m.set(i,mod((m.get(i)||0n)+a));return [...m].filter(e=>e[1]!==0n).sort((a,b)=>a[0]-b[0])};
const scale=(a,x)=>x.map(([i,b])=>[i,mod(BigInt(a)*b)]).filter(x=>x[1]!==0n),sub=(a,b)=>add(a,scale(-1,b));
function inv(x){let a=x,b=P,u=1n,v=0n;while(b){let q=a/b;[a,b]=[b,a-q*b];[u,v]=[v,u-q*v]}req(a===1n);return mod(u)}
const val=(w,l)=>mod(l.reduce((s,[i,a])=>s+w[i]*a,0n));
class CS{
 constructor(){this.ops=[null];this.rows=[];this.names=["ONE"];this.inputIds=[];this.phase="";this.labels=[]}
 alloc(fn,name){let i=this.ops.length;this.ops.push(fn);this.names.push(name||"");return [[i,1n]]}
 input(name){let i=this.ops.length;this.inputIds.push(i);return this.alloc(null,name)}
 enforce(a,b,c){this.rows.push([a,b,c]);this.labels.push(this.phase)}
 eq(a,b=constant(0)){this.enforce(sub(a,b),constant(1),[])}
 mul(a,b,name){let z=this.alloc(w=>val(w,a)*val(w,b),name);this.enforce(a,b,z);return z}
 bit(a){this.enforce(a,sub(a,constant(1)),[])}
 bound(a,n){let bits=Array.from({length:n},(_,i)=>this.alloc(w=>(val(w,a)>>BigInt(i))&1n,"range-bit"));for(const b of bits)this.bit(b);this.eq(a,add(...bits.map((b,i)=>scale(1n<<BigInt(i),b))));return bits}
 zero(a){let z=this.alloc(w=>val(w,a)===0n?1n:0n,"zero-bit"),u=this.alloc(w=>{let x=val(w,a);return x===0n?0n:inv(x)},"inverse");this.enforce(a,u,sub(constant(1),z));this.enforce(a,z,[]);return z}
 witness(inputs){req(inputs.length===this.inputIds.length);let w=[1n],j=0;for(let i=1;i<this.ops.length;i++){let op=this.ops[i];w.push(mod(op?op(w):BigInt(inputs[j++])))}return w}
 verify(w){return w.length===this.ops.length&&w[0]===1n&&w.every(x=>typeof x==="bigint"&&x>=0n&&x<P)&&this.rows.every(([a,b,c])=>mod(val(w,a)*val(w,b)-val(w,c))===0n)}
}
const cs=new CS, c=constant, eq=(g,a,b=c(0))=>cs.enforce(g,sub(a,b),[]),
le=(g,a,b)=>cs.bound(cs.mul(g,sub(b,a)),D),lt=(g,a,b)=>le(g,add(a,c(1)),b),
mx=(g,z,a,b)=>{le(g,a,z);le(g,b,z);eq(g,cs.mul(sub(z,a),sub(z,b)))};
const n=cs.input("count");cs.bound(n,D);
const r=Array.from({length:W},(_,i)=>cs.input("row"+i));
const read=Array.from({length:K},(_,j)=>({i:cs.input("address"+j),r:Array.from({length:W},(_,k)=>cs.input("read"+j+"_"+k))}));
cs.phase="range";r.forEach(x=>cs.bound(x,D));for(const p of read){cs.bound(p.i,D);p.r.forEach(x=>cs.bound(x,D))}
const zeros=new Map;
function iz(x,k){let key=x.map(([i,v])=>i+":"+v).join(",")+"="+k;if(!zeros.has(key))zeros.set(key,cs.zero(sub(x,c(k))));return zeros.get(key)}
const kind=(x,ts)=>add(...ts.map(t=>iz(x[0],id(t))));
const sels=Object.fromEntries(tags.map(t=>[t,iz(r[0],id(t))]));
cs.eq(add(...Object.values(sels)),c(1));
const plans={},usage=Array.from({length:K},()=>[]);
let activeTag,g,slot;
function need(ix,ks){
 let j=slot++;req(j<K,"too many reads "+activeTag);let p=read[j];
 usage[j].push(g);plans[activeTag].push(ix);
 eq(g,p.i,ix);eq(g,kind(p.r,ks),c(1));return p.r
}
function loc(x,d){eq(g,x[G]);le(g,x[F],d)}
function is(x,ks){eq(g,kind(x,ks),c(1))}
function inst(x,t,k,s,o){is(x,I);eq(g,x[1],t);eq(g,x[2],k);eq(g,x[3],s);eq(g,x[4],o)}
function judgment(){
 let ctx=need(r[1],C),subj=need(r[2],T),ty=need(r[3],T);loc(subj,ctx[DEP]);loc(ty,ctx[DEP]);return [ctx,subj,ty]
}
function endpoints(a,b){let x=need(a,T),y=need(b,T);eq(g,x[G]);eq(g,y[G]);eq(g,r[LEFT],a);eq(g,r[RIGHT],b)}
for(const t of tags){
 activeTag=t;g=sels[t];slot=0;plans[t]=[];
 cs.phase="canonical";for(let j=1+arity[id(t)-1];j<=8;j++)eq(g,r[j]);
 for(const j of [F,G,DEP,LEFT,RIGHT])if(!(T.includes(t)&&[F,G].includes(j)||C.includes(t)&&j===DEP||V.includes(t)&&[LEFT,RIGHT].includes(j)))eq(g,r[j]);
 cs.phase="rule_"+t;
 const a=r[1],b=r[2],d=r[3],e=r[4],h=r[5],l=r[6],m=r[7],z=r[8];
 switch(t){
 case "S":case "B":case "F":
  le(g,a,c(t==="S"?8:255));eq(g,r[F],t==="F"?add(a,c(1)):c(0));eq(g,r[G],t==="B"?add(a,c(1)):c(0));break;
 case "P":case "L":case "A":{
  const x=need(a,T),y=need(b,T);mx(g,r[F],x[F],y[F]);mx(g,r[G],x[G],sub(y[G],c(t==="A"?0:1)));break}
 case "E":eq(g,r[DEP]);break;
 case "X":{
  const p=need(a,C),x=need(b,T),w=need(d,J);need(w[3],["S"]);eq(g,w[1],a);eq(g,w[2],b);loc(x,p[DEP]);lt(g,p[DEP],c(256));eq(g,r[DEP],add(p[DEP],c(1)));break}
 case "Q0":case "Q1":{
  const p=need(a,["X"]);need(d,T);lt(g,b,p[DEP]);
  if(t==="Q0"){eq(g,b,sub(p[DEP],c(1)));eq(g,d,p[2])}
  else{const w=need(e,Q);lt(g,b,sub(p[DEP],c(1)));eq(g,w[1],p[1]);eq(g,w[2],b);eq(g,w[3],d)}
  break}
 case "I0":case "I2":{
  const x=need(a,t==="I0"?["S","B","F"]:["P","L","A"]),s=need(d,T),o=need(e,T);
  le(g,b,c(255));eq(g,s[G]);
  if(t==="I0"){
   const match=cs.mul(kind(x,["B"]),cs.zero(sub(x[1],b)));
   eq(g,e,add(a,cs.mul(match,sub(d,a))));
  }else{
   const q=need(h,I),p=need(l,I);eq(g,o[0],x[0]);inst(q,x[1],b,d,o[1]);inst(p,x[2],add(b,kind(x,["P","L"])),d,o[2]);
  }break}
 case "VR":endpoints(a,a);break;
 case "VS":{const q=need(a,V);endpoints(q[RIGHT],q[LEFT]);break}
 case "VT":{const q=need(a,V),p=need(b,V);eq(g,q[RIGHT],p[LEFT]);endpoints(q[LEFT],p[RIGHT]);break}
 case "VB":{
  const x=need(a,["A"]),y=need(b,T),w=need(d,I),f=need(x[1],["L"]);
  eq(g,x[G]);eq(g,y[G]);inst(w,f[2],c(0),x[2],b);eq(g,r[LEFT],a);eq(g,r[RIGHT],b);break}
 case "VA":{
  const x=need(a,V),y=need(b,V),p=need(d,["A"]),q=need(e,["A"]);
  eq(g,p[1],x[LEFT]);eq(g,q[1],x[RIGHT]);eq(g,p[2],y[LEFT]);eq(g,q[2],y[RIGHT]);eq(g,p[G]);eq(g,q[G]);eq(g,r[LEFT],d);eq(g,r[RIGHT],e);break}
 case "VP":case "VL":{
  const ty=t==="VP"?"P":"L",x=need(a,[ty]),y=need(b,[ty]),dc=need(d,V),fv=need(e,["F"]),il=need(h,I),ir=need(l,I),bc=need(m,V);
  eq(g,x[G]);eq(g,y[G]);eq(g,dc[LEFT],x[1]);eq(g,dc[RIGHT],y[1]);le(g,x[F],fv[1]);le(g,y[F],fv[1]);
  inst(il,x[2],c(0),e,bc[LEFT]);inst(ir,y[2],c(0),e,bc[RIGHT]);eq(g,r[LEFT],a);eq(g,r[RIGHT],b);break}
 case "JS":{
  const [ctx,x,y]=judgment();is(x,["S"]);is(y,["S"]);eq(g,y[1],add(x[1],c(1)));break}
 case "JV":{
  const [ctx,x,y]=judgment(),w=need(e,Q);is(x,["F"]);eq(g,w[1],a);eq(g,w[2],x[1]);eq(g,w[3],d);break}
 case "JP":{
  const [ctx,x,y]=judgment(),da=need(e,J),bo=need(h,J),fv=need(l,["F"]),o=need(m,I),ext=need(bo[1],["X"]),u=need(da[3],["S"]),v=need(bo[3],["S"]);
  is(x,["P"]);is(y,["S"]);eq(g,da[1],a);eq(g,da[2],x[1]);eq(g,ext[1],a);eq(g,ext[2],x[1]);eq(g,fv[1],ctx[DEP]);inst(o,x[2],c(0),l,bo[2]);
  const vz=iz(v[1],0);eq(cs.mul(g,vz),y[1]);mx(cs.mul(g,sub(c(1),vz)),y[1],u[1],v[1]);break}
 case "JL":{
  const [ctx,x,y]=judgment(),pj=need(e,J),bj=need(h,J),fv=need(l,["F"]),bi=need(m,I),ti=need(z,I),ext=need(bj[1],["X"]);need(pj[3],["S"]);
  is(x,["L"]);is(y,["P"]);eq(g,x[1],y[1]);eq(g,pj[1],a);eq(g,pj[2],d);eq(g,ext[1],a);eq(g,ext[2],x[1]);eq(g,fv[1],ctx[DEP]);
  inst(bi,x[2],c(0),l,bj[2]);inst(ti,y[2],c(0),l,bj[3]);break}
 case "JA":{
  const [ctx,x,y]=judgment(),fj=need(e,J),aj=need(h,J),o=need(l,I),ft=need(fj[3],["P"]);
  is(x,["A"]);eq(g,fj[1],a);eq(g,aj[1],a);eq(g,fj[2],x[1]);eq(g,aj[2],x[2]);eq(g,aj[3],ft[1]);inst(o,ft[2],c(0),x[2],d);break}
 case "JC":{
  const [ctx,x,y]=judgment(),from=need(e,J),cv=need(h,V),to=need(l,J);need(to[3],["S"]);
  eq(g,from[1],a);eq(g,from[2],b);eq(g,cv[LEFT],from[3]);eq(g,cv[RIGHT],d);eq(g,to[1],a);eq(g,to[2],d);break}
 default:req(false)
 }
}
cs.phase="admission";
for(let j=0;j<K;j++){
 const act=add(...usage[j]),p=read[j];lt(act,p.i,n);
 for(const x of [p.i,...p.r])eq(sub(c(1),act),x);
}
const rawRecord=(row,hist)=>{
 const t=row[0],r=[id(t),...row.slice(1)];while(r.length<W)r.push(0);
 const [_,a,b,d,e]=r,h=i=>hist[i];
 if(T.includes(t)){
  if(t==="F")r[F]=a+1;else if(t==="B")r[G]=a+1;
  else if(["P","L","A"].includes(t)){r[F]=Math.max(h(a)[F],h(b)[F]);r[G]=Math.max(h(a)[G],h(b)[G]-(t==="A"?0:1),0)}
 }else if(t==="X")r[DEP]=h(a)[DEP]+1;
 else if(V.includes(t)){
  if(t==="VR")r[LEFT]=r[RIGHT]=a;
  if(t==="VS"){r[LEFT]=h(a)[RIGHT];r[RIGHT]=h(a)[LEFT]}
  if(t==="VT"){r[LEFT]=h(a)[LEFT];r[RIGHT]=h(b)[RIGHT]}
  if(["VB","VP","VL"].includes(t)){r[LEFT]=a;r[RIGHT]=b}
  if(t==="VA"){r[LEFT]=d;r[RIGHT]=e}
 }
 return r
};
function makeInputs(row,hist){
 let rec=rawRecord(row,hist),input=[hist.length,...rec];
 // Symbolic address expressions use only current row and prior read inputs,
 // not internal wires. Resolve them against the partial input assignment.
 let w=Array(cs.ops.length).fill(0n);w[0]=1n;
 function refresh(){input.forEach((x,j)=>w[cs.inputIds[j]]=BigInt(x))}
 refresh();
 for(let j=0;j<K;j++){
  let expr=plans[row[0]][j];if(!expr){input.push(0,...Array(W).fill(0));refresh();continue}
  let i=Number(val(w,expr));req(i<hist.length&&i>=0,"witness address");input.push(i,...hist[i]);refresh();
 }
 return {rec,input}
}

let auth=null;
if(mode){
 const depth=9,capacity=1<<depth, NODE=0x5a4b4c31312f4e4fn, LEAF=0x5a4b4c31312f4c46n, TERM=0x5a4b4c31312f5400n;
 const dec=s=>{req(typeof s==="string"&&/^[0-9a-f]{64}$/.test(s));let v=BigInt("0x"+s.match(/../g).reverse().join(""));req(v<P);return v};
 req(profile.width===6&&profile.rate===5&&profile.rf===8&&profile.rp===56&&profile.crc.length===104&&profile.s==="Standard"&&profile.ht==="Sponge");
 const rc=profile.crc.map(dec),md=profile.mds.map(x=>x.map(dec)),pre=profile.psm.map(x=>x.map(dec)),sp=profile.sm.map(x=>[x.w_hat.map(dec),x.v_rest.map(dec)]);
 const IO=(1n<<128n)-159n,io=n=>(IO*(BigInt(n)+(1n<<31n))+IO*IO)%(1n<<128n);
 // A single pinned permutation for each of the supported fixed-arity
 // sponge calls. Native and symbolic implementations share the schedule.
 function perm(x,plus,sc,pow5){
  x=x.map((a,i)=>plus(a,sc(rc[i],plus.one)));let j=6;
  const dot=(a,b)=>a.reduce((z,v,i)=>plus(z,sc(b[i],v)),plus.zero);
  for(let q=0;q<64;q++){
   if(q>=4&&q<60){
    x[0]=plus(pow5(x[0]),sc(rc[j++],plus.one));const [w,v]=sp[q-4],y=x[0];
    x=[dot(x,w),...x.slice(1).map((z,i)=>plus(z,sc(v[i],y)))];
   }else{
    x=x.map(pow5);if(q!==63)x=x.map(z=>plus(z,sc(rc[j++],plus.one)));
    x=q===3?x.map((_,k)=>dot(x,pre.map(row=>row[k]))):md.map(row=>dot(x,row));
   }
  }req(j===104);return x[1]
 }
 const np=(a,b)=>mod(a+b);np.zero=0n;np.one=1n;
 const cp=(a,b)=>add(a,b);cp.zero=[];cp.one=c(1);
 function native(dom,...xs){const v=[io(xs.length+1),dom,...xs];while(v.length<6)v.push(0n);return perm(v,np,(a,b)=>mod(a*b),x=>mod(x**5n))}
 let hashes=0;
 function hash(dom,...xs){
  hashes++;const old=cs.phase;cs.phase="poseidon";let v=[c(io(xs.length+1)),dom,...xs];while(v.length<6)v.push([]);
  const out=perm(v,cp,scale,x=>{let q=cs.mul(x,x,"sbox-square"),r=cs.mul(q,q,"sbox-fourth");return cs.mul(r,x,"sbox-fifth")});
  cs.phase=old;return out
 }
 const flags=add(...T.map(t=>sels[t])),pairFlag=add(...["P","L","A"].map(t=>sels[t])),atomFlag=sub(flags,pairFlag);
 // Additional external witness inputs. Their addresses and values are
 // constrained by the already synthesized local relation and this layer.
 const td=cs.input("new-term-digest"),salt=cs.input("new-salt");
 const extra=read.map((p,j)=>({digest:cs.input("historical-digest"+j),salt:cs.input("historical-salt"+j)}));
 const missing=[];let slots=K;
 for(let l=0;l<depth;l++){missing.push(Array.from({length:slots},(_,j)=>cs.input("mp-sibling"+l+"_"+j)));slots=Math.min(K,capacity>>(l+1))}
 const root=cs.input("root-in"),goal=cs.input("goal-in"),sealed=cs.input("sealed-in");
 const rootOut=cs.input("root-out"),countOut=cs.input("count-out"),goalOut=cs.input("goal-out"),sealOut=cs.input("sealed-out");
 const frontier=Array.from({length:depth},(_,l)=>cs.input("frontier-in"+l));
 const frontierOut=Array.from({length:depth},(_,l)=>cs.input("frontier-out"+l));
 const zeroRoots=[0n];for(let l=0;l<depth;l++)zeroRoots.push(native(NODE,zeroRoots[l],zeroRoots[l]));
 cs.phase="state";
 const nb=cs.bound(n,depth);cs.eq(sealed);cs.eq(countOut,add(n,c(1)));cs.eq(goalOut,goal);cs.bit(sealOut);
 const left=add(cs.mul(atomFlag,r[1]),cs.mul(pairFlag,extra[0].digest)),right=cs.mul(pairFlag,extra[1].digest);
 cs.eq(td,cs.mul(flags,hash(add(c(TERM),r[0]),left,right)));
 const packed=(a,row)=>add(...row.map((x,j)=>scale(1n<<BigInt(D*j),x)),scale(1n<<BigInt(D*W),a));
 const leaf=(addr,row,d,s)=>hash(c(LEAF),packed(addr,row),d,s);
 const asc=(h,bits,siblings)=>{
  for(let l=0;l<depth;l++){let q=siblings[l],u=add(h,cs.mul(bits[l],sub(q,h)));h=hash(c(NODE),u,sub(add(h,q),u))}
  return h
 };

 // The local kernel determines every read address and activity flag.
 // First bind each leaf to its entire record, address, term digest and salt.
 let nodes=[];
 for(let j=0;j<K;j++){
  cs.phase="read-auth";const act=add(...usage[j]),p=read[j],x=extra[j];
  for(const z of [x.digest,x.salt])eq(sub(c(1),act),z);
  const h=leaf(p.i,p.r,x.digest,x.salt);eq(act,cs.zero(h));
  nodes.push([add(p.i,scale(BigInt(capacity),sub(c(1),act))),cs.mul(act,h)]);
 }
 // Fixed sorting network. Inactive key is capacity, after every active key.
 // Offset 2^(depth+1)-1 makes its high bit exactly [left > right].
 cs.phase="sort";
 function swapData(x,y,s){
  const a=[],b=[];
  for(let j=0;j<x.length;j++){let d=cs.mul(s,sub(y[j],x[j]));a.push(add(x[j],d));b.push(sub(y[j],d))}
  return [a,b]
 }
 function bubble(x,swap){
  for(let pass=0;pass<x.length-1;pass++)for(let j=0;j<x.length-1-pass;j++)
   [x[j],x[j+1]]=swap(x[j],x[j+1]);
  return x
 }
 nodes=bubble(nodes,(a,b)=>{
  const bits=cs.bound(add(sub(a[0],b[0]),c((1<<(depth+1))-1)),depth+2);
  return swapData(a,b,bits[depth+1])
 });
 // Preserve every distinct active leaf. For repeated addresses, the digest
 // equality must be proved before removing duplicates.
 cs.phase="dedup";
 nodes=nodes.map((x,j,all)=>{
  let a=sub(c(1),cs.zero(sub(x[0],c(capacity)))),dup=c(0);
  if(j>0){dup=cs.mul(a,cs.zero(sub(x[0],all[j-1][0])));eq(dup,x[1],all[j-1][1])}
  const h=sub(a,dup);return [h,cs.mul(h,x[0]),cs.mul(h,x[1])]
 });
 function compact(x){
  return bubble(x,(a,b)=>{
   const s=cs.mul(sub(c(1),a[0]),b[0]);
   const out=[add(a[0],s)],other=[sub(b[0],s)];
   for(let j=1;j<a.length;j++){const d=cs.mul(s,sub(b[j],a[j]));out.push(add(a[j],d));other.push(sub(b[j],d))}
   return [out,other]
  })
 }
 nodes=compact(nodes);
 // Each level consumes a sorted, unique, active prefix. Adjacent siblings
 // are paired; singleton groups require exactly one authenticated sibling.
 // Stable compaction places all groups into the exact worst-case parent
 // capacity before hashing. Zero-tail constraints prevent dropping a group.
 for(let l=0;l<depth;l++){
  cs.phase="pairing";
  const m=nodes.length,width=depth-l;
  const parity=nodes.map(x=>cs.bound(x[1],width)[0]);
  const pair=nodes.map((x,j)=>{
   if(j+1===m)return c(0);
   const adj=cs.zero(sub(nodes[j+1][1],add(x[1],c(1))));
   return cs.mul(cs.mul(nodes[j+1][0],sub(c(1),parity[j])),adj)
  });
  let groups=nodes.map((x,j)=>{
   const a=sub(x[0],j?pair[j-1]:c(0)),p=scale((P+1n)/2n,sub(x[1],parity[j]));
   const odd=cs.mul(a,parity[j]),even=sub(a,odd),sib=missing[l][j];
   eq(add(sub(c(1),a),pair[j]),sib);
   const left=add(cs.mul(even,x[2]),cs.mul(parity[j],sib));
   const right=add(cs.mul(odd,x[2]),cs.mul(pair[j],j+1<m?nodes[j+1][2]:c(0)),cs.mul(sub(c(1),parity[j]),sib));
   return [a,cs.mul(a,p),left,right]
  });
  cs.phase="compact";groups=compact(groups);
  const cap=Math.min(K,capacity>>(l+1));
  for(let j=cap;j<groups.length;j++)for(const v of groups[j])cs.eq(v);
  nodes=groups.slice(0,cap).map(([a,p,left,right])=>[a,p,cs.mul(a,hash(c(NODE),left,right))]);
 }
 req(nodes.length===1);cs.eq(nodes[0][1]);eq(nodes[0][0],nodes[0][2],root);
 cs.phase="append-auth";const newLeaf=leaf(n,r,td,salt);cs.eq(cs.zero(newLeaf));
 // The pinned recursive input state carries the frontier invariant. No
 // second old-root path is needed: genesis and every prior transition
 // establish that the root is the sparse-prefix root of these slots.
 // Before level l, h is the padded subtree containing the inserted leaf.
 // If carry=1, h is a complete subtree of size 2^l.
 let h=newLeaf,carry=c(1);
 for(let l=0;l<depth;l++){
  const b=nb[l],f=frontier[l];
  eq(sub(c(1),b),f);
  const nextCarry=cs.mul(carry,b);
  const install=sub(carry,nextCarry);
  const want=add(cs.mul(sub(c(1),carry),f),cs.mul(install,h));
  cs.eq(frontierOut[l],want);
  const left=add(h,cs.mul(b,sub(f,h)));
  const right=add(c(zeroRoots[l]),cs.mul(b,sub(h,c(zeroRoots[l]))));
  h=hash(c(NODE),left,right);carry=nextCarry;
 }
 cs.eq(h,rootOut);
 cs.phase="seal";eq(sealOut,kind(r,J),c(1));eq(sealOut,kind(read[0].r,["E"]),c(1));eq(sealOut,extra[2].digest,goal);
 const indices=[root,n,goal,sealed,...frontier,rootOut,countOut,goalOut,sealOut,...frontierOut].map(x=>x[0][0]);
 const pnative=(i,row)=>row.reduce((z,x,j)=>z+(BigInt(x)<<BigInt(D*j)),BigInt(i)<<BigInt(D*W));
 const nleaf=(i,row,d,s)=>native(LEAF,pnative(i,row),d,s);
 const ndigest=(row,hist)=>{
  const t=tags[row[0]-1];if(!T.includes(t))return 0n;
  return native(TERM+BigInt(row[0]),["P","L","A"].includes(t)?hist[row[1]].digest:BigInt(row[1]),["P","L","A"].includes(t)?hist[row[2]].digest:0n)
 };
 function goalDigest(ast){const t=ast[0],pair=["P","L","A"].includes(t);return native(TERM+BigInt(id(t)),pair?goalDigest(ast[1]):BigInt(ast[1]),pair?goalDigest(ast[2]):0n)}

 // Incremental native tree, O(depth) updates rather than rebuilding the
 // complete tree at each row. All witness paths still refer to the old root.
 function emptyTree(){
  let z=0n,a=[Array(capacity).fill(z)];
  for(let l=0;l<depth;l++){z=native(NODE,z,z);a.push(Array(capacity>>(l+1)).fill(z))}return a
 }
 function insert(a,i,v){
  req(a[0][i]===0n);a[0][i]=v;
  for(let l=0;l<depth;l++){i>>=1;a[l+1][i]=native(NODE,a[l][2*i],a[l][2*i+1])}
 }
 const path=(a,i)=>Array.from({length:depth},(_,l)=>a[l][(i>>l)^1]);
 // Canonical frontier extracted independently from the reference full tree.
 function frontierSlots(t,n){return Array.from({length:depth},(_,l)=>(n>>l)&1?t[l][(n>>l)-1]:0n)}
 function frontierStep(n,f,leaf){
  let h=leaf,carry=1,g=[];
  for(let l=0;l<depth;l++){
   const b=(n>>l)&1;
   req(b||f[l]===0n,"dirty inactive frontier");
   g.push(carry?(b?0n:h):f[l]);
   h=b?native(NODE,f[l],h):native(NODE,h,zeroRoots[l]);
   carry&=b;
  }
  return {root:h,slots:g}
 }
 // Independent boundary check across every prefix of a full depth-nine tree.
 let boundaryTree=emptyTree(),boundaryChecks=0;
 for(let i=0;i<capacity;i++){
  const prior=frontierSlots(boundaryTree,i),leaf=BigInt(i+1),computed=frontierStep(i,prior,leaf);
  insert(boundaryTree,i,leaf);
  req(computed.root===boundaryTree[depth][0],"boundary root");
  req(computed.slots.every((x,l)=>x===frontierSlots(boundaryTree,i+1)[l]),"boundary slot");
  boundaryChecks++;
 }


 const matrixInfo={depth,state_ids:indices,hashes,constraints:cs.rows.length,wires:cs.ops.length,nonzeros:cs.rows.reduce((s,row)=>s+row.reduce((a,l)=>a+l.length,0),0),hash_constraints:cs.labels.filter(x=>x==="poseidon").length,
 node_domain:NODE.toString(),leaf_domain:LEAF.toString(),term_domain:TERM.toString(),node_vector:native(NODE,19n,42n).toString(),leaf_vector:native(LEAF,123n,456n,789n).toString()};
 if(mode==="full")sink.matrix({schema:"zkl-nova-14/frontier-auth-v1",summary:matrixInfo,rows:cs.rows.map(row=>row.map(l=>l.map(([i,v])=>[i,v.toString()])))});
 let cases=[],seen=new Set;const regenerated={empty_dirty_sibling:0,terminal_payload:0,conflicting_duplicate:0,frontier_inactive:0,frontier_output:0,frontier_active:0};let readStats={rows:0,raw:0,unique:0,actual_parents:0,max_raw:0,max_unique:0};
 for(const fixture of fixtures){
  req(fixture.rows.length<capacity);const target=goalDigest(fixture.goal);
  let hist=[],records=[],states=[],tests=0,mutations=0,sampleTags=[],t=emptyTree();
  for(let i=0;i<fixture.rows.length;i++){
   const row=fixture.rows[i],{rec,input}=makeInputs(row,records),digest=ndigest(rec,hist),s=BigInt(i+10001);
   const entry={digest,salt:s,leaf:nleaf(i,rec,digest,s)},seal=+(i===fixture.rows.length-1);
   const prior=frontierSlots(t,i),z=[t[depth][0],BigInt(i),target,0n,...prior];
   const update=frontierStep(i,prior,entry.leaf);
   const baseInputs=input.slice();input.push(digest,s);
   let ids=[];
   for(let j=0;j<K;j++){
    if(j<plans[row[0]].length){let a=Number(baseInputs[1+W+j*(W+1)]),x=hist[a];req(x);input.push(x.digest,x.salt);ids.push(a)}
    else input.push(0n,0n)
   }
   let positions=[...new Set(ids)].sort((a,b)=>a-b),m=K;
   readStats.rows++;readStats.raw+=ids.length;readStats.unique+=positions.length;readStats.max_raw=Math.max(readStats.max_raw,ids.length);readStats.max_unique=Math.max(readStats.max_unique,positions.length);
   for(let l=0;l<depth;l++){
    for(let j=0;j<m;j++){
     let i=positions[j];
     if(i===undefined||(j>0&&(i&1)===1&&positions[j-1]===i-1)||((i&1)===0&&positions[j+1]===i+1))input.push(0n);
     else input.push(t[l][i^1]);
    }
    positions=[...new Set(positions.map(i=>i>>1))];readStats.actual_parents+=positions.length;m=Math.min(K,capacity>>(l+1))
   }
   insert(t,i,entry.leaf);
   const next=frontierSlots(t,i+1),zo=[t[depth][0],BigInt(i+1),target,BigInt(seal),...next];
   req(update.root===zo[0]&&update.slots.every((v,l)=>v===next[l]),"native frontier parity");
   if(i===0)states.push(z.map(String));else req(JSON.stringify(states.at(-1))===JSON.stringify(z.map(String)));
   states.push(zo.map(String));
   input.push(z[0],z[2],z[3],zo[0],zo[1],zo[2],zo[3],...prior,...next);
   // Regenerate every auxiliary wire after corrupting a raw input. This
   // challenges the relation rather than merely changing one assigned wire.
   function rejectInput(name){
    const j=cs.names.indexOf(name),k=cs.inputIds.indexOf(j);req(k>=0,name);
    let x=input.slice();x[k]=mod(BigInt(x[k])+1n);
    req(!cs.verify(cs.witness(x)),"regenerated forgery "+name);
   }
   if(i===0){rejectInput("mp-sibling0_0");regenerated.empty_dirty_sibling++;rejectInput("frontier-in0");regenerated.frontier_inactive++;rejectInput("frontier-out0");regenerated.frontier_output++}
   if(i===1){rejectInput("frontier-in0");regenerated.frontier_active++;}
   if(seal){
    for(const name of ["historical-salt0","historical-digest0","mp-sibling0_0","new-salt","root-out"]){
     rejectInput(name);regenerated.terminal_payload++
    }
   }
   if(regenerated.conflicting_duplicate<4){
    const j=ids.findIndex((v,k)=>ids.indexOf(v)<k);
    if(j>=0){rejectInput("historical-salt"+j);regenerated.conflicting_duplicate++}
   }
   const run=mode==="full"||!seen.has(row[0])||seal===1;
   if(run){
    const w=cs.witness(input);
    if(!cs.verify(w)){let j=cs.rows.findIndex(([a,b,c])=>mod(val(w,a)*val(w,b)-val(w,c))!==0n);throw Error("auth "+fixture.name+" "+i+" "+row[0]+" "+cs.labels[j]+" "+j)}
    tests++;seen.add(row[0]);sampleTags.push(row[0]);
    if(seal){
     let x=input.slice();let gi=cs.inputIds.indexOf(goal[0][0]),go=cs.inputIds.indexOf(goalOut[0][0]);x[gi]=mod(target+1n);x[go]=x[gi];
     req(!cs.verify(cs.witness(x)),"wrong theorem");mutations++;
     for(const name of ["mp-sibling0_0","new-salt","root-out"]){
      let j=cs.names.indexOf(name),v=w.slice();req(j>=0);v[j]=mod(v[j]+1n);req(!cs.verify(v),"mutation "+name);mutations++
     }
    }
    if(mode==="full")sink.step(fixture.name,i,w);
   }
   hist.push(entry);records.push(rec)
  }
  const info={name:fixture.name,steps:fixture.rows.length,goal:fixture.goal,goal_digest:target.toString(),initial:states[0],terminal:states.at(-1),matrices_checked:tests,mutations_rejected:mutations,checked_tags:[...new Set(sampleTags)].sort()};
  if(mode==="full")sink.case({info,states});cases.push(info)
 }
 return {summary:{mode,...matrixInfo,cases,boundary_checks:boundaryChecks,read_stats:readStats,regenerated_rejections:regenerated,distinct_tags_checked:[...seen].sort(),total_steps:cases.reduce((a,x)=>a+x.steps,0),total_checked:cases.reduce((a,x)=>a+x.matrices_checked,0),total_mutations_rejected:cases.reduce((a,x)=>a+x.mutations_rejected,0)}}

}

let total=0,caseRows={},usageHist={},bad=0,mut=0,caseInputs=[];
for(const fixture of fixtures){
 let hist=[],inputs=[];
 for(const row of fixture.rows){
  const {rec,input}=makeInputs(row,hist),w=cs.witness(input);
  if(!cs.verify(w)){let j=cs.rows.findIndex(([a,b,c])=>mod(val(w,a)*val(w,b)-val(w,c))!==0n);throw Error(fixture.name+" "+hist.length+" "+row[0]+" "+cs.labels[j]+" "+j)}
  let refs=plans[row[0]].length;usageHist[refs]=(usageHist[refs]||0)+1;hist.push(rec);inputs.push(input);total++;
 }
 caseRows[fixture.name]=hist.length;caseInputs.push(inputs)
}
// Invalid current record values regenerated into full auxiliary assignments,
// plus direct wire mutations. Many arbitrary mutations of unused witnesses
// remain valid, so use targeted fields and count only defined attacks.
for(const fixture of fixtures){
 let ci=fixtures.indexOf(fixture),inputs=caseInputs[ci];
 for(const [i,row] of fixture.rows.entries()){
  const original=inputs[i],plan=plans[row[0]];
  if(plan.length&&i>0){
   let x=original.slice();x[1+W]=i;
   req(!cs.verify(cs.witness(x)),"self-read accepted");bad++;
  }
  if(T.includes(row[0])){
   let x=original.slice();x[1+F]++;req(!cs.verify(cs.witness(x)),"scope forged");bad++;
  }
 }
 const x=inputs.at(-1),w=cs.witness(x);for(const name of ["range-bit","zero-bit"]){
  const j=cs.names.indexOf(name),z=w.slice();z[j]=mod(z[j]+1n);req(!cs.verify(z),"wire mutation");mut++;
 }
}
const summary={constraints:cs.rows.length,wires:cs.ops.length,nonzeros:cs.rows.reduce((s,row)=>s+row.reduce((a,l)=>a+l.length,0),0),inputs:cs.inputIds.length,max_reads:Math.max(...Object.values(plans).map(p=>p.length)),record_fields:W,field_bits:D,rows_checked:total,cases:caseRows,read_histogram:usageHist,targeted_rejections:bad,wire_mutations_rejected:mut,rule_read_counts:Object.fromEntries(tags.map(t=>[t,plans[t].length]))};
return {summary,fixture:{schema:"zkl-nova-11/local-matrix-v1",public_ids:cs.inputIds,rows:cs.rows.map(row=>row.map(l=>l.map(([i,v])=>[i,v.toString()]))),case_names:fixtures.map(x=>x.name),case_inputs:caseInputs,summary}}
}
const fixtures=JSON.parse(fs.readFileSync(path.join(__dirname,'dependent_fixtures.json'),'utf8'));
const mode=process.argv.includes('--full')?'full':'sample';
const bytes=fs.readFileSync(path.join(__dirname,'../bitvm2-nova/fixtures/nht4-genesis-0-2020-k5.poseidon.json'));if(crypto.createHash('sha256').update(bytes).digest('hex')!=='b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')throw Error('parameter pin');
const profile=JSON.parse(bytes).secondary.narrow;
let sink=null;if(mode==='full'){const dir=process.argv[process.argv.indexOf('--full')+1];if(!dir)throw Error('output directory required');fs.mkdirSync(dir,{recursive:true});const write=(name,x)=>fs.writeFileSync(path.join(dir,name),JSON.stringify(x));sink={matrix:x=>write('matrix.json',x),case:x=>write(x.info.name+'.json',x),step:(name,i,w)=>{const b=Buffer.alloc(w.length*32);for(let j=0;j<w.length;j++){let x=w[j];for(let k=0;k<4;k++){b.writeBigUInt64LE(x&((1n<<64n)-1n),32*j+8*k);x>>=64n}if(x!==0n)throw Error('wire overflow')}fs.writeFileSync(path.join(dir,name+'-'+i+'.bin'),b)}};}
console.log(JSON.stringify(arithmetic(fixtures,profile,mode,sink).summary,null,2));
