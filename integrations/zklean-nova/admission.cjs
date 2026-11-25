// ZKL-NOVA-07: actual one-row admission R1CS; trusted synthetic fixtures.
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const args=process.argv.slice(2),emit=args[0]==='--nova-fixture';if(emit)args.shift();
const file=args[0]||path.join(__dirname,'../bitvm2-nova/fixtures/nht4-genesis-0-2020-k5.poseidon.json');
const bytes=fs.readFileSync(file);if(crypto.createHash('sha256').update(bytes).digest('hex')!=='b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')throw Error('parameter pin');
function admission(profile,exportFixture){
"use strict";
const P=28948022309329048855892746252171976963363056481941647379679742748393362948097n;
const mod=x=>((x%P)+P)%P, req=x=>{if(!x)throw Error("check failed")};
const le=s=>{req(typeof s==="string"&&/^[0-9a-f]{64}$/.test(s));let x=BigInt("0x"+s.match(/../g).reverse().join(""));req(x<P);return x};
req(profile.width===6&&profile.rate===5&&profile.rf===8&&profile.rp===56&&profile.crc.length===104&&profile.s==="Standard"&&profile.ht==="Sponge");
const rc=profile.crc.map(le), md=profile.mds.map(x=>x.map(le)), pre=profile.psm.map(x=>x.map(le)), sp=profile.sm.map(x=>[x.w_hat.map(le),x.v_rest.map(le)]);
const IO=2n**128n-159n, tag= (IO*(3n+2n**31n)+IO*IO)% (2n**128n), domain=0x5a4b4c30352f4e4fn;
const dot=(a,b)=>mod(a.reduce((s,x,i)=>s+x*b[i],0n));
const native=(a,b,dom=domain)=>{
 let x=[tag,dom,a,b,0n,0n].map((v,i)=>mod(v+rc[i])), j=6;
 for(let r=0;r<64;r++){
  if(r>=4&&r<60){x[0]=mod(x[0]**5n+rc[j++]);const [w,v]=sp[r-4],y=x[0];x=[dot(x,w),...x.slice(1).map((z,i)=>mod(z+y*v[i]))]}
  else{x=x.map(z=>mod(z**5n));if(r!==63)x=x.map(z=>mod(z+rc[j++]));x=r===3?x.map((_,k)=>dot(x,pre.map(row=>row[k]))):md.map(row=>dot(row,x))}
 }
 req(j===104);return x[1];
};
const lc=x=>[[0,mod(BigInt(x))]], add=(...xs)=>{
 const m=new Map;for(const x of xs)for(const [i,a] of x)m.set(i,mod((m.get(i)||0n)+a));
 return [...m].filter(e=>e[1]!==0n).sort((a,b)=>a[0]-b[0])
}, scale=(a,x)=>x.map(([i,b])=>[i,mod(a*b)]).filter(e=>e[1]!==0n), sub=(a,b)=>add(a,scale(-1n,b));
class R1CS{
 constructor(){this.w=[1n];this.rows=[];this.labels=[];this.names=["ONE"];this.phase="";this.public=[];this.hashes=0}
 val(a){return mod(a.reduce((s,[i,c])=>s+this.w[i]*c,0n))}
 alloc(v,name=""){let i=this.w.length;this.w.push(mod(BigInt(v)));this.names.push(name);return [[i,1n]]}
 input(v,name){let a=this.alloc(v,name);this.public.push(a[0][0]);return a}
 enforce(a,b,c){this.rows.push([a,b,c]);this.labels.push(this.phase)}
 eq(a,b){this.enforce(sub(a,b),lc(1),[])}
 mul(a,b,name=""){let z=this.alloc(this.val(a)*this.val(b),name);this.enforce(a,b,z);return z}
 bit(a){this.enforce(a,sub(a,lc(1)),[])}
 sel(s,a,b){return add(a,this.mul(s,sub(b,a)))}
 bound(a,w){let v=this.val(a),bs=Array.from({length:w},(_,j)=>this.alloc((v>>BigInt(j))&1n,"range-bit"));for(const b of bs)this.bit(b);this.eq(a,add(...bs.map((b,j)=>scale(1n<<BigInt(j),b))));return bs}
 iszero(x){let v=this.val(x),z=this.alloc(v===0n?1:0,"zero-flag");let u=this.alloc(v===0n?0:inv(v),"inverse");this.enforce(x,u,sub(lc(1),z));this.enforce(x,z,[]);return z}
 hash(a,b,dom=domain){this.hashes++;let old=this.phase;this.phase="poseidon";let x=[lc(tag),lc(dom),a,b,lc(0),lc(0)].map((v,i)=>add(v,lc(rc[i]))),j=6;
  const pow5=v=>{let q=this.mul(v,v,"sbox-square"),r=this.mul(q,q,"sbox-fourth");return this.mul(r,v,"sbox-fifth")};
  const mix=(row,vs)=>add(...row.map((v,i)=>scale(v,vs[i])));
  for(let r=0;r<64;r++){if(r>=4&&r<60){x[0]=add(pow5(x[0]),lc(rc[j++]));let [w,v]=sp[r-4],y=x[0];x=[mix(w,x),...x.slice(1).map((z,i)=>add(z,scale(v[i],y)))]}
  else{x=x.map(pow5);if(r!==63)x=x.map(z=>add(z,lc(rc[j++])));x=r===3?x.map((_,k)=>mix(pre.map(row=>row[k]),x)):md.map(row=>mix(row,x))}}
  req(j===104);this.phase=old;return x[1]
 }
}
function inv(x){let a=x,b=P,u=1n,v=0n;while(b){let q=a/b;[a,b]=[b,a-q*b];[u,v]=[v,u-q*v]}req(a===1n);return mod(u)}
function verify(rows,w,publicIds,publicValues){
 if(w.length===0||w[0]!==1n||w.some(x=>typeof x!=="bigint"||x<0n||x>=P)||publicIds.some((i,j)=>w[i]!==publicValues[j]))return false;
 const val=a=>mod(a.reduce((s,[i,c])=>s+w[i]*c,0n));
 return rows.every(([a,b,c])=>mod(val(a)*val(b)-val(c))===0n)
}

const LEAF=0x5a4b4c30372f4c46n, D=4, LIMIT=16;
const ATOM=0,ARR=1,NIL=2,EXT=3,HERE=4,THERE=5,VAR=6,LAM=7,APP=8;
const genesis=[[ATOM,0,0,0,0],[ARR,0,0,0,0],[ARR,1,1,0,0],[NIL,0,0,0,0]];
const chain=[[EXT,3,0,0,0],[HERE,4,0,0,0],[VAR,4,0,5,0],[LAM,3,1,6,0],[EXT,4,1,0,0],[THERE,8,0,5,0],[VAR,8,0,9,0],[EXT,3,1,0,0],[HERE,11,1,0,0],[VAR,11,1,12,0],[LAM,3,2,13,0],[APP,3,1,14,7]];
const rec=(r,i)=>({r,s:BigInt(i+101)});
const pack=(r,i)=>r.reduce((a,x,j)=>a+(BigInt(x)<<(4n*BigInt(j))),BigInt(i)<<20n);
const leaf=(r,i,s)=>native(pack(r,i),s,LEAF);
const history0=()=>genesis.map(rec);
function tree(history){
 let x=Array.from({length:LIMIT},(_,i)=>i<history.length?leaf(history[i].r,i,history[i].s):0n),t=[x];
 for(let l=0;l<D;l++){x=Array.from({length:x.length/2},(_,i)=>native(x[2*i],x[2*i+1]));t.push(x)}
 return t
}
const path=(tree,i)=>Array.from({length:D},(_,l)=>tree[l][(i>>l)^1]);
function refs(r,history){
 let [k,a,b,x,y]=r;let h=i=>history[i]?.r||[0,0,0,0,0];
 if(k===ARR||k===EXT||k===HERE)return [a,b];
 if(k===THERE||k===VAR)return [a,b,x];
 if(k===LAM)return [a,b,x,h(x)[1]];
 if(k===APP)return [a,b,x,y,h(x)[2]];
 return []
}
// A separate direct native rule checker; no matrices, no path witnesses.
function direct(history,r,seal,goal=1,empty=3){
 const [k,a,b,x,y]=r;
 if(r.length!==5||r.some(v=>!Number.isInteger(v)||v<0||v>=16)||k>8)return false;
 const arity=[1,2,0,2,2,3,3,3,4][k];
 if(r.slice(1+arity).some(v=>v!==0))return false;
 let ix=refs(r,history);
 if(ix.some(i=>i>=history.length))return false;
 let [A,B,C,E,F]=ix.map(i=>history[i].r);
 const ty=q=>q&&(q[0]===ATOM||q[0]===ARR);
 const ctx=q=>q&&(q[0]===NIL||q[0]===EXT);
 const lookup=q=>q&&(q[0]===HERE||q[0]===THERE);
 const jud=q=>q&&q[0]>=VAR&&q[0]<=APP;
 let ok;
 switch(k){
 case ATOM:case NIL:ok=true;break;
 case ARR:ok=ty(A)&&ty(B);break;
 case EXT:ok=ctx(A)&&ty(B);break;
 case HERE:ok=A[0]===EXT&&ty(B)&&A[2]===b;break;
 case THERE:ok=A[0]===EXT&&ty(B)&&lookup(C)&&C[1]===A[1]&&C[2]===b;break;
 case VAR:ok=ctx(A)&&ty(B)&&lookup(C)&&C[1]===a&&C[2]===b;break;
 case LAM:ok=ctx(A)&&B[0]===ARR&&jud(C)&&E[0]===EXT&&E[1]===a&&E[2]===B[1]&&C[2]===B[2];break;
 case APP:ok=ctx(A)&&ty(B)&&jud(C)&&jud(E)&&F[0]===ARR&&C[1]===a&&E[1]===a&&F[1]===E[2]&&F[2]===b;break;
 }
 return !!ok&&(!seal||(jud(r)&&a===empty&&b===goal))
}
function build(history,r,seal,opts={}){
 const c=new R1CS(), n=history.length, t=tree(history), before=t[D][0], after=tree([...history,rec(r,n)])[D][0];
 // Public state endpoints. A recursive verifier must pin the first state and
 // require the sealed endpoint; arbitrary initial states are not admitted.
 c.phase="state";
 const z=[before,BigInt(n),1n,3n,0n].map((v,i)=>c.input(opts.state?.[i]??v,"zin"+i));
 const zo=[after,BigInt(n+1),1n,3n,BigInt(seal)].map((v,i)=>c.input(opts.out?.[i]??v,"zout"+i));
 const [root,count,goal,empty,sealed]=z;
 const nb=c.bound(count,D);c.bound(sub(count,lc(4)),D);c.eq(sealed,lc(0));c.eq(zo[1],add(count,lc(1)));c.eq(zo[2],goal);c.eq(zo[3],empty);c.bit(zo[4]);
 const gate=(g,a,b=lc(0))=>c.enforce(g,sub(a,b),[]);
 c.phase="row";
 const row=r.map((v,i)=>c.alloc(v,"row"+i));row.forEach(v=>c.bound(v,4));
 const ss=Array.from({length:9},(_,k)=>c.iszero(sub(row[0],lc(k))));
 const sum=ks=>add(...ks.map(k=>ss[k]));
 c.eq(sum([0,1,2,3,4,5,6,7,8]),lc(1));
 const arity=[1,2,0,2,2,3,3,3,4];
 for(let j=1;j<5;j++)gate(sum(arity.map((v,k)=>v<j?k:-1).filter(k=>k>=0)),row[j]);
 const rowpack=(r,i)=>add(...r.map((v,j)=>scale(1n<<(4n*BigInt(j)),v)),scale(1n<<20n,i));
 const rh=(r,i,s)=>c.hash(rowpack(r,i),s,LEAF);
 const addr=refs(r,history);
 const used=[[ARR,EXT,HERE,THERE,VAR,LAM,APP],[ARR,EXT,HERE,THERE,VAR,LAM,APP],[THERE,VAR,LAM,APP],[LAM,APP],[APP]];
 const rr=[], ii=[];
 for(let j=0;j<5;j++){
   c.phase="historical";
   const active=sum(used[j]), idx=opts.indices?.[j]??addr[j]??0;
   const entry=j<addr.length?(history[idx]||rec([ATOM,0,0,0,0],idx)):{r:[0,0,0,0,0],s:0n};
   const i=c.alloc(idx,"read-index"),v=entry.r.map(x=>c.alloc(x,"read-field")),s=c.alloc(entry.s,"read-salt");
   const bits=c.bound(i,D);c.bound(c.mul(active,sub(sub(count,lc(1)),i)),D);
   for(const w of [i,...v,s])gate(sub(lc(1),active),w);
   v.forEach(x=>c.bound(x,4));rr.push(v);ii.push(i);
   let h=rh(v,i,s);gate(active,c.iszero(h));
   const hp=path(t,idx%LIMIT);
   for(let l=0;l<D;l++){const w=c.alloc(j<addr.length?hp[l]:0n,"read-sibling");gate(sub(lc(1),active),w);let u=c.sel(bits[l],h,w),b=sub(add(h,w),u);h=c.hash(u,b)}
   gate(active,h,root);
 }
 c.phase="rule";
 const [A,B,C,E,F]=rr;const [i,j,k,l,m]=ii;const [tag,a,b,x,y]=row;
 const kind=(g,v,ks)=>gate(g,add(...ks.map(t=>c.iszero(sub(v[0],lc(t))))),lc(1));
 gate(sum(used[0]),i,a);gate(sum(used[1]),j,b);gate(sum(used[2]),k,x);
 gate(ss[APP],l,y);gate(ss[LAM],l,C[1]);gate(ss[APP],m,C[2]);
 kind(ss[ARR],A,[ATOM,ARR]);kind(sum([EXT,HERE,THERE,VAR,LAM,APP]),A,[NIL,EXT]);
 kind(sum([ARR,EXT,HERE,THERE,VAR,LAM,APP]),B,[ATOM,ARR]);
 kind(sum([THERE,VAR]),C,[HERE,THERE]);kind(sum([LAM,APP]),C,[VAR,LAM,APP]);
 kind(ss[LAM],E,[EXT]);kind(ss[APP],E,[VAR,LAM,APP]);kind(ss[APP],F,[ARR]);
 gate(ss[HERE],A[0],lc(EXT));gate(ss[HERE],A[2],b);
 gate(ss[THERE],A[0],lc(EXT));gate(ss[THERE],C[1],A[1]);gate(ss[THERE],C[2],b);
 gate(ss[VAR],C[1],a);gate(ss[VAR],C[2],b);
 gate(ss[LAM],B[0],lc(ARR));gate(ss[LAM],E[1],a);gate(ss[LAM],E[2],B[1]);gate(ss[LAM],C[2],B[2]);
 gate(ss[APP],C[1],a);gate(ss[APP],E[1],a);gate(ss[APP],F[1],E[2]);gate(ss[APP],F[2],b);
 gate(zo[4],sum([VAR,LAM,APP]),lc(1));gate(zo[4],a,empty);gate(zo[4],b,goal);
 c.phase="append";
 let s=c.alloc(n+101,"new-salt"),h=rh(row,count,s);c.eq(c.iszero(h),lc(0));
 let old=lc(0),fresh=h;
 for(let l=0;l<D;l++){
   let w=c.alloc(path(t,n)[l],"append-sibling");
   let u=c.sel(nb[l],old,w);old=c.hash(u,sub(add(old,w),u));
   let v=c.sel(nb[l],fresh,w);fresh=c.hash(v,sub(add(fresh,w),v));
 }
 c.eq(old,root);c.eq(fresh,zo[0]);
 return c
}
const check=c=>verify(c.rows,c.w,c.public,c.public.map(i=>c.w[i]));
const summary=c=>({constraints:c.rows.length,wires:c.w.length,hashes:c.hashes,hash_constraints:c.labels.filter(x=>x==="poseidon").length,nonzeros:c.rows.reduce((n,r)=>n+r.reduce((s,l)=>s+l.length,0),0)});
function sameShape(a,b){if(a.rows.length!==b.rows.length||a.w.length!==b.w.length)return false;for(let i=0;i<a.rows.length;i++)for(let j=0;j<3;j++){let x=a.rows[i][j],y=b.rows[i][j];if(x.length!==y.length||x.some((z,k)=>z[0]!==y[k][0]||z[1]!==y[k][1]))return false}return true}
if(exportFixture){
 let history=history0(),first=null,assignments=[],states=[],controls=[];
 const state=(c,j)=>c.public.slice(j,j+5).map(i=>c.w[i].toString());
 const capture=c=>c.w.map(x=>x.toString());
 const addStep=c=>{
  req(check(c));if(first)req(sameShape(first,c));else{first=c;states.push(state(c,0))}
  req(JSON.stringify(states.at(-1))===JSON.stringify(state(c,0)));
  states.push(state(c,5));assignments.push(capture(c));
 };
 for(let i=0;i<chain.length;i++){
  const r=chain[i],seal=+(i===chain.length-1);
  req(direct(history,r,seal));
  if(seal){
   const unsealed=build(history,r,0);
   req(check(unsealed)&&sameShape(first,unsealed));
   controls.push({name:"unsealed_terminal",step:i,assignment:capture(unsealed),valid_relation:true});
   const wrong=build(history,r,1,{state:{2:0n},out:{2:0n}});
   req(!check(wrong)&&sameShape(first,wrong));
   controls.push({name:"wrong_goal",step:i,assignment:capture(wrong),valid_relation:false});
   const bad=build(history,r,1,{out:{0:123n}});
   req(!check(bad)&&sameShape(first,bad));
   controls.push({name:"wrong_append_root",step:i,assignment:capture(bad),valid_relation:false});
  }
  addStep(build(history,r,seal));history.push(rec(r,history.length));
 }
 req(history.length===16&&states.length===13&&states.at(-1)[4]==="1");
 const leafVector=leaf(genesis[0],0,101n);
 return {schema:"zkl-nova-08/admission-matrix-v1",D,goal:1,empty:3,
   node_domain:domain.toString(),leaf_domain:LEAF.toString(),
   node_vector:native(19n,42n).toString(),leaf_vector:leafVector.toString(),
   public_ids:first.public,states,summary:summary(first),
   rows:first.rows.map(r=>r.map(l=>l.map(([i,v])=>[i,v.toString()]))),
   assignments,controls,corrupt_wire:first.names.indexOf("sbox-square")};
}
let history=history0(),base=null,counts={},valid=0,shape=0,attacks=0,mutations=0,trace=[];
function accept(r,seal,advance=false){
 req(direct(history,r,seal));let c=build(history,r,seal);req(check(c));let s=summary(c);
 if(base){req(sameShape(base,c));shape++}else{base=c;counts=s}
 valid++;trace.push({n:history.length,rule:r[0],seal:!!seal,root_in:c.w[c.public[0]].toString(),root_out:c.w[c.public[5]].toString()});
 if(advance)history.push(rec(r,history.length))
}
for(const r of [[ATOM,1,0,0,0],[ARR,0,0,0,0],[NIL,0,0,0,0]])accept(r,0);
for(let i=0;i<chain.length;i++){
 let r=chain[i],seal=+(i===chain.length-1);
 if(i===3){
  for(const [bad,flag,opts] of [
   [[LAM,3,2,6,0],0,{}],[[LAM,3,1,6,0],1,{out:{3:4n}}],[[LAM,3,1,6,0],0,{indices:{3:3}}],
   [[LAM,3,1,6,0],0,{state:{4:1n}}],[[LAM,3,1,6,0],0,{out:{0:123n}}],
   [[VAR,4,1,5,0],0,{}],[[ARR,0,3,0,0],0,{}],[[HERE,4,1,0,0],0,{}],
   [[THERE,4,0,5,0],0,{}],[[ATOM,0,0,0,0],1,{}],[[VAR,4,0,7,0],0,{}]]){
   const c=build(history,bad,flag,opts);req(sameShape(base,c));req(!check(c));attacks++;
  }
 }
 if(seal){
  const c=build(history,r,seal);req(check(c));
  for(const name of ["row1","read-index","read-field","read-salt","read-sibling","new-salt","append-sibling","sbox-square","sbox-fifth","zout0"]){
   const at=c.names.indexOf(name);req(at>=0);let w=c.w.slice();w[at]=mod(w[at]+1n);req(!verify(c.rows,w,c.public,c.public.map(j=>w[j])));mutations++
  }
 }
 accept(r,seal,true);
}
req(history.length===16);
return {profile:"vesta_base/narrow",D,history_capacity:16,genesis_root:tree(history0())[D][0].toString(),terminal_root:tree(history)[D][0].toString(),constraints:counts,accepted:valid,shape_equal:shape,malformed_steps_rejected:attacks,mutated_assignments_rejected:mutations,trace};
}

console.log(JSON.stringify(admission(JSON.parse(bytes).secondary.narrow,emit),null,emit?0:2));
