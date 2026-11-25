// ZKL-NOVA-05: real sparse R1CS matrices, no recursive proof.
// Node >=18; exact pinned repo parameter file checked before use.
const fs=require('node:fs');const crypto=require('node:crypto');const path=require('node:path');
const file=process.argv[2]||path.join(__dirname,'../bitvm2-nova/fixtures/nht4-genesis-0-2020-k5.poseidon.json');
const bytes=fs.readFileSync(file);if(crypto.createHash('sha256').update(bytes).digest('hex')!=='b55fa125133315243cb299ee7603c5f0508d68abf64f0dab43ecba4a0d09fa67')throw Error('parameter pin');
function experiment(profile){
"use strict";
const P=28948022309329048855892746252171976963363056481941647379679742748393362948097n;
const mod=x=>((x%P)+P)%P, req=x=>{if(!x)throw Error("check failed")};
const le=s=>{req(typeof s==="string"&&/^[0-9a-f]{64}$/.test(s));let x=BigInt("0x"+s.match(/../g).reverse().join(""));req(x<P);return x};
req(profile.width===6&&profile.rate===5&&profile.rf===8&&profile.rp===56&&profile.crc.length===104&&profile.s==="Standard"&&profile.ht==="Sponge");
const rc=profile.crc.map(le), md=profile.mds.map(x=>x.map(le)), pre=profile.psm.map(x=>x.map(le)), sp=profile.sm.map(x=>[x.w_hat.map(le),x.v_rest.map(le)]);
const IO=2n**128n-159n, tag= (IO*(3n+2n**31n)+IO*IO)% (2n**128n), domain=0x5a4b4c30352f4e4fn;
const dot=(a,b)=>mod(a.reduce((s,x,i)=>s+x*b[i],0n));
const native=(a,b)=>{
 let x=[tag,domain,a,b,0n,0n].map((v,i)=>mod(v+rc[i])), j=6;
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
 hash(a,b){this.hashes++;let old=this.phase;this.phase="poseidon";let x=[lc(tag),lc(domain),a,b,lc(0),lc(0)].map((v,i)=>add(v,lc(rc[i]))),j=6;
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
function controls(pi){
 let n=pi.length;if(n===1)return null;if(n===2)return pi[0];
 let invp=Array(n),color=Array(n).fill(-1);pi.forEach((j,i)=>invp[j]=i);
 for(let i=0;i<n;i++)if(color[i]<0){color[i]=0;let st=[i];while(st.length){let j=st.pop();for(const t of [j^1,invp[pi[j]^1]]){if(color[t]<0){color[t]=1-color[j];st.push(t)}else req(color[t]!==color[j])}}}
 let subp=[Array(n/2),Array(n/2)];pi.forEach((j,i)=>subp[color[i]][i>>1]=j>>1);
 return [Array.from({length:n/2},(_,i)=>color[2*i]),controls(subp[0]),controls(subp[1]),Array.from({length:n/2},(_,i)=>color[invp[2*i]])]
}
const pow2=n=>2**Math.ceil(Math.log2(n));
function route(c,x,s){
 if(x.length===1)return x;
 const sw=(a,b,t)=>{let k=c.alloc(t,"switch");c.bit(k);let z=a.map((v,i)=>c.sel(k,v,b[i]));return [z,a.map((v,i)=>sub(add(v,b[i]),z[i]))]};
 if(x.length===2)return sw(x[0],x[1],s);
 let [f,t,u,l]=s,top=[],bot=[];
 for(let i=0;i<x.length/2;i++){let [a,b]=sw(x[2*i],x[2*i+1],f[i]);top.push(a);bot.push(b)}
 top=route(c,top,t);bot=route(c,bot,u);return top.flatMap((v,i)=>sw(v,bot[i],l[i]))
}
const pad=()=>[lc(0),lc(0),lc(0)];
function perm(c,x,placements,N){
 let xx=x.concat(Array.from({length:N-x.length},pad)),pi=Array(N).fill(-1);
 for(const [i,j] of placements)pi[i]=j;
 let used=new Set(placements.map(z=>z[1])),spare=Array.from({length:N},(_,i)=>i).filter(i=>!used.has(i)),j=0;
 for(let i=0;i<N;i++)if(pi[i]<0)pi[i]=spare[j++];
 return route(c,xx.map(([a,i,v])=>[add(a,i),v]),controls(pi)).map(([key,v])=>{let a=sub(lc(1),c.iszero(key));return [a,sub(key,a),v]})
}
const prefix=(c,x)=>{for(let i=1;i<x.length;i++)c.enforce(x[i][0],sub(lc(1),x[i-1][0]),[])};
const gap=(c,a,b,w,strict)=>{c.bound(c.mul(b[0],sub(sub(b[1],a[1]),lc(strict))),w)};
const canon=(c,x)=>x.forEach(r=>r.forEach(v=>c.eq(v,[])));
function build(D,K,n,ids,shared,tree){
 let c=new R1CS();c.phase="public";
 const root=c.input(tree[D][0],"root"), count=c.input(n,"occupied");
 c.bound(count,D+1);c.bound(sub(lc(2**D),count),D+1);
 let raw=Array.from({length:K},(_,j)=>{let a=j<ids.length?1:0,i=a?ids[j]:0,v=a?tree[0][i]:0n;return [c.input(a,"active"),c.input(i,"index"),c.input(v,"digest")]});
 c.phase="requests";
 const bits=raw.map(([a,i,v])=>{c.bit(a);c.enforce(sub(lc(1),a),i,[]);c.enforce(sub(lc(1),a),v,[]);let b=c.bound(i,D);c.bound(c.mul(a,sub(sub(count,lc(1)),i)),D);return b});
 if(!shared){raw.forEach(([a,i,v],j)=>{let x=v,idx=Number(c.val(i));for(let l=0;l<D;l++){c.phase="paths";let s=c.alloc(c.val(a)?tree[l][(idx>>l)^1]:0n,"sibling"),u=c.sel(bits[j][l],x,s),r=sub(add(x,s),u);x=c.hash(u,r)}c.phase="root";c.enforce(a,sub(x,root),[])});return c}
 c.phase="sort";let order=raw.map((_,i)=>i).sort((a,b)=>Number(c.val(raw[b][0])-c.val(raw[a][0])||c.val(raw[a][1])-c.val(raw[b][1])));
 let x=perm(c,raw,order.map((i,j)=>[i,j]),pow2(K));canon(c,x.slice(K));x=x.slice(0,K);prefix(c,x);
 let heads=x.map((r,j)=>{let [a,i,v]=r,dup=lc(0);if(j){gap(c,x[j-1],r,D,0);dup=c.mul(a,c.iszero(sub(i,x[j-1][1])));c.enforce(dup,sub(v,x[j-1][2]),[])}let h=sub(a,dup);return [h,c.mul(h,i),c.mul(h,v)]});
 let children=heads;
 for(let l=0;l<D;l++){
  c.phase="layer_route";
  let cap=Math.min(K,2**(D-l-1)),act=children.map((r,j)=>[r,j]).filter(([r])=>c.val(r[0])===1n),pars=[...new Set(act.map(([r])=>Number(c.val(r[1]))>>1))].sort((a,b)=>a-b),pm=new Map(pars.map((p,j)=>[p,j]));
  let xx=perm(c,children,act.map(([r,j])=>{let i=Number(c.val(r[1]));return [j,2*pm.get(i>>1)+(i&1)]}),pow2(2*cap));canon(c,xx.slice(2*cap));
  let out=[];
  for(let j=0;j<cap;j++){
   c.phase="layer_checks";let L=xx[2*j],R=xx[2*j+1],a=L[0],b=R[0],both=c.mul(a,b),live=sub(add(a,b),both),p=c.alloc(j<pars.length?pars[j]:0,"parent");
   c.enforce(a,sub(L[1],scale(2n,p)),[]);c.enforce(b,sub(sub(R[1],scale(2n,p)),lc(1)),[]);c.enforce(sub(lc(1),live),p,[]);c.bound(p,D-l-1);
   let s=c.alloc(c.val(live)&&!c.val(both)?tree[l][2*Number(c.val(p))+(c.val(a)?1:0)]:0n,"sibling");c.enforce(add(sub(lc(1),live),both),s,[]);
   let u=add(L[2],c.mul(sub(lc(1),a),s)),v=add(R[2],c.mul(sub(lc(1),b),s));out.push([live,p,c.mul(live,c.hash(u,v))])
  }
  prefix(c,out);for(let j=1;j<out.length;j++)gap(c,out[j-1],out[j],D-l-1,1);children=out
 }
 c.phase="root";c.eq(children[0][1],[]);c.enforce(children[0][0],sub(children[0][2],root),[]);return c
}
function tree(D,n){let x=Array.from({length:2**D},(_,i)=>i<n?BigInt(i+1):0n),t=[x];for(let l=0;l<D;l++){x=Array.from({length:x.length/2},(_,i)=>native(x[2*i],x[2*i+1]));t.push(x)}return t}
function summary(c){return {constraints:c.rows.length,wires:c.w.length,hashes:c.hashes,hash_constraints:c.labels.filter(x=>x==="poseidon").length,non_hash:c.labels.filter(x=>x!=="poseidon").length,nonzeros:c.rows.reduce((n,r)=>n+r.reduce((s,l)=>s+l.length,0),0)}}
function sameShape(a,b){if(a.rows.length!==b.rows.length||a.w.length!==b.w.length)return false;for(let i=0;i<a.rows.length;i++)for(let j=0;j<3;j++){let x=a.rows[i][j],y=b.rows[i][j];if(x.length!==y.length||x.some((z,k)=>z[0]!==y[k][0]||z[1]!==y[k][1]))return false}return true}
let h=new R1CS();let a=h.input(19,"a"),b=h.input(42,"b"),out=h.input(native(19n,42n),"out");h.eq(h.hash(a,b),out);
let check=c=>verify(c.rows,c.w,c.public,c.public.map(i=>c.w[i]));req(check(h));req(h.hashes===1&&summary(h).hash_constraints===312);
let hv=h.w.slice();hv[3]=mod(hv[3]+1n);req(!verify(h.rows,hv,h.public,h.public.map(i=>hv[i])));
let results=[],muts=0,shapes=0;
for(let [D,K,n] of [[4,5,11],[5,10,23]]){
 let t=tree(D,n);
 for(let shared of [false,true]){
  let first=null;
  for(let ids of [[0,1,n-1,1],[...Array(K)].map((_,j)=>Math.floor(j*n/K)),[]]){
   let c=build(D,K,n,ids,shared,t);req(check(c));let info=summary(c);req(info.hash_constraints===312*info.hashes);
   if(first){req(sameShape(first,c));shapes++}else first=c;
   let names=ids.length?["sbox-square","sbox-fourth","sbox-fifth","sibling","range-bit",...(shared?["switch","parent"]:[])]:["sbox-square","sbox-fifth"];
   for(let name of names){let i=c.names.indexOf(name);if(i<0)continue;let w=c.w.slice();w[i]=mod(w[i]+1n);req(!verify(c.rows,w,c.public,c.public.map(j=>c.w[j])));muts++}
   if(ids.length){let w=c.w.slice(),i=c.names.indexOf("digest");w[i]=mod(w[i]+1n);req(!verify(c.rows,w,c.public,c.public.map(j=>w[j])));muts++}
   results.push({D,K,n,mode:shared?"packed":"independent",reads:ids.length,unique:new Set(ids).size,...info})
  }
 }
}
return {profile:"vesta_base/narrow",domain:domain.toString(),hash_vector:{a:"19",b:"42",out:native(19n,42n).toString()},hash:summary(h),matrix_shape_checks:shapes,mutations_rejected:muts+1,results}
}
console.log(JSON.stringify(experiment(JSON.parse(bytes).secondary.narrow),null,2));
