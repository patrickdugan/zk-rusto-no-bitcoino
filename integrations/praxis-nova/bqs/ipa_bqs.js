'use strict';
// PNS-04C: streaming Boolean quadratic IPA arithmetic and group constraints.
function ipaBqsLibrary(){
"use strict";
const Q=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PALLAS=0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n;
const VESTA=0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n;
const B=1n<<32n,L=8,S=1n<<36n,CW=37;
const A=(n,f)=>Array.from({length:n},(_,i)=>f(i)),ck=(v,m)=>{if(!v)throw Error(m)},mod=(x,p)=>((x%p)+p)%p,digit=(x,i)=>(x>>BigInt(32*i))&(B-1n);
const con=x=>x?[[0,x]]:[],scale=(a,k)=>a.map(([i,c])=>[i,c*k]),add=(...a)=>a.flat();
const pow=(a,n,p)=>{let z=1n;for(a=mod(a,p);n;n>>=1n,a=a*a%p)if(n&1n)z=z*a%p;return z};
const inv=(a,p)=>{ck(mod(a,p)!==0n,"zero inverse");return pow(a,p-2n,p)};
const eqP=(p,q)=>p.x===q.x&&p.y===q.y&&p.inf===q.inf;
const O={x:0n,y:0n,inf:true};
function refAdd(p,q,m){
 if(p.inf)return q;if(q.inf)return p;
 if(p.x===q.x&&mod(p.y+q.y,m)===0n)return O;
 const l=p.x===q.x?mod(3n*p.x*p.x*inv(2n*p.y,m),m):mod((q.y-p.y)*inv(q.x-p.x,m),m);
 const x=mod(l*l-p.x-q.x,m);return {x,y:mod(l*(p.x-x)-p.y,m),inf:false};
}
function refMul(p,k,m){
 let z=O;for(;k;k>>=1n,p=refAdd(p,p,m))if(k&1n)z=refAdd(z,p,m);return z;
}
class Store{
 constructor(prefix){this.chunks=[];this.n=0;this.chunk=1<<20;this.mask=this.chunk-1;if(prefix){for(const b of prefix)this.push(b)}else{this.push(1);this.push(0)}}
 push(v){ck(v===0||v===1,"not bit");const i=this.n++;if((i&this.mask)===0)this.chunks.push(new Uint8Array(this.chunk));this.chunks[i>>>20][i&this.mask]=v;return i}
 at(i){ck(Number.isSafeInteger(i)&&i>=0&&i<this.n,"wire index");return this.chunks[i>>>20][i&this.mask]}
 set(i,v){ck(i>=0&&i<this.n,"wire index");this.chunks[i>>>20][i&this.mask]=v}
}
class Bqs{
 constructor(prefix=null,keep=false,onRow=null){
  this.w=new Store(prefix);this.keep=keep;this.saved=[];this.onRow=onRow;this.nrows=0;this.quad=0;this.max=0;this.failed=0;this.first=null;
  this.initial=this.w.n;if(!prefix)this.lin([[1,1n]],"false constant");
  ck(this.w.at(0)===1&&this.w.at(1)===0,"constant assignment");
 }
 bit(v){ck(v===0n||v===1n,"bit");return this.w.push(Number(v))}
 val(i){return BigInt(this.w.at(i))}
 eval(a){let x=0n;for(let i=0;i<a.length;i++)if(this.w.at(a[i][0]))x+=a[i][1];return x}
 residual(ab,c){let z=-this.eval(c);for(const [a,b] of ab)z+=this.eval(a)*this.eval(b);return z}
 row(ab,c,name=""){this.nrows++;if(ab.length)this.quad++;this.max=Math.max(this.max,ab.length);
  const z=this.residual(ab,c);if(z!==0n&&z%Q!==0n){this.failed++;if(this.first===null)this.first={row:this.nrows,name,residual:z.toString()}}
  if(this.keep)this.saved.push({ab,c,name});if(this.onRow)this.onRow(ab,c);
 }
 lin(c,name=""){this.row([],c,name)}
 eq(a,b){this.lin(add(a,scale(b,-1n)))}
 cond(s,a,b){this.row([[[[s,1n]],add(a,scale(b,-1n))]],[])}
 bits(v,n){ck(v>=0n&&v<(1n<<BigInt(n)),"bit range");return A(n,i=>this.bit(v>>BigInt(i)&1n))}
 lcBits(ids){return ids.map((id,i)=>[id,1n<<BigInt(i)])}
 number(ids){let v=0n;for(let i=ids.length-1;i>=0;i--)v=2n*v+this.val(ids[i]);return v}
 word(ids){return {ids,v:this.number(ids),parts:A(Math.ceil(ids.length/32),i=>this.lcBits(ids.slice(32*i,32*i+32)))}}
 integer(v,n){return this.word(this.bits(v,n))}
 constant(v,n=255){ck(v>=0n&&v<(1n<<BigInt(n)),"constant width");return this.word(A(n,i=>Number(v>>BigInt(i)&1n)?0:1))}
 canonical(v,p,ids=null){
  const x=ids?this.word(ids):this.integer(v,255);ck(x.v===v&&x.ids.length===255,"canonical wire width");
  const sl=this.integer(v<p?p-1n-v:0n,255);let c=0n,cl=[];
  for(let i=0;i<L;i++){
   let t=digit(v,i)+digit(sl.v,i)+c-digit(p-1n,i),next=t>=B?1n:0n;
   let nl=i===L-1?[]:[[this.bit(next),1n]];
   this.lin(add(x.parts[i],sl.parts[i],cl,con(-digit(p-1n,i)),scale(nl,-B)),"canonical");cl=nl;c=next;
  }return x;
 }
 importScalar(ids,p){ck(ids.length===256,"import scalar width");this.lin([[ids[255],1n]],"top bit");const a=ids.slice(0,255);return this.canonical(this.number(a),p,a)}
 scalar(v,p){return this.canonical(v,p)}
 same(a,b){ck(a.parts.length===b.parts.length,"limb arity");for(let i=0;i<a.parts.length;i++)this.eq(a.parts[i],b.parts[i])}
 pin(a,v){this.same(a,this.constant(v,a.ids.length))}
 csame(s,a,b){ck(a.parts.length===b.parts.length,"limb arity");for(let i=0;i<a.parts.length;i++)this.cond(s,a.parts[i],b.parts[i])}
 zero(a){
  const count=a.ids.reduce((s,i)=>s+this.val(i),0n),z=this.bit(BigInt(count===0n)),nz=this.bit(BigInt(count!==0n));
  this.lin([[z,1n],[nz,1n],[0,-1n]],"zero complements");
  const sum=a.ids.map(i=>[i,1n]),sl=this.lcBits(this.bits(count?count-1n:0n,8));
  this.eq(sum,add([[nz,1n]],sl));this.cond(z,sum,[]);
  return {z,nz};
 }
 mul(a,b,p){
  const r=this.scalar(a.v*b.v%p,p),k=this.scalar(a.v*b.v/p,p);let carry=0n,cl=[];
  for(let j=0;j<2*L;j++){
   let ab=[],v=carry-digit(r.v,j),rhs=add(r.parts[j]||[],scale(cl,-1n));
   for(let i=0;i<L;i++){let h=j-i;if(h>=0&&h<L){ab.push([a.parts[i],b.parts[h]]);
    v+=digit(a.v,i)*digit(b.v,h)-digit(p,i)*digit(k.v,h);rhs=add(rhs,scale(k.parts[h],digit(p,i)))}}
   const next=v/B,nl=j===2*L-1?[]:add(this.lcBits(this.bits(next+S,CW)),con(-S));
   this.row(ab,add(rhs,scale(nl,B)),"modmul");cl=nl;carry=next;
  }return r;
 }
 addsub(a,b,p,sub=false){
  let v=sub?a.v-b.v:a.v+b.v,r=this.scalar(mod(v,p),p),k=sub?BigInt(v<0n):BigInt(v>=p),kl=[[this.bit(k),1n]],carry=0n,cl=[];
  for(let j=0;j<L;j++){
   let t=digit(a.v,j)+(sub?-1n:1n)*digit(b.v,j)+(sub?1n:-1n)*k*digit(p,j)-digit(r.v,j)+carry;
   let next=t/B;ck(next>=-2n&&next<=1n,"add carry");
   let nl=j===L-1?[]:add(this.lcBits(this.bits(next+2n,2)),con(-2n));
   this.lin(add(a.parts[j],scale(b.parts[j],sub?-1n:1n),scale(kl,(sub?1n:-1n)*digit(p,j)),scale(r.parts[j],-1n),cl,scale(nl,-B)),"modadd");cl=nl;carry=next;
  }return r;
 }
 select(s,a,b,p){
  let r=this.scalar(this.val(s)?b.v:a.v,p);
  for(let j=0;j<L;j++)this.row([[[[s,1n]],add(b.parts[j],scale(a.parts[j],-1n))]],add(r.parts[j],scale(a.parts[j],-1n)),"select");
  return r;
 }
 point(p,m,ids=null,constant=false){
  if(ids){ck(ids.length===520,"commitment width");for(let j=513;j<520;j++)this.lin([[ids[j],1n]],"reserved point bits");
   return {x:this.importScalar(ids.slice(0,256),m),y:this.importScalar(ids.slice(256,512),m),f:ids[512]}}
  const scalar=v=>constant?this.constant(v):this.scalar(v,m);
  return {x:scalar(p.x),y:scalar(p.y),f:constant?(p.inf?0:1):this.bit(BigInt(p.inf))};
 }
 pv(p){return {x:p.x.v,y:p.y.v,inf:this.val(p.f)===1n}}
 admit(p,m){
  const z=this.constant(0n),x2=this.mul(p.x,p.x,m),x3=this.mul(x2,p.x,m),y2=this.mul(p.y,p.y,m),rhs=this.addsub(x3,this.constant(5n),m);
  this.csame(p.f,p.x,z);this.csame(p.f,p.y,z);
  const finite=this.bit(1n-this.val(p.f));this.eq([[finite,1n],[p.f,1n]],con(1n));this.csame(finite,y2,rhs);
 }
 pointEq(p,q){this.same(p.x,q.x);this.same(p.y,q.y);this.eq([[p.f,1n]],[[q.f,1n]])}
 cpointEq(s,p,q){this.csame(s,p.x,q.x);this.csame(s,p.y,q.y);this.cond(s,[[p.f,1n]],[[q.f,1n]])}
 // Complete fixed-shape affine group addition for already-admitted points.
 // Canonical outputs and branch equations establish closure inductively.
 groupAdd(p,q,m,override=null){
  const P=this.pv(p),Q=this.pv(q),R=override?.point??refAdd(P,Q,m);
  const out=this.point(R,m),zero=this.constant(0n),I=this.point(O,m,null,true);
  const dx=this.addsub(q.x,p.x,m,true),dy=this.addsub(q.y,p.y,m,true),ys=this.addsub(q.y,p.y,m);
  const yz=this.zero(ys),xz=this.zero(dx),dYz=this.zero(dy);
  const kind=P.inf?0:Q.inf?1:(P.x===Q.x&&mod(P.y+Q.y,m)===0n)?2:P.x!==Q.x?3:4;
  const flags=A(5,i=>this.bit(BigInt(i===kind)));
  this.eq(flags.map(i=>[i,1n]),con(1n));
  const [left,right,opp,ordinary,dbl]=flags;
  this.cond(left,[[p.f,1n]],con(1n));this.cpointEq(left,out,q);
  this.cond(right,[[p.f,1n]],[]);this.cond(right,[[q.f,1n]],con(1n));this.cpointEq(right,out,p);
  for(const b of [opp,ordinary,dbl]){this.cond(b,[[p.f,1n]],[]);this.cond(b,[[q.f,1n]],[]);}
  this.cond(opp,[[xz.z,1n]],con(1n));this.cond(opp,[[yz.z,1n]],con(1n));this.cpointEq(opp,out,I);
  this.cond(ordinary,[[xz.nz,1n]],con(1n));
  this.cond(dbl,[[xz.z,1n]],con(1n));this.cond(dbl,[[dYz.z,1n]],con(1n));
  this.cond(dbl,[[yz.nz,1n]],con(1n));
  const x2=this.mul(p.x,p.x,m),twox=this.addsub(x2,x2,m),threex=this.addsub(twox,x2,m),twoy=this.addsub(p.y,p.y,m);
  const den=this.select(dbl,dx,twoy,m),num=this.select(dbl,dy,threex,m);
  let slope=kind===3?mod((Q.y-P.y)*inv(Q.x-P.x,m),m):kind===4?mod(3n*P.x*P.x*inv(2n*P.y,m),m):0n;
  slope=override?.slope??slope;
  const lam=this.scalar(slope,m),ld=this.mul(lam,den,m),lam2=this.mul(lam,lam,m),
    sumx=this.addsub(p.x,q.x,m),xr=this.addsub(lam2,sumx,m,true),
    yd=this.addsub(p.x,xr,m,true),ly=this.mul(lam,yd,m),yr=this.addsub(ly,p.y,m,true);
  for(const b of [left,right,opp])this.csame(b,lam,zero);
  for(const b of [ordinary,dbl]){this.csame(b,ld,num);this.csame(b,out.x,xr);this.csame(b,out.y,yr);this.cond(b,[[out.f,1n]],[]);}
  return out;
 }
 lookup(table,bits,m){
  ck(table.length===16&&bits.length===4,"window arity");
  const idx=Number(this.number(bits)),s=A(16,j=>this.bit(BigInt(j===idx)));
  this.eq(s.map(i=>[i,1n]),con(1n));
  for(let j=0;j<4;j++)this.eq(s.flatMap((i,k)=>(k>>j)&1?[[i,1n]]:[]),[[bits[j],1n]]);
  const r=this.point(this.pv(table[idx]),m);
  for(let j=0;j<L;j++){
   this.row(table.map((p,k)=>[[[s[k],1n]],p.x.parts[j]]),r.x.parts[j],"lookup x");
   this.row(table.map((p,k)=>[[[s[k],1n]],p.y.parts[j]]),r.y.parts[j],"lookup y");
  }
  this.row(table.map((p,k)=>[[[s[k],1n]],[[p.f,1n]]]),[[r.f,1n]],"lookup flag");
  return r;
 }
 msm(points,scalars,m,windows=64){
  ck(points.length===scalars.length&&windows>0&&windows<=64,"MSM shape");
  const I=this.point(O,m,null,true),tables=points.map(p=>{
   let t=[I,p];for(let j=2;j<16;j++)t.push(this.groupAdd(t[j-1],p,m));return t;
  });
  for(const s of scalars)for(let j=4*windows;j<255;j++)this.lin([[s.ids[j],1n]],"truncated fixture scalar");
  let r=I,adds=0;
  for(let j=windows-1;j>=0;j--){
   for(let k=0;k<4;k++){r=this.groupAdd(r,r,m);adds++}
   for(let k=0;k<points.length;k++){
    const bits=A(4,b=>scalars[k].ids[4*j+b]??1);
    r=this.groupAdd(r,this.lookup(tables[k],bits,m),m);adds++;
   }
  }return {r,group_adds:adds+14*points.length};
 }
 ipaScalars(x,y,ah,rho,r,p){
  const one=this.constant(1n),zero=this.constant(0n),ri=r.map(t=>{
   const s=this.scalar(t.v?inv(t.v,p):0n,p);this.pin(this.mul(t,s,p),1n);return s;
  });
  const r2=r.map(t=>this.mul(t,t,p)),ri2=ri.map(t=>this.mul(t,t,p));
  let s0=one,bhat=one;
  for(let i=0;i<r.length;i++){
   s0=this.mul(s0,ri[i],p);
   let diff=this.addsub(r[i],ri[i],p,true),xd=this.mul(x[i],diff,p);
   bhat=this.mul(bhat,this.addsub(ri[i],xd,p),p);
  }
  const negah=this.addsub(zero,ah,p,true),ws=[this.mul(negah,s0,p)];
  for(let i=1;i<2**r.length;i++){let h=31-Math.clz32(i);ws.push(this.mul(ws[i-(1<<h)],r2[r.length-1-h],p))}
  const hcoef=this.mul(rho,this.addsub(y,this.mul(ah,bhat,p),p,true),p);
  return {r2,ri2,ws,hcoef,bhat};
 }
 replay(){ck(this.keep,"rows not retained");if(this.w.at(0)!==1||this.w.at(1)!==0)return false;return this.saved.every(({ab,c})=>this.residual(ab,c)%Q===0n)}
 stats(){return {boolean_unknowns:this.w.n-1,new_boolean_unknowns:this.w.n-this.initial,equations:this.nrows,quadratic_equations:this.quad,max_products_per_equation:this.max,failed_rows:this.failed,first_failure:this.first}}
}
function selftest(){
 let report=[];
 for(const [name,m,p] of [["Pallas",PALLAS,VESTA],["Vesta",VESTA,PALLAS]]){
  const G={x:m-1n,y:2n,inf:false},H=refMul(G,5n,m),neg={x:G.x,y:m-G.y,inf:false};
  let pos=0,negatives=0,shape=null,counts={};
  for(const [a,b] of [[O,O],[O,G],[G,O],[G,neg],[G,G],[G,H],[H,H]]){
   const g=new Bqs(null,true),A=g.point(a,m),B=g.point(b,m);g.admit(A,m);g.admit(B,m);let before=g.stats(),R=g.groupAdd(A,B,m);
   ck(eqP(g.pv(R),refAdd(a,b,m))&&g.failed===0&&g.replay(),"curve add");
   const s=g.stats(),inc={boolean_unknowns:s.boolean_unknowns-before.boolean_unknowns,equations:s.equations-before.equations};
   if(shape===null)shape=JSON.stringify(inc);ck(shape===JSON.stringify(inc),"fixed shape");
   counts.affine_add_incremental=inc;
   pos++;
   const id=R.x.ids[0];g.w.set(id,g.w.at(id)^1);ck(!g.replay(),"wrong x");negatives++;
  }
  for(const bad of [{x:G.x,y:3n,inf:false},{x:1n,y:0n,inf:true},{x:m,y:2n,inf:false}]){
   let g=new Bqs();g.admit(g.point(bad,m),m);ck(g.failed>0,"malformed point");negatives++;
  }
  {let g=new Bqs(),A=g.point(G,m),B=g.point(H,m);g.admit(A,m);g.admit(B,m);g.groupAdd(A,B,m,{slope:0n});ck(g.failed>0,"wrong slope");negatives++}
  {let g=new Bqs(),A=g.point(G,m),B=g.point(H,m);g.admit(A,m);g.admit(B,m);g.groupAdd(A,B,m,{point:O});ck(g.failed>0,"wrong sum");negatives++}
  // Small-width MSM still has all upper scalar bits constrained to zero.
  {let g=new Bqs(),a=g.point(G,m),b=g.point(H,m);g.admit(a,m);g.admit(b,m);
   let s=[g.scalar(13n,p),g.scalar(22n,p)],before=g.stats(),res=g.msm([a,b],s,m,2);
   ck(g.failed===0&&eqP(g.pv(res.r),refAdd(refMul(G,13n,m),refMul(H,22n,m),m)),"MSM");
   let after=g.stats();counts.two_term_8bit_msm={group_adds:res.group_adds,boolean_unknowns:after.boolean_unknowns-before.boolean_unknowns,equations:after.equations-before.equations};pos++;}
  // IPA scalar coefficients against direct tensor sum and inverse checks.
  {const g=new Bqs(null,true),x=[2n,p-1n,4n].map(v=>g.scalar(v,p)),r=[7n,13n,23n].map(v=>g.scalar(v,p)),y=g.scalar(9n,p),ah=g.scalar(11n,p),rho=g.scalar(5n,p);
   let before=g.stats(),t=g.ipaScalars(x,y,ah,rho,r,p),bh=0n;
   for(let j=0;j<8;j++){let s=1n,b=1n;for(let i=0;i<3;i++){let bit=(j>>(2-i))&1;s=s*(bit?r[i].v:inv(r[i].v,p))%p;b=mod(b*(bit?x[i].v:1n-x[i].v),p)}bh=mod(bh+s*b,p);ck(t.ws[j].v===mod(-ah.v*s,p),"tensor weights")}
   ck(t.bhat.v===bh&&t.hcoef.v===mod(rho.v*(y.v-ah.v*bh),p)&&g.failed===0&&g.replay(),"IPA coefficient relation");
   let after=g.stats();counts.ipa_scalar_3round={boolean_unknowns:after.boolean_unknowns-before.boolean_unknowns,equations:after.equations-before.equations};
   pos++;let id=t.hcoef.ids[0];g.w.set(id,g.w.at(id)^1);ck(!g.replay(),"bad coefficient");negatives++;
  }
  report.push({curve:name,positive_checks:pos,negative_controls:negatives,counts});
 }
 return {scope:"Executed fixed-shape group and scalar BQS components; native IPA transcript composition separate CI",curves:report};
}
return {Bqs,selftest,refAdd,refMul,eqP,PALLAS,VESTA,Q,ck,mod,O};
}
module.exports=ipaBqsLibrary();
if(require.main===module)console.log(JSON.stringify(module.exports.selftest(),null,2));
