'use strict';
// PNS-04D: compact conditional modular polynomial and constant MSM tables.
function compactLibrary(lib){
"use strict";
const {ck,mod,refAdd,refMul,eqP,O}=lib;
const Q=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const B=1n<<86n,M=B-1n,K=1n<<257n,S=1n<<93n;
const A=(n,f)=>Array.from({length:n},(_,i)=>f(i)),digit=(x,j)=>(x>>BigInt(j*86))&M,con=x=>x?[[0,x]]:[],sc=(a,k)=>a.map(([i,c])=>[i,c*k]),add=(...a)=>a.flat();
const inv=(x,p)=>{let a=mod(x,p),n=p-2n,z=1n;ck(a!==0n,"inverse zero");for(;n;n>>=1n,a=a*a%p)if(n&1n)z=z*a%p;return z};
const bit=(g,b)=>g.bit(BigInt(b)),lc=i=>[[i,1n]];
function parts(g,w){ck(w.ids.length<=258,"wide limb width");return A(Math.ceil(w.ids.length/86),i=>g.lcBits(w.ids.slice(i*86,i*86+86)))}
function poly(g,p,products,linear,active){
  // All input scalars are 255-bit integers. Coefficients are verifier-owned.
  const weight=products.reduce((s,t)=>s+(t[2]<0n?-t[2]:t[2]),0n);
  const linweight=linear.reduce((s,t)=>s+(t[1]<0n?-t[1]:t[1]),0n);
  ck(weight<=5n&&linweight<=3n,"fixed expression bound");
  const val=products.reduce((s,[a,b,k])=>s+k*a.v*b.v,0n)+linear.reduce((s,[a,k])=>s+k*a.v,0n);
  const residue=mod(val,p),quo=(val-residue)/p;
  ck(quo>=-K&&quo<K,"signed quotient");
  const k=g.integer(quo+K,258),r=g.integer(residue,255);
  const kl=parts(g,k).map((a,i)=>add(a,con(-digit(K,i)))),rl=parts(g,r);
  const prod=products.map(([a,b,c])=>[parts(g,a),parts(g,b),a.v,b.v,c]),lin=linear.map(([a,c])=>[parts(g,a),a.v,c]);
  // |column residual| <= 15*B²+3*B²+5*B + (B+1)*S < Q.
  // This holds for every bit assignment, not just generated witnesses.
  const bound=18n*B*B+5n*B+(B+1n)*S;
  ck(bound<Q,"integer residual can wrap");
  let carry=0n,cl=[];
  for(let j=0;j<6;j++){
    let ab=[],v=carry-digit(residue,j),rhs=add(rl[j]||[],sc(cl,-1n));
    for(const [a,b,av,bv,c] of prod)for(let i=0;i<3;i++){
      const h=j-i;if(h<0||h>=3)continue;
      ab.push([sc(a[i]||[],c),b[h]||[]]);v+=c*digit(av,i)*digit(bv,h);
    }
    for(const [a,av,c] of lin){v+=c*digit(av,j);rhs=add(rhs,sc(a[j]||[],-c))}
    for(let i=0;i<3;i++){const h=j-i;if(h<0||h>=3)continue;
      const pd=digit(p,i);v-=pd*(digit(k.v,h)-digit(K,h));rhs=add(rhs,sc(kl[h],pd));
    }
    ck(v%B===0n,"column construction");const next=v/B;
    ck(next>=-S&&next<S,"carry bound");const nl=j===5?[]:add(g.lcBits(g.bits(next+S,94)),con(-S));
    if(j===5)ck(next===0n,"terminal carry");
    g.row(ab,add(rhs,sc(nl,B)),"compact modular polynomial");cl=nl;carry=next;
  }
  g.cond(active,r.ids.map(i=>[i,1n]),[]);
  return r;
}
function eqFlag(g,a,b){
  const diff=a.parts.map((p,i)=>add(p,sc(b.parts[i],-1n)));
  const value=diff.reduce((s,x)=>s+g.eval(x)**2n,0n);
  const z=bit(g,value===0n),nz=bit(g,value!==0n);
  const slack=g.lcBits(g.bits(value?value-1n:0n,67));
  g.eq([ [z,1n],[nz,1n] ],con(1n));
  g.row(diff.map(d=>[d,d]),add(lc(nz),slack),"equality squares");
  g.cond(z,slack,[]);return {z,nz};
}
function compactAdd(g,p,q,m,override=null){
  const P=g.pv(p),Qp=g.pv(q),R=override?.point??refAdd(P,Qp,m);
  const out=g.point(R,m),I=g.point(O,m,null,true);
  const xe=eqFlag(g,p.x,q.x),ye=eqFlag(g,p.y,q.y),yz=g.zero(p.y);
  const kind=P.inf?0:Qp.inf?1:P.x===Qp.x&&(P.y!==Qp.y||P.y===0n)?2:P.x!==Qp.x?3:4;
  const flags=A(5,i=>bit(g,i===kind)),[left,right,opp,ordinary,dbl]=flags,reg=bit(g,kind>=3);
  g.eq(flags.map(i=>[i,1n]),con(1n));g.eq(lc(reg),[[ordinary,1n],[dbl,1n]]);
  g.cond(left,lc(p.f),con(1n));g.cpointEq(left,out,q);
  g.cond(right,lc(p.f),[]);g.cond(right,lc(q.f),con(1n));g.cpointEq(right,out,p);
  for(const b of [opp,ordinary,dbl]){g.cond(b,lc(p.f),[]);g.cond(b,lc(q.f),[])}
  g.cond(opp,lc(xe.z),con(1n));
  const equalNonzero=bit(g,P.y===Qp.y&&P.y!==0n);
  g.row([[lc(ye.z),lc(yz.nz)]],lc(equalNonzero));g.cond(opp,lc(equalNonzero),[]);g.cpointEq(opp,out,I);
  g.cond(ordinary,lc(xe.nz),con(1n));g.cond(dbl,lc(xe.z),con(1n));g.cond(dbl,lc(equalNonzero),con(1n));
  g.cond(reg,lc(out.f),[]);
  let lam=kind===3?mod((Qp.y-P.y)*inv(Qp.x-P.x,m),m):kind===4?mod(3n*P.x*P.x*inv(2n*P.y,m),m):0n;
  lam=override?.slope??lam;const s=g.scalar(lam,m);
  for(const b of [left,right,opp])g.cond(b,s.ids.map(i=>[i,1n]),[]);
  poly(g,m,[[s,q.x,1n],[s,p.x,-1n]],[[q.y,-1n],[p.y,1n]],ordinary);
  poly(g,m,[[s,p.y,2n],[p.x,p.x,-3n]],[],dbl);
  poly(g,m,[[s,s,1n]],[[p.x,-1n],[q.x,-1n],[out.x,-1n]],reg);
  poly(g,m,[[s,p.x,1n],[s,out.x,-1n]],[[p.y,-1n],[out.y,-1n]],reg);
  return out;
}
function table(base,width,m){
  ck(width>=2&&width<=10,"window width");const t=[O,base];
  for(let i=2;i<2**width;i++)t.push(refAdd(t[i-1],base,m));return t;
}
function selectFixed(g,t,bits,m){
  ck(t.length===2**bits.length,"table size");
  const i=Number(g.number(bits)),sel=A(t.length,j=>bit(g,j===i));
  g.eq(sel.map(i=>[i,1n]),con(1n));
  for(let j=0;j<bits.length;j++)g.eq(sel.flatMap((s,k)=>(k>>j)&1?[[s,1n]]:[]),lc(bits[j]));
  // Selected coordinates are canonical and on-curve by exact selection
  // from verifier-owned points. Allocate coordinate bits only, no slack.
  const r={x:g.integer(t[i].x,255),y:g.integer(t[i].y,255),f:bit(g,t[i].inf)};
  for(const name of ["x","y"]){
    const a=parts(g,r[name]);for(let j=0;j<a.length;j++)g.eq(a[j],sel.flatMap((s,k)=>{let v=digit(t[k][name],j);return v?[[s,v]]:[]}));
  }
  g.eq(lc(r.f),sel.flatMap((s,k)=>t[k].inf?[[s,1n]]:[]));
  return r;
}
function fixedMSM(g,bases,scalars,m,width,windows=Math.ceil(255/width),shifted=false){
  ck(bases.length===scalars.length&&windows>=1&&windows<=Math.ceil(255/width),"fixed MSM shape");
  for(const s of scalars)for(let j=width*windows;j<255;j++)g.lin(lc(s.ids[j]),"upper scalar bit");
  // All table entries are deterministic functions of pinned base points.
  // Shifted mode trades extra constants for fewer constrained doublings.
  const getBits=(s,j)=>A(width,i=>s.ids[j*width+i]??1);
  let acc=g.point(O,m,null,true),adds=0,entries=0,lookups=0;
  if(shifted){
    for(let k=0;k<bases.length;k++){
      let p=bases[k];
      for(let j=0;j<windows;j++){
        const t=table(p,width,m);entries+=t.length;
        acc=compactAdd(g,acc,selectFixed(g,t,getBits(scalars[k],j),m),m);adds++;lookups++;
        for(let b=0;b<width;b++)p=refAdd(p,p,m);
      }
    }
  }else{
    const ts=bases.map(b=>table(b,width,m));entries=ts.reduce((a,b)=>a+b.length,0);
    for(let j=windows-1;j>=0;j--){
      // Initial accumulator is the known identity: omit first doublings.
      if(j!==windows-1)for(let i=0;i<width;i++){acc=compactAdd(g,acc,acc,m);adds++}
      for(let k=0;k<bases.length;k++){acc=compactAdd(g,acc,selectFixed(g,ts[k],getBits(scalars[k],j),m),m);adds++;lookups++;}
    }
  }
  return {r:acc,adds,entries,lookups};
}
function variableMSM(g,points,scalars,m,width=4,windows=Math.ceil(255/width)){
  ck(width===4&&points.length===scalars.length,"variable MSM shape");
  const I=g.point(O,m,null,true),tables=points.map(p=>{const t=[I,p];for(let j=2;j<16;j++)t.push(compactAdd(g,t[j-1],p,m));return t});
  for(const s of scalars)for(let j=4*windows;j<255;j++)g.lin(lc(s.ids[j]),"upper scalar bit");
  let acc=I,adds=14*points.length,lookups=0;
  for(let j=windows-1;j>=0;j--){
    if(j!==windows-1)for(let i=0;i<4;i++){acc=compactAdd(g,acc,acc,m);adds++}
    for(let k=0;k<points.length;k++){
      const bits=A(4,i=>scalars[k].ids[j*4+i]??1);
      acc=compactAdd(g,acc,g.lookup(tables[k],bits,m),m);adds++;lookups++;
    }
  }
  return {r:acc,adds,lookups};
}
return {compactAdd,poly,eqFlag,selectFixed,fixedMSM,variableMSM};
}
module.exports=compactLibrary(require('./ipa_bqs.js'));
