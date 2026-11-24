'use strict';
const lib=require('./ipa_bqs.js'),compact=require('./compact_msm.js');
function run(lib,compact,mutated=false){
 const {Bqs,refAdd,refMul,PALLAS,VESTA,mod,O,ck}=lib,{compactAdd,fixedMSM,variableMSM}=compact;
 const p=VESTA,m=PALLAS,G={x:m-1n,y:2n,inf:false};
 const G0=refMul(G,3n,m),G1=refMul(G,7n,m),H=refMul(G,19n,m),a0=5n,a1=9n,x=p-1n,y=mod(a0*(1n-x)+a1*x,p);
 const r=(p-3n)/2n,rho=p-4n;
 const pow=(x,n)=>{let z=1n;for(;n;n>>=1n,x=x*x%p)if(n&1n)z=z*x%p;return z};
 const ri=pow(r,p-2n),ah=mod(a0*r+a1*ri,p);
 const C=refAdd(refMul(G0,a0,m),refMul(G1,a1,m),m);
 const L=refAdd(refMul(G1,a0,m),refMul(H,mod(rho*a0*x,p),m),m);
 const R=refAdd(refMul(G0,a1,m),refMul(H,mod(rho*a1*(1n-x),p),m),m);
 const g=new Bqs(),[xx,yy,aa,rr,cc]=[x,y,mod(ah+BigInt(mutated),p),rho,r].map(v=>g.scalar(v,p));
 const pp=[C,L,R,H,G0,G1].map((v,i)=>g.point(v,m,null,i>=3));
 pp.forEach(v=>g.admit(v,m));
 const z=g.ipaScalars([xx],yy,aa,rr,[cc],p);
 const v=variableMSM(g,pp.slice(1,3),[...z.r2,...z.ri2],m);
 const f=fixedMSM(g,[H,G0,G1],[z.hcoef,...z.ws],m,8,32,true);
 const fin=compactAdd(g,pp[0],compactAdd(g,v.r,f.r,m),m);ck(g.failed===0,"valid group trace");
 const last=g.nrows;g.pointEq(fin,g.point(O,m,null,true));
 ck(mutated?g.failed>0&&g.first.row>last:g.failed===0,"IPA equality");
 return {mutated,accepted:g.failed===0,group_additions:v.adds+f.adds+2,variable_additions:v.adds,fixed_additions:f.adds,fixed_table_entries:f.entries,...g.stats()};
}
console.log(JSON.stringify({scope:'Full-width synthetic IPA arithmetic with compact group law and fixed public shifted tables; chosen challenges; no transcript claim',positive:run(lib,compact,false),negative:run(lib,compact,true)},null,2));
