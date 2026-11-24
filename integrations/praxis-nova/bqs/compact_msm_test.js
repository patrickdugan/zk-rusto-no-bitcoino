'use strict';
const lib=require('./ipa_bqs.js'),compact=require('./compact_msm.js');
function run(lib,compact){
 const {Bqs,refAdd,refMul,eqP,PALLAS,VESTA,mod,O,ck}=lib,{compactAdd,fixedMSM,variableMSM}=compact;
 const rows=[];
 for(const [curve,m,p] of [["Pallas",PALLAS,VESTA],["Vesta",VESTA,PALLAS]]){
 const G={x:m-1n,y:2n,inf:false},H=refMul(G,5n,m),neg={x:G.x,y:m-G.y,inf:false};
 let counts=null,pos=0,negative=0;
 for(const [a,b] of [[O,O],[O,G],[G,O],[G,neg],[G,G],[G,H],[H,H]]){
  const g=new Bqs(null,true),P=g.point(a,m),Q=g.point(b,m);g.admit(P,m);g.admit(Q,m);const before=g.stats(),R=compactAdd(g,P,Q,m),after=g.stats();
  ck(eqP(g.pv(R),refAdd(a,b,m))&&g.failed===0&&g.replay(),"compact add");
  const inc={boolean_unknowns:after.boolean_unknowns-before.boolean_unknowns,equations:after.equations-before.equations};
  if(counts)ck(JSON.stringify(counts)===JSON.stringify(inc),"shape changes");counts=inc;pos++;
  const idx=R.y.ids[1];g.w.set(idx,g.w.at(idx)^1);ck(!g.replay(),"mutated result");negative++;
 }
 for(const ov of [{slope:0n},{point:O}]){
  const g=new Bqs(),P=g.point(G,m),Q=g.point(H,m);g.admit(P,m);g.admit(Q,m);compactAdd(g,P,Q,m,ov);ck(g.failed>0,"bad group trace");negative++;
 }
 // Include full-width high-bit and zero scalars for the fixed lookup.
 const fixed=[],bases=[G,H],scalars=[p-1n,0n];
 for(const [width,shifted] of [[4,true],[6,true],[8,true],[8,false]]){
  let termCount=0;const g=new Bqs(null,false,(ab,c)=>{termCount+=c.length+ab.reduce((s,[a,b])=>s+a.length+b.length,0)});const ss=scalars.map(x=>g.scalar(x,p));const b=g.stats(),t=termCount;
  const res=fixedMSM(g,bases,ss,m,width,Math.ceil(255/width),shifted);
  const w=refAdd(refMul(G,scalars[0],m),refMul(H,scalars[1],m),m);
  ck(g.failed===0&&eqP(g.pv(res.r),w),"fixed MSM");
  const a=g.stats();fixed.push({width,shifted,group_additions:res.adds,table_entries:res.entries,lookups:res.lookups,boolean_unknowns:a.boolean_unknowns-b.boolean_unknowns,equations:a.equations-b.equations,linear_form_terms:termCount-t});pos++;
 }
 rows.push({curve,positive_checks:pos,negative_controls:negative,compact_affine_add_incremental:counts,fixed_base_two_term_fullwidth:fixed});
 }
 return {scope:"Exact fixed-base and compact group-law BQS components; deterministic public test bases; no full verifier",curves:rows};
}
console.log(JSON.stringify(run(lib,compact),null,2));
