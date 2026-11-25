// ZKL-NOVA-15: pinned Nat constants and dependent recursor certificate pilot.
function experiment(){
"use strict";
const assert=(v,m="invalid certificate")=>{if(!v)throw new Error(m)};
const int=(n,max=65535)=>Number.isInteger(n)&&n>=0&&n<=max;
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const S=u=>["S",u],B=i=>["B",i],F=i=>["F",i],P=(a,b)=>["P",a,b],L=(a,b)=>["L",a,b],A=(a,b)=>["A",a,b];
// Public environment is immutable: numeric constant IDs, no user axioms.
// C(0)=Nat; C(1)=Nat.zero; C(2)=Nat.succ; C(3+u)=Nat.rec.{u}.
const C=i=>["C",i], Nat=C(0), Z=C(1), Succ=C(2), numeral=n=>n?A(Succ,numeral(n-1)):Z;
const apply=(f,...xs)=>xs.reduce((g,x)=>A(g,x),f);
function recType(u){
 const step=P(Nat,P(A(B(2),B(0)),A(B(3),A(Succ,B(1)))));
 return P(P(Nat,S(u)),P(A(B(0),Z),P(step,P(Nat,A(B(3),B(0))))));
}
const ENV=[S(1),Nat,P(Nat,Nat),recType(0),recType(1),recType(2)];
const envType=i=>{assert(int(i,ENV.length-1),"unknown public constant");return ENV[i]};
const pair=k=>["P","L","A"].includes(k), binder=k=>k==="P"||k==="L";
const arities={S:2,B:2,F:2,P:3,L:3,A:3,E:1,X:4,Q0:4,Q1:5,I0:5,I2:7,VR:2,VS:2,VT:3,VB:4,VA:5,VP:8,VL:8,JS:4,JV:5,JP:8,JL:9,JA:7,JC:7,C:2,JK:4,VZ:3,VN:3};
function bounds(t){
 if(t[0]==="S"||t[0]==="C")return [0,0];if(t[0]==="B")return [0,t[1]+1];if(t[0]==="F")return [t[1]+1,0];
 const a=bounds(t[1]),b=bounds(t[2]);return [Math.max(a[0],b[0]),Math.max(a[1],Math.max(0,b[1]-(binder(t[0])?1:0)))];
}
// Standard locally nameless opening: replacement is locally closed.
function open(t,k,s){
 if(t[0]==="B")return t[1]===k?s:t;
 if(!pair(t[0]))return t;
 return [t[0],open(t[1],k,s),open(t[2],k+(binder(t[0])?1:0),s)];
}
function close(t,l,k=0){
 if(t[0]==="F")return t[1]===l?B(k):t;
 if(!pair(t[0]))return t;
 return [t[0],close(t[1],l,k),close(t[2],l,k+(binder(t[0])?1:0))];
}
const imax=(u,v)=>v===0?0:Math.max(u,v);
class Relation {
 constructor(){this.rows=[];this.meta=[]}
 add(r){
  const i=this.rows.length;assert(i<20000&&Array.isArray(r)&&Object.hasOwn(arities,r[0])&&r.length===arities[r[0]]&&r.slice(1).every(x=>int(x)));
  const g=(j,k)=>{assert(j<i&&this.meta[j].kind===k);return this.meta[j]};
  const t=j=>g(j,"term"),c=j=>g(j,"ctx"),q=j=>g(j,"lookup"),ins=j=>g(j,"inst"),v=j=>g(j,"conv"),j=j=>g(j,"jud");
  const is=(m,k)=>m.tag===k;
  const loc=(m,n)=>m.g===0&&m.f<=n;
  const sort=x=>{const a=t(x);assert(is(a,"S"));return a.a};
  const judgment=(ctx,subject,ty)=>{assert(loc(t(subject),c(ctx).depth)&&loc(t(ty),c(ctx).depth));return {kind:"jud",ctx,subject,ty}};
  const conv=(a,b)=>{assert(t(a).g===0&&t(b).g===0);return {kind:"conv",a,b}};
  const checkInst=(u,term,k,s,result)=>assert(u.term===term&&u.k===k&&u.s===s&&u.out===result);
  const [tag,a,b,d,e,h,l,m,z]=r;
  let out;
  if(["S","B","F","C"].includes(tag)){
   assert(tag==="C"?a<ENV.length:tag==="S"?a<=8:a<=255);
   out={kind:"term",tag,a,ast:[tag,a],f:tag==="F"?a+1:0,g:tag==="B"?a+1:0};
  }else if(pair(tag)){
   let x=t(a),y=t(b);out={kind:"term",tag,a,b,ast:[tag,x.ast,y.ast],f:Math.max(x.f,y.f),g:Math.max(x.g,Math.max(0,y.g-(binder(tag)?1:0)))};
  }else if(tag==="E"){out={kind:"ctx",depth:0,empty:true}}
  else if(tag==="X"){
   const p=c(a),w=j(d);assert(w.ctx===a&&w.subject===b);sort(w.ty);assert(loc(t(b),p.depth)&&p.depth<256);
   out={kind:"ctx",depth:p.depth+1,parent:a,ty:b,empty:false};
  }else if(tag==="Q0"||tag==="Q1"){
   const p=c(a);assert(!p.empty&&b<p.depth);t(d);
   if(tag==="Q0")assert(b===p.depth-1&&d===p.ty);
   else {const w=q(e);assert(b<p.depth-1&&w.ctx===p.parent&&w.level===b&&w.ty===d)}
   out={kind:"lookup",ctx:a,level:b,ty:d};
  }else if(tag==="I0"||tag==="I2"){
   const x=t(a),s=t(d),o=t(e);assert(b<=255&&s.g===0);
   if(tag==="I0"){
    assert(!pair(x.tag));assert(e===(x.tag==="B"&&x.a===b?d:a));
   }else{
    assert(pair(x.tag)&&o.tag===x.tag);
    checkInst(ins(h),x.a,b,d,o.a);checkInst(ins(l),x.b,b+(binder(x.tag)?1:0),d,o.b);
   }
   out={kind:"inst",term:a,k:b,s:d,out:e};
  }else if(tag==="VR")out=conv(a,a);
  else if(tag==="VS"){const u=v(a);out=conv(u.b,u.a)}
  else if(tag==="VT"){const x=v(a),y=v(b);assert(x.b===y.a);out=conv(x.a,y.b)}
  else if(tag==="VB"){
   const x=t(a),y=t(b),w=ins(d);assert(x.tag==="A");const f=t(x.a);
   assert(f.tag==="L");checkInst(w,f.b,0,x.b,b);out=conv(a,b);
  }else if(tag==="VZ"||tag==="VN"){
   // Explicit local iota equation. Inspect only the authenticated spine and
   // result DAG nodes; no recursive evaluation or arbitrary rewrite oracle.
   const lhs=t(a),rhs=t(b);assert(lhs.tag==="A");
   const p3=t(lhs.a);assert(p3.tag==="A");
   const p2=t(p3.a);assert(p2.tag==="A");
   const p1=t(p2.a);assert(p1.tag==="A");
   const head=t(p1.a);assert(head.tag==="C"&&head.a>=3&&head.a<ENV.length);
   const scrut=t(lhs.b);
   if(tag==="VZ"){assert(scrut.tag==="C"&&scrut.a===1&&b===p2.b)}
   else{
    assert(scrut.tag==="A");const ctor=t(scrut.a);assert(ctor.tag==="C"&&ctor.a===2);
    assert(rhs.tag==="A");const step=t(rhs.a),rec=t(rhs.b);
    assert(step.tag==="A"&&step.a===p3.b&&step.b===scrut.b);
    assert(rec.tag==="A"&&rec.a===lhs.a&&rec.b===scrut.b);
   }
   out=conv(a,b);
  }else if(tag==="VA"){
   const x=v(a),y=v(b),p=t(d),r=t(e);
   assert(p.tag==="A"&&r.tag==="A"&&p.a===x.a&&r.a===x.b&&p.b===y.a&&r.b===y.b);
   out=conv(d,e);
  }else if(tag==="VP"||tag==="VL"){
   const x=t(a),y=t(b),dc=v(d),fv=t(e),il=ins(h),ir=ins(l),bc=v(m);
   assert(x.tag===(tag==="VP"?"P":"L")&&y.tag===x.tag&&dc.a===x.a&&dc.b===y.a);
   assert(fv.tag==="F"&&fv.a>=Math.max(x.f,y.f));
   assert(il.term===x.b&&il.k===0&&il.s===e&&ir.term===y.b&&ir.k===0&&ir.s===e);
   assert(bc.a===il.out&&bc.b===ir.out);
   out=conv(a,b);
  }else if(tag==="JK"){
   const x=t(b);assert(x.tag==="C"&&eq(t(d).ast,envType(x.a)));
   out=judgment(a,b,d);
  }else if(tag==="JS"){
   assert(t(b).tag==="S"&&t(d).tag==="S"&&t(d).a===t(b).a+1);out=judgment(a,b,d);
  }else if(tag==="JV"){
   const x=t(b),w=q(e);assert(x.tag==="F"&&w.ctx===a&&w.level===x.a&&w.ty===d);out=judgment(a,b,d);
  }else if(tag==="JP"){
   // [JP,ctx,subject,type,domain_j,body_j,fresh,body_inst]
   const x=t(b),da=j(e),bo=j(h),fv=t(l),o=ins(m);const parent=c(a),ext=c(bo.ctx);
   assert(x.tag==="P"&&da.ctx===a&&da.subject===x.a&&!ext.empty&&ext.parent===a&&ext.ty===x.a);
   assert(fv.tag==="F"&&fv.a===parent.depth);
   checkInst(o,x.b,0,l,bo.subject);
   assert(sort(d)===imax(sort(da.ty),sort(bo.ty)));out=judgment(a,b,d);
  }else if(tag==="JL"){
   // [JL,ctx,lambda,pi,pi_j,body_j,fresh,body_inst,type_inst]
   const x=t(b),y=t(d),pj=j(e),bj=j(h),fv=t(l),bi=ins(m),ti=ins(z),ext=c(bj.ctx);
   assert(x.tag==="L"&&y.tag==="P"&&x.a===y.a&&pj.ctx===a&&pj.subject===d);sort(pj.ty);
   assert(!ext.empty&&ext.parent===a&&ext.ty===x.a&&fv.tag==="F"&&fv.a===c(a).depth);
   checkInst(bi,x.b,0,l,bj.subject);checkInst(ti,y.b,0,l,bj.ty);out=judgment(a,b,d);
  }else if(tag==="JA"){
   const x=t(b),fj=j(e),aj=j(h),o=ins(l),ft=t(fj.ty);
   assert(x.tag==="A"&&fj.ctx===a&&aj.ctx===a&&fj.subject===x.a&&aj.subject===x.b&&ft.tag==="P"&&aj.ty===ft.a);
   checkInst(o,ft.b,0,x.b,d);out=judgment(a,b,d);
  }else if(tag==="JC"){
   const from=j(e),cv=v(h),to=j(l);
   assert(from.ctx===a&&from.subject===b&&cv.a===from.ty&&cv.b===d&&to.ctx===a&&to.subject===d);sort(to.ty);
   out=judgment(a,b,d);
  }else assert(false);
  this.rows.push(r);this.meta.push(out);return i;
 }
 finish(goal){
  const x=this.meta.at(-1);assert(x.kind==="jud"&&this.meta[x.ctx].empty&&eq(this.meta[x.ty].ast,goal));
  assert(this.meta[x.subject].f===0&&this.meta[x.subject].g===0);
  return this.meta[x.subject].ast;
 }
}
class Builder{
 constructor(){this.r=new Relation;this.terms=new Map;this.empty=this.r.add(["E"])}
 add(r){return this.r.add(r)}
 get(i){return this.r.meta[i]}
 term(ast){
  const key=JSON.stringify(ast);if(this.terms.has(key))return this.terms.get(key);
  const i=this.add(pair(ast[0])?[ast[0],this.term(ast[1]),this.term(ast[2])]:ast.slice());
  this.terms.set(key,i);return i;
 }
 inst(t,k,s){
  const x=this.get(t),out=this.term(open(x.ast,k,this.get(s).ast));
  if(!pair(x.tag))return this.add(["I0",t,k,s,out]);
  const i=this.inst(x.a,k,s),j=this.inst(x.b,k+(binder(x.tag)?1:0),s);
  return this.add(["I2",t,k,s,out,i,j]);
 }
 extend(c,t,j){return this.add(["X",c,t,j])}
 lookup(c,l){
  const x=this.get(c);assert(!x.empty&&l<x.depth);
  if(l===x.depth-1)return this.add(["Q0",c,l,x.ty]);
  const p=this.lookup(x.parent,l);return this.add(["Q1",c,l,this.get(p).ty,p]);
 }
 refl(t){return this.add(["VR",t])}
 trans(a,b){return this.add(["VT",a,b])}
 norm(t,depth=0){
  assert(depth<80);const x=this.get(t);
  if(!pair(x.tag))return [t,this.refl(t)];
  if(x.tag==="A"){
   const [f,fc]=this.norm(x.a,depth+1),[a,ac]=this.norm(x.b,depth+1);
   const app=this.term(A(this.get(f).ast,this.get(a).ast));
   let cv=this.add(["VA",fc,ac,t,app]);
   if(this.get(f).tag==="L"){
    const q=this.inst(this.get(f).b,0,a),red=this.get(q).out,beta=this.add(["VB",app,red,q]);
    const [u,uc]=this.norm(red,depth+1);return [u,this.trans(this.trans(cv,beta),uc)];
   }
   // Detect a saturated recursor after normalizing its operands.
   const f3=this.get(f);
   if(f3.tag==="A"){
    const f2=this.get(f3.a);
    if(f2.tag==="A"){
     const f1=this.get(f2.a);
     if(f1.tag==="A"){
      const h=this.get(f1.a),n=this.get(a);
      if(h.tag==="C"&&h.a>=3&&h.a<ENV.length){
       let red=null,tag=null;
       if(n.tag==="C"&&n.a===1){red=f2.b;tag="VZ"}
       if(n.tag==="A"&&this.get(n.a).tag==="C"&&this.get(n.a).a===2){
        red=this.term(A(A(this.get(f3.b).ast,this.get(n.b).ast),A(this.get(f).ast,this.get(n.b).ast)));tag="VN"
       }
       if(tag){const v=this.add([tag,app,red]),[u,uc]=this.norm(red,depth+1);return [u,this.trans(this.trans(cv,v),uc)]}
      }
     }
    }
   }
   return [app,cv];
  }
  const fresh=Math.max(x.f,0),fv=this.term(F(fresh));
  const [dom,dc]=this.norm(x.a,depth+1);
  const il=this.inst(x.b,0,fv),[body,bc]=this.norm(this.get(il).out,depth+1);
  const u=this.term([x.tag,this.get(dom).ast,close(this.get(body).ast,fresh)]);
  const ir=this.inst(this.get(u).b,0,fv);
  return [u,this.add([x.tag==="P"?"VP":"VL",t,u,dc,fv,il,ir,bc])];
 }
 asSort(j){
  const x=this.get(this.get(j).ty);if(x.tag==="S")return j;
  const [u]=this.norm(this.get(j).ty);assert(this.get(u).tag==="S","expected sort");
  return this.convert(j,u)
 }
 convert(j,target){
  const x=this.get(j);if(x.ty===target)return j;
  const [a,ac]=this.norm(x.ty),[b,bc]=this.norm(target);assert(a===b,"types not convertible");
  const cv=this.trans(ac,this.add(["VS",bc])),tj=this.asSort(this.infer(x.ctx,target));
  return this.add(["JC",x.ctx,x.subject,target,j,cv,tj]);
 }
 infer(c,t,depth=0){
  assert(depth<80);const x=this.get(t),d=this.get(c).depth;
  if(x.tag==="S"){return this.add(["JS",c,t,this.term(S(x.a+1))])}
  if(x.tag==="C"){return this.add(["JK",c,t,this.term(envType(x.a))])}
  if(x.tag==="F"){const q=this.lookup(c,x.a);return this.add(["JV",c,t,this.get(q).ty,q])}
  if(x.tag==="P"||x.tag==="L"){
   const aj=this.asSort(this.infer(c,x.a,depth+1)),ext=this.extend(c,x.a,aj),fv=this.term(F(d)),bi=this.inst(x.b,0,fv),bj=this.infer(ext,this.get(bi).out,depth+1);
   if(x.tag==="P"){
    const bodyJ=this.asSort(bj),u=this.get(this.get(aj).ty),v=this.get(this.get(bodyJ).ty);
    assert(u.tag==="S"&&v.tag==="S");
    return this.add(["JP",c,t,this.term(S(imax(u.a,v.a))),aj,bodyJ,fv,bi]);
   }
   const pi=this.term(P(this.get(x.a).ast,close(this.get(this.get(bj).ty).ast,d)));
   const pj=this.infer(c,pi,depth+1),ti=this.inst(this.get(pi).b,0,fv);
   return this.add(["JL",c,t,pi,pj,bj,fv,bi,ti]);
  }
  if(x.tag==="A"){
   let fj=this.infer(c,x.a,depth+1),ft=this.get(this.get(fj).ty);
   if(ft.tag!=="P"){const [u]=this.norm(this.get(fj).ty);fj=this.convert(fj,u);ft=this.get(u)}
   assert(ft.tag==="P");
   let aj=this.infer(c,x.b,depth+1);aj=this.convert(aj,ft.a);
   const i=this.inst(ft.b,0,x.b);
   return this.add(["JA",c,t,this.get(i).out,fj,aj,i]);
  }
  assert(false,"loose bound variable");
 }
 prove(proof,goal){
  const p=this.term(proof),g=this.term(goal),j=this.infer(this.empty,p);
  this.convert(j,g); // if already exact, infer emitted the final judgment
  // A conversion request may have added rows after a cached final judgment;
  // all successful generation calls finish with a judgment.
  this.r.finish(goal);return this.r.rows;
 }
}
// Independent reference: ordinary de Bruijn substitution and type inference,
// no certificate rows, free-variable levels, or locally nameless opening.
function reference(proof,goal){
 let fuel=200000;const tick=()=>assert(--fuel>0,"reference fuel");
 function shift(t,n,c=0){tick();if(t[0]==="B"){const j=t[1]+(t[1]>=c?n:0);assert(j>=0);return B(j)}if(!pair(t[0]))return t;return [t[0],shift(t[1],n,c),shift(t[2],n,c+(binder(t[0])?1:0))]}
 function subst(t,s,k=0){tick();if(t[0]==="B")return t[1]===k?shift(s,k):t;if(!pair(t[0]))return t;return [t[0],subst(t[1],s,k),subst(t[2],s,k+(binder(t[0])?1:0))]}
 const top=(t,s)=>shift(subst(t,shift(s,1)), -1);
 function nf(t){
  tick();if(!pair(t[0]))return t;
  const f=nf(t[1]),a=nf(t[2]);if(t[0]==="A"&&f[0]==="L")return nf(top(f[2],a));
  const u=[t[0],f,a];
  if(t[0]==="A"){
   let h=u,xs=[];while(h[0]==="A"){xs.unshift(h[2]);h=h[1]}
   if(h[0]==="C"&&h[1]>=3&&h[1]<=5&&xs.length===4){
    const [m,z,s,n]=xs;
    if(eq(n,Z))return z;
    if(n[0]==="A"&&eq(n[1],Succ))return nf(A(A(s,n[2]),apply(h,m,z,s,n[2])));
   }
  }
  return u
 }
 function infer(t,ctx){
  tick();const [k,a,b]=t;
  if(k==="S"){assert(int(a,7));return S(a+1)}
  if(k==="C")return envType(a);
  if(k==="B"){assert(a<ctx.length);return shift(ctx[a],a+1)}
  if(k==="P"||k==="L"){const u=nf(infer(a,ctx));assert(u[0]==="S");const v=infer(b,[a,...ctx]);if(k==="L")return P(a,v);const w=nf(v);assert(w[0]==="S");return S(imax(u[1],w[1]))}
  if(k==="A"){const u=nf(infer(a,ctx));assert(u[0]==="P");assert(eq(nf(infer(b,ctx)),nf(u[1])));return top(u[2],b)}
  assert(false);
 }
 try{const ty=infer(proof,[]);assert(nf(infer(goal,[]))[0]==="S");return eq(nf(ty),nf(goal))}catch{return false}
}
function replay(rows,goal){
 try{const r=new Relation;for(const row of rows)r.add(row);return {accepted:true,proof:r.finish(goal),meta:r.meta}}catch{return {accepted:false}}
}
const id=L(S(1),L(B(0),B(0))), idTy=P(S(1),P(B(0),B(1)));
const dep=L(S(1),L(P(B(0),S(1)),L(P(B(1),A(B(1),B(0))),L(B(2),A(B(1),B(0))))));
const depTy=P(S(1),P(P(B(0),S(1)),P(P(B(1),A(B(1),B(0))),P(B(2),A(B(2),B(0))))));
const beta=L(S(1),L(A(L(S(1),B(0)),B(0)),B(0)));
const betaTy=P(S(1),P(A(L(S(1),B(0)),B(0)),B(1)));
const prop=L(S(1),L(P(B(0),S(0)),L(B(1),L(A(B(1),B(0)),B(0)))));
const propTy=P(S(1),P(P(B(0),S(0)),P(B(1),P(A(B(1),B(0)),A(B(2),B(1))))));
const cases=[["polymorphic_identity",id,idTy],["dependent_application",dep,depTy],["beta_conversion",beta,betaTy],["impredicative_predicate_identity",prop,propTy]];
const motiveNat=L(Nat,Nat),stepNat=L(Nat,L(Nat,A(Succ,B(0))));
const recNat=n=>apply(C(4),motiveNat,Z,stepNat,n);
const motiveType=L(Nat,S(1)),stepType=L(Nat,L(S(1),B(0)));
const recTypeAt=n=>apply(C(5),motiveType,Nat,stepType,n);
cases.push(["nat_zero",Z,Nat],["nat_recursion",recNat(numeral(2)),Nat],["iota_zero_type",Z,recTypeAt(Z)],["iota_succ_type",Z,recTypeAt(numeral(2))]);
// A nonconstant family Nat -> Sort 2, indexed by the scrutinee.
const fam=P(Nat,S(1));
const varying=L(Nat,P(fam,P(A(B(0),B(1)),A(B(1),B(2)))));
const baseId=L(fam,L(A(B(0),Z),B(0)));
const stepId=L(Nat,L(A(varying,B(0)),L(fam,L(A(B(0),A(Succ,B(2))),B(0)))));
const dependentNat=apply(C(5),varying,baseId,stepId,numeral(1));
cases.push(["dependent_nat_elimination",dependentNat,A(varying,numeral(1))]);
const famProp=P(Nat,S(0)),varyingProp=L(Nat,P(famProp,P(A(B(0),B(1)),A(B(1),B(2)))));
const propBase=L(famProp,L(A(B(0),Z),B(0)));
const propStep=L(Nat,L(A(varyingProp,B(0)),L(famProp,L(A(B(0),A(Succ,B(2))),B(0)))));
const propElim=apply(C(3),varyingProp,propBase,propStep,numeral(1));
cases.push(["prop_nat_elimination",propElim,A(varyingProp,numeral(1))]);
const declarationSorts=[2,1,1,0,2,3];
let declarationChecks=0;
for(let i=0;i<ENV.length;i++){
 assert(reference(ENV[i],S(declarationSorts[i])),"public declaration sort "+i);
 assert(bounds(ENV[i]).every(x=>x===0),"open declaration");
 // Only the primitive Nat family/constructors can occur in a signature.
 const stack=[ENV[i]];while(stack.length){const t=stack.pop();if(t[0]==="C")assert(t[1]<i&&t[1]<=2,"cyclic declaration");if(pair(t[0]))stack.push(t[1],t[2]);}
 declarationChecks++;
}

let fixtures=[],counts={},all=0;
for(const [name,proof,goal] of cases){
 assert(reference(proof,goal),"reference "+name);
 const b=new Builder,rows=b.prove(proof,goal),rr=replay(rows,goal);assert(rr.accepted&&reference(rr.proof,goal),"relation "+name);
 const hist={};for(const row of rows)hist[row[0]]=(hist[row[0]]||0)+1;
 fixtures.push({name,proof,goal,rows});counts[name]={rows:rows.length,tags:hist};all+=rows.length;
}
let seed=20261125;const rng=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
const bad=[
 ["unknown_constant",C(6),Nat],["zero_as_sort",Z,S(1)],["bad_rec_motive",apply(C(4),Nat,Z,stepNat,Z),Nat],["bad_rec_step",apply(C(4),motiveNat,Z,Z,Z),Nat],["bad_rec_index",recNat(S(1)),Nat],["type_in_type",S(1),S(1)],
 ["prop_in_prop",S(0),S(0)],
 ["open_variable",B(0),S(1)],
 ["non_function_application",A(S(0),S(0)),S(1)],
 ["wrong_dependent_domain",L(S(1),L(B(0),S(0))),idTy],
 ["invalid_beta_goal",beta,P(S(1),P(A(L(S(1),B(0)),B(0)),S(0)))]
];
for(const [name,p,g] of bad){assert(!reference(p,g),"negative oracle "+name);let rejected=false;try{new Builder().prove(p,g)}catch{rejected=true}assert(rejected,"negative relation "+name)}
let accepted=0,rejected=0,oracleAgreements=0,changedRoot=0;
for(const f of fixtures){
 for(let j=0;j<200;j++){
  const rows=f.rows.map(r=>r.slice());const i=rng(rows.length),r=rows[i];
  if(r.length===1||rng(7)===0){r[0]=Object.keys(arities)[rng(Object.keys(arities).length)]}
  else {const k=1+rng(r.length-1);r[k]=rng(Math.max(10,rows.length+2))}
  const rr=replay(rows,f.goal);
  if(rr.accepted){accepted++;assert(reference(rr.proof,f.goal),"unsound accepted corruption");oracleAgreements++}else rejected++;
 }
 const other=S(1);assert(!replay(f.rows,other).accepted);changedRoot++;
}
// Each used proof-rule tag is challenged with a self-reference at a field
// that must be a prior index. These are distinct from the random mutations.
let targeted=0;const refField={P:1,L:1,A:1,X:1,Q0:1,Q1:4,I0:1,I2:5,VR:1,VS:1,VT:2,VB:3,VA:4,VP:7,VL:7,JS:1,JV:4,JP:5,JL:8,JA:6,JC:5};
const bf=fixtures.find(f=>f.name==="beta_conversion");
for(const [tag,field] of Object.entries(refField)){
 const i=bf.rows.findIndex(r=>r[0]===tag);if(i<0)continue;
 const rows=bf.rows.map(r=>r.slice());rows[i][field]=i;
 assert(!replay(rows,bf.goal).accepted,"accepted self-reference "+tag);targeted++;
}
// Falsify the sort equality and substitution result without introducing
// forward references. The original rows' indices remain valid.
for(const tag of ["JS","JP","I0","VB","JC"]){
 let done=false;
 for(let i=0;i<bf.rows.length&&!done;i++){
  const r=bf.rows[i];if(r[0]!==tag)continue;
  const field=tag==="I0"?4:tag==="VB"?2:3;
  for(let j=0;j<i;j++){
   if(j===r[field]||!["S","B","F","P","L","A"].includes(bf.rows[j][0]))continue;
   const rows=bf.rows.map(x=>x.slice());rows[i][field]=j;
   if(!replay(rows,bf.goal).accepted){targeted++;done=true;break}
  }
 }
 assert(done,"targeted control unavailable "+tag);
}
const iotaTests={zero:0,succ:0,forged_result:0,wrong_tag:0,constant_typing:0,unknown_constant:0};
for(const f of fixtures){
 for(let i=0;i<f.rows.length;i++){
  const r=f.rows[i];
  if((r[0]==="VZ"||r[0]==="VN")&&iotaTests[r[0]==="VZ"?"zero":"succ"]<32){
   iotaTests[r[0]==="VZ"?"zero":"succ"]++;
   let rows=f.rows.map(r=>r.slice());rows[i][2]=r[1];assert(!replay(rows,f.goal).accepted,"forged iota rhs");iotaTests.forged_result++;
   rows=f.rows.map(r=>r.slice());rows[i][0]=r[0]==="VZ"?"VN":"VZ";assert(!replay(rows,f.goal).accepted,"wrong constructor");iotaTests.wrong_tag++;
  }
  if(r[0]==="JK"&&iotaTests.constant_typing<32){
   const rows=f.rows.map(r=>r.slice());rows[i][3]=r[2];assert(!replay(rows,f.goal).accepted,"forged constant type");iotaTests.constant_typing++;
  }
  if(r[0]==="C"&&iotaTests.unknown_constant<32){
   const rows=f.rows.map(r=>r.slice());rows[i][1]=ENV.length;assert(!replay(rows,f.goal).accepted,"unknown constant");iotaTests.unknown_constant++;
  }
 }
}
assert(iotaTests.zero>0&&iotaTests.succ>0&&iotaTests.constant_typing>0);
const result={environment:ENV,declaration_sorts:declarationSorts,declaration_checks:declarationChecks,iota_tests:iotaTests,targeted_rejections:targeted,cases:counts,total_rows:all,valid_cases:fixtures.length,negative_cases:bad.length,wrong_statement_rejections:changedRoot,mutations:accepted+rejected,mutations_accepted:accepted,mutations_rejected:rejected,accepted_mutations_reference_valid:oracleAgreements};
return {result,fixtures}
}
const x=experiment();console.log(JSON.stringify(process.argv.includes('--fixtures')?x:x.result,null,2));
