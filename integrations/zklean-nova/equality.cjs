// ZKL-NOVA-17: fixed propositional equality and dependent path induction.
"use strict";
const assert=(v,m="invalid certificate")=>{if(!v)throw new Error(m)};
const int=(n,max=65535)=>Number.isInteger(n)&&n>=0&&n<=max;
const eq=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const S=u=>["S",u],B=i=>["B",i],F=i=>["F",i],P=(a,b)=>["P",a,b],L=(a,b)=>["L",a,b],A=(a,b)=>["A",a,b];
// Verifier-owned fixed signatures. The caller cannot supply an environment.
const ENV=require('./equality_environment.cjs');
const C=i=>["C",i], Nat=C(0), Z=C(1), Succ=C(2), numeral=n=>n?A(Succ,numeral(n-1)):Z;
const apply=(f,...xs)=>xs.reduce((g,x)=>A(g,x),f);
const envType=i=>{assert(int(i,ENV.length-1),"unknown public constant");return ENV[i]};
const pair=k=>["P","L","A"].includes(k), binder=k=>k==="P"||k==="L";
const arities={S:2,B:2,F:2,P:3,L:3,A:3,E:1,X:4,Q0:4,Q1:5,I0:5,I2:7,VR:2,VS:2,VT:3,VB:4,VA:5,VP:8,VL:8,JS:4,JV:5,JP:8,JL:9,JA:7,JC:7,C:2,JK:4,VZ:3,VN:3,VJ:3};
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
   const head=t(p1.a);assert(head.tag==="C"&&head.a>=3&&head.a<=5);
   const scrut=t(lhs.b);
   if(tag==="VZ"){assert(scrut.tag==="C"&&scrut.a===1&&b===p2.b)}
   else{
    assert(scrut.tag==="A");const ctor=t(scrut.a);assert(ctor.tag==="C"&&ctor.a===2);
    assert(rhs.tag==="A");const step=t(rhs.a),rec=t(rhs.b);
    assert(step.tag==="A"&&step.a===p3.b&&step.b===scrut.b);
    assert(rec.tag==="A"&&rec.a===lhs.a&&rec.b===scrut.b);
   }
   out=conv(a,b);
  }else if(tag==="VJ"){
   // Based path induction. Six arguments: carrier, source, motive, base,
   // destination and equality proof. Every equality below is an earlier ID.
   const lhs=t(a);t(b);assert(lhs.tag==="A");
   const p5=t(lhs.a);assert(p5.tag==="A");
   const p4=t(p5.a);assert(p4.tag==="A");
   const p3=t(p4.a);assert(p3.tag==="A");
   const p2=t(p3.a);assert(p2.tag==="A");
   const p1=t(p2.a);assert(p1.tag==="A");
   const head=t(p1.a);assert(head.tag==="C"&&head.a>=8&&head.a<=10);
   const refl=t(lhs.b);assert(refl.tag==="A");
   const refl1=t(refl.a);assert(refl1.tag==="A");
   const ctor=t(refl1.a);assert(ctor.tag==="C"&&ctor.a===7);
   assert(refl1.b===p1.b&&refl.b===p2.b&&p5.b===p2.b&&b===p4.b);
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
      if(h.tag==="C"&&h.a>=3&&h.a<=5){
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
   // The generator can collect a spine, but VJ checks its bounded nodes.
   let head=app,args=[];
   while(this.get(head).tag==="A"){const v=this.get(head);args.unshift(v.b);head=v.a}
   const hd=this.get(head);
   if(hd.tag==="C"&&hd.a>=8&&hd.a<=10&&args.length===6){
    const [carrier,source,motive,base,dest,proof]=args,p=this.get(proof);
    if(p.tag==="A"){
     const rp=this.get(p.a);
     if(rp.tag==="A"){
      const rc=this.get(rp.a);
      if(rc.tag==="C"&&rc.a===7&&rp.b===carrier&&p.b===source&&dest===source){
       const j=this.add(["VJ",app,base]),[u,uc]=this.norm(base,depth+1);
       return [u,this.trans(this.trans(cv,j),uc)];
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
   if(h[0]==="C"&&h[1]>=8&&h[1]<=10&&xs.length===6){
    const [carrier,source,motive,base,dest,proof]=xs;
    const refl=apply(C(7),carrier,source);
    if(eq(proof,refl)&&eq(source,dest))return nf(base);
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

 // Reference positions (tag at index 0); all other fields are numeric
 // scalars. Implicit derived references follow these term/judgment edges.
 const refs={S:[],B:[],F:[],C:[],P:[1,2],L:[1,2],A:[1,2],E:[],X:[1,2,3],Q0:[1,3],Q1:[1,3,4],I0:[1,3,4],I2:[1,3,4,5,6],VR:[1],VS:[1],VT:[1,2],VB:[1,2,3],VA:[1,2,3,4],VP:[1,2,3,4,5,6,7],VL:[1,2,3,4,5,6,7],JS:[1,2,3],JK:[1,2,3],JV:[1,2,3,4],JP:[1,2,3,4,5,6,7],JL:[1,2,3,4,5,6,7,8],JA:[1,2,3,4,5,6],JC:[1,2,3,4,5,6],VZ:[1,2],VN:[1,2],VJ:[1,2]};
 const semanticKey=(r,m)=>{
   switch(m.kind){
    case "term":return JSON.stringify(["term",m.tag,m.a,m.b??null]);
    case "ctx":return JSON.stringify(m.empty?["empty"]:["context",m.parent,m.ty]);
    case "lookup":return JSON.stringify(["lookup",m.ctx,m.level,m.ty]);
    case "inst":return JSON.stringify(["inst",m.term,m.k,m.s,m.out]);
    case "conv":return JSON.stringify(["conv",m.a,m.b]);
    case "jud":return JSON.stringify(["jud",m.ctx,m.subject,m.ty]);
    default:assert(false);
   }
 };
 function dedup(rows,goal,semantic){
  const rel=new Relation(),map=[],seen=new Map();
  for(let i=0;i<rows.length;i++){
   const row=rows[i].slice();for(const p of refs[row[0]]){assert(row[p]<i);row[p]=map[row[p]]}
   // Validate even discarded alternative justifications. Canonical key
   // comes from the checker-derived semantic record, never a raw claim.
   const j=rel.add(row),key=semantic?semanticKey(row,rel.meta[j]):JSON.stringify(row);
   if(i+1<rows.length&&seen.has(key)){
    map.push(seen.get(key));rel.rows.pop();rel.meta.pop();
   }else{map.push(j);seen.set(key,j)}
  }
  rel.finish(goal);return rel.rows
 }
 function prune(rows,goal){
  const keep=new Set(),stack=[rows.length-1];
  while(stack.length){const i=stack.pop();if(keep.has(i))continue;keep.add(i);for(const p of refs[rows[i][0]])stack.push(rows[i][p])}
  const out=[],map=new Map();
  for(let i=0;i<rows.length;i++)if(keep.has(i)){
   let row=rows[i].slice();for(const p of refs[row[0]]){assert(map.has(row[p]));row[p]=map.get(row[p])}
   map.set(i,out.length);out.push(row)
  }
  const rr=replay(out,goal);assert(rr.accepted);return out
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

// Named notation is used only to author closed test ASTs. The checker sees
// ordinary de Bruijn terms, while the certificate opens them into free levels.
const V=name=>["named",name], pi=(name,type,body)=>["pi",name,type,body], lam=(name,type,body)=>["lam",name,type,body];
function db(t,scope=[]){
 if(t[0]==="named"){const i=scope.indexOf(t[1]);assert(i>=0,"unbound fixture name "+t[1]);return B(i)}
 if(t[0]==="pi"||t[0]==="lam")return [t[0]==="pi"?"P":"L",db(t[2],scope),db(t[3],[t[1],...scope])];
 if(pair(t[0]))return [t[0],db(t[1],scope),db(t[2],scope)];
 return t;
}
const eqa=(a,x,y)=>apply(C(6),a,x,y), reflex=(a,x)=>apply(C(7),a,x);
const jrec=(v,a,x,m,d,y,p)=>apply(C(8+v),a,x,m,d,y,p);
const bind=(kind,bindings,body)=>bindings.reduceRight((b,[n,t])=>kind(n,t,b),body);
function example(name,bindings,body,goal){cases.push([name,db(bind(lam,bindings,body)),db(bind(pi,bindings,goal))])}
const AA=V("A"),xx=V("x"),yy=V("y"),zz=V("z"),pp=V("p"),qq=V("q"),ff=V("f"),family=V("P"),dd=V("d");
cases.push(["equality_reflexivity",reflex(Nat,Z),eqa(Nat,Z,Z)]);
const symmetryM=lam("y",AA,lam("q",eqa(AA,xx,yy),eqa(AA,yy,xx)));
example("equality_symmetry",[["A",S(1)],["x",AA],["y",AA],["p",eqa(AA,xx,yy)]],jrec(0,AA,xx,symmetryM,reflex(AA,xx),yy,pp),eqa(AA,yy,xx));
const transM=lam("z",AA,lam("q",eqa(AA,yy,zz),eqa(AA,xx,zz)));
example("equality_transitivity",[["A",S(1)],["x",AA],["y",AA],["p",eqa(AA,xx,yy)],["z",AA],["q",eqa(AA,yy,zz)]],jrec(0,AA,yy,transM,pp,zz,qq),eqa(AA,xx,zz));
for(const v of [0,1]){
 const transportM=lam("y",AA,lam("q",eqa(AA,xx,yy),A(family,yy)));
 example(v?"dependent_transport":"propositional_transport",[["A",S(1)],["x",AA],["P",pi("w",AA,S(v))],["d",A(family,xx)],["y",AA],["p",eqa(AA,xx,yy)]],jrec(v,AA,xx,transportM,dd,yy,pp),A(family,yy));
}
const congrM=lam("y",Nat,lam("q",eqa(Nat,xx,yy),eqa(Nat,A(ff,xx),A(ff,yy))));
example("equality_congruence",[["f",pi("w",Nat,Nat)],["x",Nat],["y",Nat],["p",eqa(Nat,xx,yy)]],jrec(0,Nat,xx,congrM,reflex(Nat,A(ff,xx)),yy,pp),eqa(Nat,A(ff,xx),A(ff,yy)));
const proofFamily=pi("y",Nat,pi("p",eqa(Nat,Z,yy),S(1)));
example("proof_dependent_elimination",[["P",proofFamily],["d",apply(family,Z,reflex(Nat,Z))],["y",Nat],["p",eqa(Nat,Z,yy)]],jrec(1,Nat,Z,family,dd,yy,pp),apply(family,yy,pp));
const typeM=db(lam("y",Nat,lam("p",eqa(Nat,Z,yy),S(1))));
const typeReduction=jrec(2,Nat,Z,typeM,Nat,Z,reflex(Nat,Z));
cases.push(["equality_iota_type",Z,typeReduction]);
const valueM=db(lam("y",Nat,lam("p",eqa(Nat,Z,yy),Nat)));
cases.push(["equality_iota_value",jrec(1,Nat,Z,valueM,Z,Z,reflex(Nat,Z)),Nat]);
const propM=db(lam("y",Nat,lam("p",eqa(Nat,Z,yy),S(0))));
const propReduction=jrec(1,Nat,Z,propM,eqa(Nat,Z,Z),Z,reflex(Nat,Z));
cases.push(["equality_iota_proposition",reflex(Nat,Z),propReduction]);
const equalityM=db(lam("y",Nat,lam("p",eqa(Nat,Z,yy),eqa(Nat,Z,yy))));
const proofReduction=jrec(0,Nat,Z,equalityM,reflex(Nat,Z),Z,reflex(Nat,Z));
example("equality_iota_proof_index",[["K",pi("h",eqa(Nat,Z,Z),S(1))],["u",A(V("K"),reflex(Nat,Z))]],V("u"),A(V("K"),proofReduction));

function experiment(){
 const declarationSorts=[2,1,1,0,2,3,2,0,0,2,3];
 let declarations=0;
 for(let i=0;i<ENV.length;i++){
  assert(reference(ENV[i],S(declarationSorts[i])),"declaration sort "+i);
  assert(bounds(ENV[i]).every(x=>x===0),"open declaration "+i);
  const stack=[ENV[i]];
  while(stack.length){const t=stack.pop();if(t[0]==="C")assert(t[1]<i,"cyclic declaration "+i);if(pair(t[0]))stack.push(t[1],t[2]);}
  declarations++;
 }
 const fixtures=[],counts={},optimization={};let totals={original:0,exact:0,semantic:0,pruned:0};
 for(const [name,proof,goal] of cases){
  assert(reference(proof,goal),"reference "+name);
  const raw=new Builder().prove(proof,goal);
  const exact=dedup(raw,goal,false),semantic=dedup(raw,goal,true),rows=prune(semantic,goal);
  for(const candidate of [raw,exact,semantic,rows]){const rr=replay(candidate,goal);assert(rr.accepted&&eq(rr.proof,proof)&&reference(rr.proof,goal),"optimized parity "+name)}
  const hist={};for(const row of rows)hist[row[0]]=(hist[row[0]]||0)+1;
  const sizes={original:raw.length,exact:exact.length,semantic:semantic.length,pruned:rows.length};
  for(const k of Object.keys(totals))totals[k]+=sizes[k];
  counts[name]={rows:rows.length,tags:hist};optimization[name]=sizes;fixtures.push({name,proof,goal,rows});
 }
 const malformed=[
  ["unknown_constant",C(11),Nat],
  ["wrong_equality_endpoint",reflex(Nat,Z),eqa(Nat,Z,numeral(1))],
  ["wrong_equality_carrier",reflex(Nat,Z),eqa(S(1),Nat,Nat)],
  ["bad_J_proof",jrec(1,Nat,Z,valueM,Z,Z,Z),Nat],
  ["bad_J_endpoint",jrec(1,Nat,Z,valueM,Z,numeral(1),reflex(Nat,Z)),Nat],
  ["bad_J_base",jrec(1,Nat,Z,valueM,S(0),Z,reflex(Nat,Z)),Nat],
  ["bad_J_motive",jrec(1,Nat,Z,Nat,Z,Z,reflex(Nat,Z)),Nat],
  ["bad_J_universe",jrec(0,Nat,Z,valueM,Z,Z,reflex(Nat,Z)),Nat],
  ["bad_J_carrier",jrec(1,S(1),Nat,valueM,Z,Nat,reflex(Nat,Z)),Nat],
  ["type_in_type",S(1),S(1)],
  ["zero_as_sort",Z,S(1)],
  ["bad_nat_motive",apply(C(4),Nat,Z,stepNat,Z),Nat]
 ];
 for(const [name,p,g] of malformed){
  assert(!reference(p,g),"malformed reference "+name);let caught=false;try{new Builder().prove(p,g)}catch{caught=true}assert(caught,"malformed builder "+name);
 }
 let wrongGoals=0,forward=0,accepted=0,rejected=0,seed=20261125;
 const rng=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};
 for(const f of fixtures){
  assert(!replay(f.rows,S(1)).accepted,"wrong goal "+f.name);wrongGoals++;
  // Every rule with references is challenged at its first reference field.
  for(let i=0;i<f.rows.length;i++)if(refs[f.rows[i][0]].length){
   const bad=f.rows.map(x=>x.slice());bad[i][refs[bad[i][0]][0]]=i;
   assert(!replay(bad,f.goal).accepted,"forward reference "+f.name);forward++;
  }
  for(let trial=0;trial<80;trial++){
   const bad=f.rows.map(x=>x.slice()),i=rng(bad.length),row=bad[i];
   if(row.length===1||rng(7)===0)row[0]=Object.keys(arities)[rng(Object.keys(arities).length)];
   else row[1+rng(row.length-1)]=rng(Math.max(12,bad.length+2));
   const rr=replay(bad,f.goal);
   if(rr.accepted){accepted++;assert(reference(rr.proof,f.goal),"accepted unsound mutation "+f.name)}else rejected++;
  }
 }
 // Local VJ attacks rebuild every term as a valid earlier row. The premise
 // failures occur in VJ itself, independently of whole-certificate typing.
 let vjPositive=0,vjNegative=0;const vjCases={};
 function local(name,lhs,rhs,want){
  const b=new Builder(),a=b.term(lhs),r=b.term(rhs);let ok=true;
  try{b.add(["VJ",a,r])}catch{ok=false}
  assert(ok===want,"local VJ "+name);vjCases[name]=ok;if(want)vjPositive++;else vjNegative++;
 }
 for(const v of [0,1,2])local("valid_universe_"+v,jrec(v,Nat,Z,typeM,Nat,Z,reflex(Nat,Z)),Nat,true);
 local("wrong_destination",jrec(2,Nat,Z,typeM,Nat,numeral(1),reflex(Nat,Z)),Nat,false);
 local("wrong_refl_source",jrec(2,Nat,Z,typeM,Nat,Z,reflex(Nat,numeral(1))),Nat,false);
 local("wrong_refl_carrier",jrec(2,Nat,Z,typeM,Nat,Z,reflex(S(1),Z)),Nat,false);
 local("wrong_constructor",jrec(2,Nat,Z,typeM,Nat,Z,apply(C(2),Nat,Z)),Nat,false);
 local("wrong_recursor",apply(C(5),Nat,Z,typeM,Nat,Z,reflex(Nat,Z)),Nat,false);
 local("unknown_recursor",apply(C(6),Nat,Z,typeM,Nat,Z,reflex(Nat,Z)),Nat,false);
 local("forged_rhs",typeReduction,S(1),false);
 local("truncated_spine",apply(C(10),Nat,Z,typeM,Nat,reflex(Nat,Z)),Nat,false);
 local("neutral_proof",jrec(2,Nat,Z,typeM,Nat,Z,F(0)),Nat,false);
 const typedVjHeads={};
 for(const [name,head] of [["equality_iota_proof_index",8],["equality_iota_proposition",9],["equality_iota_type",10]]){
  const fixture=fixtures.find(x=>x.name===name),checked=replay(fixture.rows,fixture.goal),heads=[];
  for(const row of fixture.rows)if(row[0]==="VJ"){
   let term=checked.meta[row[1]];
   for(let n=0;n<6;n++){assert(term.tag==="A");term=checked.meta[term.a]}
   assert(term.tag==="C");heads.push(term.a);
  }
  assert(heads.includes(head),"typed VJ coverage "+name);typedVjHeads[name]=heads;
 }
 const old=JSON.parse(require('node:fs').readFileSync(require('node:path').join(__dirname,'nat_optimized_fixtures.json'),'utf8'));
 for(let i=0;i<old.length;i++)assert(eq(old[i],fixtures[i]),"Nat regression "+old[i].name);
 return {result:{environment:ENV,declaration_sorts:declarationSorts,declaration_checks:declarations,cases:counts,optimization,totals,valid_cases:fixtures.length,nat_regressions:old.length,negative_source_cases:malformed.length,wrong_statement_rejections:wrongGoals,self_reference_rejections:forward,random_mutations:accepted+rejected,mutations_accepted:accepted,mutations_rejected:rejected,accepted_mutations_reference_valid:accepted,vj_positive_controls:vjPositive,vj_negative_controls:vjNegative,vj_controls:vjCases,typed_vj_heads:typedVjHeads,max_pruned:Math.max(...fixtures.map(x=>x.rows.length))},fixtures};
}
module.exports={Relation,Builder,reference,replay,environment:ENV,experiment,refs,dedup,prune,cases,syntax:{S,B,F,P,L,A,C,apply,db,pi,lam,V,eqa,reflex,jrec}};
if(require.main===module){const x=experiment();console.log(JSON.stringify(process.argv.includes('--fixtures')?x:x.result,null,2));}
