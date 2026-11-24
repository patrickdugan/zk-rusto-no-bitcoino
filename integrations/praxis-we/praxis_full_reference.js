'use strict';
// PRAXIS-05 exact independent exponent reference, deterministic TEST coins.
function runPraxis(){
const Q=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ck=(x,s)=>{if(!x)throw Error(s)},A=(n,f)=>Array.from({length:n},(_,i)=>f(i));
const report={scope:"Deterministic exponent model, toy parameters, no security guarantee",sampler:null,variants:[],mutations:[],zero_weight:null},lines=[];
function model(q,n,K1,K2,chunked){
const N=3,d=4,nu=4,nc=2,D=13,J=chunked?2:1,Jp=J,Delta=Math.ceil(D/J),Dp=nu*nc/Jp;
const f=x=>((x%q)+q)%q,Z=n=>A(n,()=>0n),e=i=>A(d,j=>BigInt(i===j)),sum=a=>f(a.reduce((s,x)=>s+x,0n)),coef=(p,i)=>p[i]||0n,dot=(a,b)=>sum(a.map((x,i)=>x*coef(b,i)));
const pow=(x,k)=>{let t=1n;for(x=f(x),k=BigInt(k);k>0n;k>>=1n,x=f(x*x))if(k&1n)t=f(t*x);return t};
const inv=x=>{ck(f(x)!==0n,"zero inverse");return pow(x,q-2n)};
const trim=p=>{p=p.map(f);while(p.length&&!p.at(-1))p.pop();return p},sc=(p,c)=>trim(p.map(x=>x*c)),add=(a,b)=>trim(A(Math.max(a.length,b.length),i=>coef(a,i)+coef(b,i))),sub=(a,b)=>add(a,sc(b,-1n));
const mul=(a,b)=>{if(!a.length||!b.length)return [];const r=Z(a.length+b.length-1);a.forEach((x,i)=>b.forEach((y,j)=>r[i+j]=f(r[i+j]+x*y)));return trim(r)};
const ev=(p,x)=>p.reduceRight((a,b)=>f(a*x+b),0n),prod=p=>p.reduce((a,x)=>mul(a,[-x,1n]),[1n]),div=(a,b)=>{a=trim(a);b=trim(b);ck(b.length,"zero divisor");let h=Z(Math.max(0,a.length-b.length+1)),v=inv(b.at(-1));while(a.length>=b.length){let k=a.length-b.length,c=f(a.at(-1)*v);h[k]=c;b.forEach((x,i)=>a[k+i]=f(a[k+i]-c*x));a=trim(a)}return [trim(h),a]};
const exact=(a,b)=>{let [h,r]=div(a,b);ck(!r.length,"inexact tie");return h},lag=p=>p.map(x=>{let a=prod(p.filter(y=>y!==x));return sc(a,inv(ev(a,x)))}),interp=(L,y)=>L.reduce((a,p,i)=>add(a,sc(p,y[i])),[]),tw=(p,x)=>trim(p.map((a,i)=>f(a*pow(x,i))));
let c0=2n,omega;for(;;c0++){omega=pow(c0,(q-1n)/BigInt(n));if(pow(omega,n/2)===q-1n)break;ck(c0<100n,"root")};ck(n===2*K1*K2&&(q-1n)%BigInt(n)===0n&&q%4n===1n,"domain");
const P=A(n+1,i=>i===0?-c0:i===n?1n:0n),emul=(a,b)=>div(mul(a,b),P)[1];
const root=pow(omega,n/4),H=A(nu,i=>pow(root,i)),K=[H];let j=2n;while(K.length<nc){const scale=j++,h=H.map(x=>f(x*scale));if(h.every(x=>x!==0n&&!K.flat().includes(x)))K.push(h)}
ck(K.every(h=>h.every(x=>pow(x,nu)===pow(h[0],nu))),"coset membership");
const ks=K.flat(),p0=[];for(let x=0n;p0.length<5;x++)if(!ks.includes(x))p0.push(x);
const rho=p0[4],pts=[...p0,...ks],Z0=prod(p0),Zo=prod(pts.filter(x=>x!==rho)),Zk=prod(pts),L=lag(pts),LR=L[4],LK=lag(ks);
ck(new Set(pts).size===D,"QAP domain");
const legs=[];for(const kind of ["E","O","V"])for(let k=0;k<K2;k++)legs.push({kind,k:2*K1*k+Number(kind==="O")});
const cells=[];for(let a=0;a<K1;a++)for(let b=0;b<legs.length;b++)cells.push({a,b,k:2*a+legs[b].k,kind:legs[b].kind,key:a===0&&b===0});
function setup(alt=false){
const S=[{ab:[[e(1),e(2)],[e(3),e(0)]],c:alt?e(-1):e(0)},{ab:[[e(0),e(1)]],c:e(2)}];
const av=[e(-1),...A(N,i=>sub(e(i+1),e(0))),e(0)],bv=[e(0),...A(N,i=>e(i+1)),e(0)];
S.forEach((t,i)=>K[i].forEach((x,j)=>{if(j<t.ab.length){av.push(sc(t.ab[j][0],ev(Z0,x)));bv.push(t.ab[j][1])}else if(j===t.ab.length){av.push(sc(e(0),ev(Z0,x)));bv.push(sc(t.c,-1n))}else{av.push(e(-1));bv.push(e(-1))}}));
const ap=A(d,i=>interp(L,av.map(a=>coef(a,i)))),bp=A(d,i=>interp(L,bv.map(a=>coef(a,i))));
function polys(w){if(w.length!==d||w[0]!==1n||w.some(x=>x!==0n&&x!==1n))return null;const a=ap.reduce((p,x,i)=>add(p,sc(x,w[i])),[]),b=bp.reduce((p,x,i)=>add(p,sc(x,w[i])),[]),p=mul(a,b),R=interp(LK,ks.map(x=>f(ev(p,x)*inv(ev(Z0,x)))));
if(R.some((x,i)=>i%nu===0&&x))return null;let [hk,rk]=div(sub(sub(p,LR),mul(Z0,R)),Zk),[ho,ro]=div(sub(p,mul(Z0,R)),Zo);if(rk.length||ro.length)return null;ck(hk.length<=D-1&&ho.length<=D&&R.length<=nu*nc,"degree");return {hk,ho,R}}
return {ap,bp,polys}}
function sample(coins,g,centered){let rr=coins.slice(0,N),star=coins[N];return [centered?Math.ceil(N*(g+1)/2)+star-Math.floor(rr.reduce((a,b)=>a+b,0)/2):star,...rr]}
function center(w,g,centered){let wt=w.slice(1).reduce((a,b)=>a+Number(b),0);return centered?Math.floor(Math.ceil(N*(g+1)/2)+(g+3)/2*(1+wt-N/2)):Math.floor((1+wt)*(g+3)/2)}
function weights(forms,w){const z=forms.map(p=>dot(p,w)),zm=tw(z,f(-inv(omega))),zo=tw(z,q-1n),zp=tw(z,f(-omega)),U=emul(z,zm),V=emul(z,zo),Um=tw(U,f(-omega));ck(V.every((x,i)=>i%2===0||!x),"V parity");
const xi=cells.map(c=>coef(c.kind==="V"?V:U,c.k)),Up=Z(n),Vp=Z(n),Upp=Z(n);cells.forEach((c,i)=>{let a=pow(omega,2*c.a);if(c.kind==="V")Vp[c.k]=f(a*xi[i]);else{Up[c.k]=f(a*xi[i]);Upp[c.k]=f(xi[i]*pow(-omega,legs[c.b].k))}});
return {xi,cancel:[[1,0,exact(sub(mul(U,zo),mul(V,zm)),P)],[2,0,exact(sub(mul(U,zp),mul(Um,zm)),P)],[3,0,exact(sub(mul(V,zp),mul(Um,zo)),P)],[1,1,sub(mul(Up,zo),mul(Vp,zm))],[2,1,mul(Up,zp)],[3,1,mul(Vp,zp)],[2,-1,sc(mul(Upp,zm),-1n)],[3,-1,sc(mul(Upp,zo),-1n)]]}}
function enc(pp,seed,g,centered,zeroPsi=false,zeroXi=false){
let state=BigInt(seed);const next=()=>{state=(state*6364136223846793005n+1442695040888963407n)&((1n<<64n)-1n);return state},draw=()=>f(next()+(next()<<64n)+(next()<<128n)+(next()<<192n)),nz=()=>{let x;do{x=draw()}while(!x);return x};
const forms=[e(0),...A(n-1,()=>A(d,()=>draw()))]; // d_R=1; phi_0=w_0; M has n-1 rows.
if(zeroXi){ck(q===97n&&n===8,"zero xi fixture");for(let a=1;a<n;a++)forms[a]=e(-1);forms[1]=e(0);let b=inv(f(-c0*(pow(omega,3)+pow(omega,21))));forms[7]=sc(e(0),b);ck(weights(forms,[1n,1n,1n,0n]).xi[0]===0n,"zero xi")}
const coins=A(d,()=>2+Number(next()%BigInt(g))),r=sample(coins,g,centered),y=A(d,()=>zeroPsi?0n:draw());let tau=nz();while(pts.includes(tau))tau=nz();
const o12=draw(),o22=nz(),alpha=nz(),pi=nz(),s={E:nz(),O:nz(),V:nz()},v=nz(),zeta=nz(),zp=nz(),zpp=nz(),eta=[nz(),nz(),nz()];let eps=nz();while(A(K1,k=>f(1n+eps*pow(omega,2*k))).includes(0n))eps=nz();
const pis=A(K1,k=>f(pi*pow(v,2*k)*(1n+eps*pow(omega,2*k)))),ss=legs.map(l=>f(s[l.kind]*pow(v,l.k))),gamma=cells.map(c=>f(pis[c.a]*ss[c.b])),key=f(gamma[0]*ev(LR,tau)),ka=f(alpha*key);
const l=[],rr=[],g1=x=>{l.push(f(x));return l.length-1},g2=x=>{rr.push(f(x));return rr.length-1};
const F=pis.map(p=>A(d,i=>[g1(p*y[i]),g1(p*(y[i]*o12+ev(pp.ap[i],tau)*o22))]));
const zx=x=>A(d,i=>ev(forms.map(p=>coef(p,i)),x)),minus=zx(f(-v*inv(omega))),zero=zx(f(-v)),plus=zx(f(-omega*v));
const Hh=legs.map((leg,b)=>A(d,j=>{let k=leg.k,mask=leg.kind==="V"?f(pow(v,k)*(eta[2]*plus[j]-eta[0]*minus[j])):f(pow(v,k)*(eta[0]*zero[j]+eta[1]*plus[j])-inv(eps)*pow(-omega*v,k)*(eta[1]*minus[j]+eta[2]*zero[j]));let a=f(ss[b]*(BigInt(r[j])+ev(pp.ap[j],tau))+mask),h=f(ss[b]*(ev(pp.bp[j],tau)-y[j])*inv(o22));return [g2(a-o12*h),g2(h)]}));
const S=ss.map(g2),PQ=A(Delta,k=>g1(zeta*pow(tau,k))),PR=A(Dp,k=>k%nu?g1(zp*pow(tau,k)):-1),Y=y.map(x=>g1(zpp*x)),BQ=cells.map((c,i)=>A(J,j=>g2(gamma[i]*ev(c.key?Zk:Zo,tau)*pow(tau,j*Delta)*inv(zeta)))),BR=cells.map((c,i)=>A(Jp,j=>g2(gamma[i]*ev(Z0,tau)*pow(tau,j*Dp)*inv(zp))));
const BC={};for(let a=1;a<=3;a++)for(let t of [0,1,-1])if(a!==1||t!==-1)BC[a+","+t]=A(t===0?n-1:2*n-1,k=>g2(pi*eta[a-1]*pow(v,k)*inv(zpp)*(t===0?ev(P,v):t===1?eps:inv(eps))));
ck(l.length===(2*K1+1)*d+Delta+(nu-1)*nc/Jp,"G1 count");ck(rr.length===6*K2*d+3*K2+3*n/2*(J+Jp)+13*n-8,"G2 count");
return {ct:{forms,l,rr,ra:rr.map(x=>f(alpha*x)),ka,F,Hh,S,PQ,PR,Y,BQ,BR,BC},o:{r,y,gamma,key,alpha},g,centered}}
const lin=(ids,cs)=>ids.flatMap((i,j)=>{let c=f(coef(cs,j));ck(i>=0||!c,"forbidden coefficient");return c?[[i,c]]:[]}),apply=(v,a)=>sum(a.map(([i,c])=>v[i]*c));
function plan(pp,ct,w){const p=pp.polys(w);if(!p)return {error:"invalid-witness"};const {xi,cancel}=weights(ct.forms,w);if(!xi[0])return {error:"zero-key-weight"};const pairs=[],push=(dest,l,r,sgn=1n)=>pairs.push({dest,l:l.map(([i,c])=>[i,f(c*sgn)]),r});
legs.forEach((leg,b)=>{for(let h=0;h<2;h++){const l=cells.flatMap((c,i)=>c.b===b?lin(ct.F[c.a].map(p=>p[h]),w.map(x=>f(x*xi[i]))):[]);push("L",l,lin(ct.Hh[b].map(p=>p[h]),w));if(!h)push("P",l,[[ct.S[b],1n]])}});
for(let j=0;j<J;j++){push("L",lin(ct.PQ,p.hk.slice(j*Delta,(j+1)*Delta)),[[ct.BQ[0][j],xi[0]]],-1n);push("L",lin(ct.PQ,p.ho.slice(j*Delta,(j+1)*Delta)),cells.slice(1).map((c,i)=>[ct.BQ[i+1][j],xi[i+1]]),-1n)}
for(let j=0;j<Jp;j++)push("L",lin(ct.PR,p.R.slice(j*Dp,(j+1)*Dp)),cells.map((c,i)=>[ct.BR[i][j],xi[i]]),-1n);
push("L",lin(ct.Y,w),cancel.flatMap(([a,t,p])=>lin(ct.BC[a+","+t],p)),-1n);return {xi:xi[0],pairs}}
function comb(ct,p){let L=0n,P=0n,La=0n,Pa=0n;for(const t of p.pairs){let a=apply(ct.l,t.l),b=apply(ct.rr,t.r),ba=apply(ct.ra,t.r);if(t.dest==="L"){L=f(L+a*b);La=f(La+a*ba)}else{P=f(P+a*b);Pa=f(Pa+a*ba)}}return {L,P,La,Pa}}
function recover(ct,p,c,B){let {L,P,La,Pa}=comb(ct,p),target=f(La-p.xi*ct.ka-BigInt(c)*Pa);for(let k=0;k<=B;k++)for(const t of k?[k,-k]:[0])if(f(BigInt(t)*Pa)===target)return f((L-BigInt(c+t)*P)*inv(p.xi));return null}
function evaluate(pp,E,w){let p=plan(pp,E.ct,w);if(p.error)return p;const {L,P,La,Pa}=comb(E.ct,p),o=E.o,rw=o.r.reduce((s,x,i)=>s+x*Number(w[i]),0),psi=f(dot(o.y,w)*dot(o.gamma,weights(E.ct.forms,w).xi)),c=center(w,E.g,E.centered),B=d*(E.g+1);
ck(BigInt(2*B+1)<q&&Math.abs(rw-c)<=B,"search bounds");ck(P===psi&&L===f(p.xi*o.key+BigInt(rw)*psi)&&La===f(o.alpha*L)&&Pa===f(o.alpha*P),"Lemma 5.4");ck(recover(E.ct,p,c,B)===o.key,"key");return {p,L,P,La,Pa,c,B}}
function samplerAudit(){let checks=0,max=0,hist={};for(let g of [1,2,3,4,5])for(let centered of [false,true])for(let mask=0;mask<8;mask++){let w=[1n,...A(3,i=>BigInt((mask>>i)&1))],c=center(w,g,centered),s2=0,support=0,counts={};for(let j=0;j<g**d;j++){let v=j,coins=A(d,()=>{let x=2+v%g;v=Math.floor(v/g);return x}),r=sample(coins,g,centered),delta=r.reduce((a,x,i)=>a+x*Number(w[i]),0)-c;ck(Math.abs(delta)<=d*(g+1),"support");support=Math.max(support,Math.abs(delta));s2+=delta*delta;counts[delta]=(counts[delta]||0)+1;checks++}
let wt=mask.toString(2).replace(/0/g,"").length,upper=(centered?g*Math.sqrt((N+4)/48)+1.5:g*Math.sqrt((1+wt)/12)+.5)**2;ck(s2/g**d<=upper+1e-12,"variance");max=Math.max(max,support);if(g===5&&centered)hist[mask]={mean_square:s2/g**d,max_abs:support,counts}}
return {checks,max_abs:max,centered_g5:hist}}
return {setup,enc,plan,comb,recover,evaluate,samplerAudit,f}
}
const ws=[[1n,1n,1n,0n],[1n,0n,0n,1n]],fmt=a=>a.map(([i,c])=>i+":"+c).join(",")||"-";
function fixture(name,E,V){const ct=E.ct;lines.push(["CASE",name,V.p.xi,V.c,V.B,E.o.key,ct.ka,V.L,V.P,V.La,V.Pa].join(" "),"G1 "+ct.l.join(" "),"G2 "+ct.rr.join(" "),"GA "+ct.ra.join(" "),...V.p.pairs.map(p=>["PAIR",p.dest,fmt(p.l),fmt(p.r)].join(" ")),"END")}
for(const q of [97n,Q])for(const [n,k1,k2,chunk] of [[4,1,2,false],[4,2,1,true],[8,2,2,true]]){
const m=model(q,n,k1,k2,chunk),pp=m.setup(),alt=m.setup(true);if(!report.sampler)report.sampler=m.samplerAudit();let ok=0,zero=0,invalid=0,cases=[];
for(let seed=1;seed<=12;seed++)for(let centered of [false,true]){const g=3+seed%2,E=m.enc(pp,seed,g,centered,seed===12);for(let i=0;i<2;i++){let V=m.evaluate(pp,E,ws[i]);if(V.error){ck(V.error==="zero-key-weight","valid witness rejected");zero++;continue}ok++;
if(q===Q&&((seed===1&&centered===chunk&&i===0)||(seed===12&&centered&&i===1))){let name=`n${n}_k${k1}_s${seed}`;fixture(name,E,V);cases.push({name,g1:E.ct.l.length,g2:E.ct.rr.length*2,pairings_per_comb:V.p.pairs.length,zero_psi:V.P===0n})}}
for(let mask=0;mask<8;mask++){let w=[1n,...A(3,j=>BigInt((mask>>j)&1))];if(!ws.some(v=>v.every((x,i)=>x===w[i]))){ck(m.plan(pp,E.ct,w).error==="invalid-witness","invalid witness accepted");invalid++}}}
if(q===Q){let E=m.enc(pp,71,4,true),V=m.evaluate(pp,E,ws[0]),ct=E.ct;function mutate(kind,ids,alphaOnly=false){for(let i of ids){const cp={...ct,rr:ct.rr.slice(),ra:ct.ra.slice()};if(!alphaOnly)cp.rr[i]=m.f(cp.rr[i]+1n);cp.ra[i]=m.f(cp.ra[i]+(alphaOnly?1n:E.o.alpha));let C=m.comb(cp,V.p);if(C.L!==V.L||C.P!==V.P||C.La!==V.La||C.Pa!==V.Pa)return {kind,comb_changed:true,original_key_recovered:m.recover(cp,V.p,V.c,V.B)===E.o.key}}throw Error("unused "+kind)}
const bad=[mutate("quotient",ct.BQ.flat()),mutate("remainder",ct.BR.flat()),mutate("mask",Object.values(ct.BC).flat()),mutate("alpha_copy",A(ct.ra.length,i=>i),true)];
const ap=m.plan(alt,ct,[1n,0n,0n,0n]);ck(!ap.error,"alternate fixture");const wrong=m.recover(ct,ap,5,20);ck(wrong!==E.o.key,"wrong statement key");bad.push({kind:"wrong_statement",original_key_recovered:false});report.mutations.push({n,K1:k1,controls:bad})}
if(q===97n&&n===8){let E=m.enc(pp,17,3,true,false,true);ck(m.plan(pp,E.ct,ws[0]).error==="zero-key-weight","zero weight rejection");report.zero_weight="rejected"}
report.variants.push({field:q===Q?"BN254 Fr":"F97",n,K1:k1,K2:k2,chunked:chunk,valid_recoveries:ok,zero_key_weight:zero,invalid_witness_rejections:invalid,real_group_fixtures:cases})}
return {report,tsv:lines.join("\n")+"\n"}}
const o=runPraxis();
if(process.argv[2]==='--fixtures')process.stdout.write(o.tsv);else console.log(JSON.stringify(o.report,null,2));
