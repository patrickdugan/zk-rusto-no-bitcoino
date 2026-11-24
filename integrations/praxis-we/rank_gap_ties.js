// PRAXIS-04: exact toy field reference; run with node.
'use strict';
function main() {
  // PRAXIS-04 exact toy field regression. Sections 4 and 5.1, equation (5).
  const q=17, n=4, c0=3, omega=13, nu=4;
  const mod=x=>((x%q)+q)%q;
  const check=(x,msg)=>{if(!x)throw Error(msg)};
  const zeros=k=>Array(k).fill(0);
  const vec=(k,f)=>Array.from({length:k},(_,i)=>f(i));
  const sum=a=>mod(a.reduce((s,x)=>s+x,0));
  const power=(x,k)=>{let y=1;for(let i=0;i<k;i++)y=mod(y*x);return y};
  const inv=x=>{check(mod(x)!==0,"zero inverse");return power(mod(x),q-2)};
  const e=i=>vec(n,j=>+(i===j));
  const zero=e(-1);
  const dot=(a,b)=>sum(a.map((x,i)=>x*b[i]));
  const matvec=(M,x)=>M.map(row=>dot(row,x));
  const outer=(a,b)=>a.map(x=>b.map(y=>mod(x*y)));
  const scale=(a,s)=>a.map(x=>mod(x*s));
  const add=(a,b)=>vec(Math.max(a.length,b.length),i=>mod((a[i]||0)+(b[i]||0)));
  const sub=(a,b)=>add(a,scale(b,-1));
  const trim=a=>{let b=a.map(mod);while(b.length&&b[b.length-1]===0)b.pop();return b};
  const mul=(a,b)=>{const r=zeros(Math.max(0,a.length+b.length-1));for(let i=0;i<a.length;i++)for(let j=0;j<b.length;j++)r[i+j]=mod(r[i+j]+a[i]*b[j]);return trim(r)};
  const evalp=(a,x)=>a.reduceRight((s,y)=>mod(s*x+y),0);
  const product=ps=>ps.reduce((a,x)=>mul(a,[mod(-x),1]),[1]);
  const divrem=(a,b)=>{a=trim(a);b=trim(b);check(b.length,"zero divisor");const d=zeros(Math.max(0,a.length-b.length+1));while(a.length>=b.length){let k=a.length-b.length,s=mod(a[a.length-1]*inv(b[b.length-1]));d[k]=s;for(let j=0;j<b.length;j++)a[k+j]=mod(a[k+j]-s*b[j]);a=trim(a)}return [trim(d),a]};
  const lagrange=pts=>pts.map(x=>{const p=product(pts.filter(y=>y!==x));return scale(p,inv(evalp(p,x)))});
  const interp=(L,y)=>trim(L.reduce((p,l,i)=>add(p,scale(l,y[i])),[]));
  const ext=a=>vec(n,i=>divrem(a,[mod(-c0),0,0,0,1])[1][i]||0);
  const emul=(a,b)=>{const r=zeros(n);for(let i=0;i<n;i++)for(let j=0;j<n;j++){const k=i+j;r[k%n]=mod(r[k%n]+a[i]*b[j]*(k>=n?c0:1))}return r};
  const sigma=(a,k)=>a.map((x,i)=>mod(x*power(omega,(k*i)%n)));
  const pairs=[];for(let i=0;i<n;i++)for(let j=i;j<n;j++)pairs.push([i,j]);
  const m=pairs.length, copies=6;
  const matrix=x=>{let M=vec(n,()=>zeros(n));pairs.forEach(([i,j],k)=>{M[i][j]=M[j][i]=mod(x[k])});return M};
  const flat=M=>pairs.map(([i,j])=>M[i][j]);
  const unit=(k,d)=>vec(d,i=>+(i===k));
  const basis=vec(m,k=>matrix(unit(k,m)));
  const rref=(rows,d)=>{let A=rows.map(r=>r.map(mod)),piv=[],r=0;for(let j=0;j<d&&r<A.length;j++){let k=A.findIndex((row,i)=>i>=r&&row[j]!==0);if(k<0)continue;[A[k],A[r]]=[A[r],A[k]];A[r]=scale(A[r],inv(A[r][j]));for(let i=0;i<A.length;i++)if(i!==r&&A[i][j])A[i]=sub(A[i],scale(A[r],A[i][j]));piv.push(j);r++}return {rows:A.slice(0,r),piv}};
  const rank=rows=>rref(rows,rows[0]?.length||0).piv.length;
  const kernel=(rows,d)=>{const R=rref(rows,d);return vec(d,i=>i).filter(i=>!R.piv.includes(i)).map(i=>{let v=unit(i,d);R.piv.forEach((j,k)=>v[j]=mod(-R.rows[k][i]));return v})};
  const columns=(cols)=>vec(cols[0].length,i=>cols.map(c=>c[i]));
  const stack=x=>vec(copies,k=>matrix(x.slice(k*m,(k+1)*m)));
  const stackRank=W=>rank(W.flat());
  const zeroes=a=>a.every(x=>x===0);
  const assignments=vec(8,k=>[1,...vec(3,i=>(k>>i)&1)]);
  function* projective(d){for(let j=0;j<d;j++)for(let k=0;k<q**(d-j-1);k++){let z=k;const v=zeros(d);v[j]=1;for(let i=j+1;i<d;i++){v[i]=z%q;z=Math.floor(z/q)}yield v}}
  // Irreducibility: a reducible quartic has a monic factor of degree 1 or 2.
  const P=[mod(-c0),0,0,0,1];
  for(let a=0;a<q;a++){check(divrem(P,[a,1])[1].length>0,"linear factor");for(let b=0;b<q;b++)check(divrem(P,[a,b,1])[1].length>0,"quadratic factor")}
  check(power(omega,4)===1&&power(omega,2)===q-1&&omega===power(c0,4),"Frobenius");
  for(let a=0;a<q;a++)for(let b=0;b<q;b++){
    const x=[a,b,1,2],y=[b,a,3,4];
    check(JSON.stringify(emul(x,y))===JSON.stringify(ext(mul(x,y))),"extension multiplication");
    check(JSON.stringify(sigma(emul(x,y),1))===JSON.stringify(emul(sigma(x,1),sigma(y,1))),"Frobenius product");
  }
  // Constraint t = list of product pairs and c, with sum a(w)b(w)=w0 c(w).
  const fixtures={
    true_multi:[{ab:[[e(1),e(2)],[e(3),e(0)]],c:e(0)},{ab:[[e(0),e(1)]],c:e(2)}],
    false_free:[{ab:[[zero,zero]],c:e(0)},{ab:[[zero,zero],[zero,zero]],c:zero}],
  };
  const direct=(S,W)=>[...vec(n-1,k=>mod(W[k+1][k+1]-W[0][k+1])),...S.map(t=>mod(sum(t.ab.map(([a,b])=>dot(a,matvec(W,b))))-dot(e(0),matvec(W,t.c))))];
  const passes=(S,W)=>zeroes(direct(S,W));
  const witness=(S,w)=>w[0]===1&&w.every(x=>x===0||x===1)&&passes(S,outer(w,w));
  // Two disjoint cosets of order 4; d0,...,d3,rho outside them.
  const H=vec(nu,i=>power(omega,i));
  const cosets=[H,H.map(x=>mod(3*x))];
  const K=cosets.flat(), P0=vec(q,i=>i).filter(x=>!K.includes(x)).slice(0,n+1);
  const rho=P0[n], pts=[...P0,...K], D=pts.length;
  check(new Set(pts).size===D&&D===13,"admissible QAP");
  const Z0=product(P0),Z=product(pts.filter(x=>x!==rho)),L=lagrange(pts),LK=lagrange(K);
  const Lrho=L[n],Zkey=mul(Z,[mod(-rho),1]);
  function qap(S){
    const A=[zero,...vec(n-1,k=>sub(e(k+1),e(0))),e(0)];
    const B=[e(0),...vec(n-1,k=>e(k+1)),e(0)];
    S.forEach((t,i)=>cosets[i].forEach((p,j)=>{
      if(j<t.ab.length){A.push(scale(t.ab[j][0],evalp(Z0,p)));B.push(t.ab[j][1])}
      else if(j===t.ab.length){A.push(scale(e(0),evalp(Z0,p)));B.push(scale(t.c,-1))}
      else {A.push(zero);B.push(zero)}
    }));
    const ap=vec(n,i=>interp(L,A.map(a=>a[i]))),bp=vec(n,i=>interp(L,B.map(b=>b[i])));
    const pw=W=>trim(ap.reduce((p,a,i)=>bp.reduce((s,b,j)=>add(s,scale(mul(a,b),W[i][j])),p),[]));
    return W=>{
      const p=pw(W);
      const R=interp(LK,K.map(k=>mod(evalp(p,k)*inv(evalp(Z0,k)))));
      const [h,r]=divrem(sub(sub(p,scale(Lrho,W[0][0])),mul(Z0,R)),Zkey);
      const [hOther,rOther]=divrem(sub(p,mul(Z0,R)),Z);
      check(h.length<D-1+1&&hOther.length<=D,"QAP degree");
      const forbidden=vec(K.length/nu,i=>R[i*nu]||0);
      return {b:[...forbidden,...vec(Zkey.length-1,i=>r[i]||0)],c:[...forbidden,...vec(Z.length-1,i=>rOther[i]||0)]};
    };
  }
  const identity=vec(n,i=>e(i)),degenerate=[e(0),e(1),e(2),zero];
  const z=(forms,w)=>forms.map(f=>dot(f,w));
  const weights=(forms,w)=>{let a=z(forms,w),u=emul(a,sigma(a,1)),v=emul(a,sigma(a,2));check(v[1]===0&&v[3]===0,"V parity");return [...u,v[0],v[2]]};
  const honest=(forms,w)=>weights(forms,w).map(s=>outer(scale(w,s),w));
  const packed=(W,i,j)=>[vec(n,k=>W[k][i][j]),[W[4][i][j],0,W[5][i][j],0]];
  // Equation (5), polynomial products in F_q[T]/(T^4-3); all output coefficients.
  const tie=(forms,W)=>{const out=[];
    for(let i=0;i<n;i++){let t=[zeros(n),zeros(n),zeros(n)];
      for(let j=0;j<n;j++){let [U,V]=packed(W,i,j),a=forms.map(f=>f[j]),b=sigma(a,1),c=sigma(a,2),d=sigma(a,3),U3=sigma(U,3);
        t[0]=add(t[0],sub(emul(U,c),emul(V,b)));
        t[1]=add(t[1],sub(emul(U,d),emul(U3,b)));
        t[2]=add(t[2],sub(emul(V,d),emul(U3,c)));
      }out.push(...t.flat())
    }return out};
  const tied=(forms,W)=>zeroes(tie(forms,W));
  const report={q,n,c0,omega,cosets,P0,rho,fixtures:{}};
  for(const [name,S] of Object.entries(fixtures)){
    const Q=qap(S),d=columns(basis.map(W=>direct(S,W))),b=columns(basis.map(W=>Q(W).b)),c=columns(basis.map(W=>Q(W).c));
    // Equal row spaces certify identical kernels for ALL 17^10 symmetric matrices.
    const canonical=A=>JSON.stringify(rref(A,m).rows);
    check(canonical(d)===canonical(b)&&canonical(d)===canonical(c),"QAP criterion failed");
    const ws=assignments.filter(w=>witness(S,w));
    let checked=0,passing=0;
    for(const u of projective(n)){
      checked++;const W=outer(u,u);
      if(passes(S,W)){passing++;check(u[0]!==0,"rank-one zero corner");const w=scale(u,inv(u[0]));check(witness(S,w),"rank-one extraction")}
    }
    check(passing===ws.length,"rank-one witness count");
    for(const w of assignments){const W=honest(identity,w);check(tied(identity,W),"honest tie");check(W.every(M=>passes(S,M))===witness(S,w),"honest pass");if(witness(S,w))check(stackRank(W)===1,"honest rank")}
    report.fixtures[name]={witnesses:ws,projective_rank1_checked:checked,passing_rank1_lines:passing,qap_row_rank:rank(d),qap_equivalence_all_symmetric:true};
  }
  const S=fixtures.false_free;
  const off=(i,j)=>{const W=vec(n,()=>zeros(n));W[i][j]=W[j][i]=1;return W};
  const W2=vec(copies,k=>k===0?off(1,2):matrix(zeros(m)));
  const W3=vec(copies,k=>k===0?off(1,2):k===1?off(1,3):matrix(zeros(m)));
  const passStack=W=>W.every(M=>passes(S,M));
  for(const [W,r] of [[W2,2],[W3,3]])check(passStack(W)&&stackRank(W)===r&&!tied(identity,W),"untied cheat control");
  // With phi_3=0, e3 lies in kernel. Weight offdiag(1,3) by weights(e1).
  const Wk=weights(degenerate,e(1)).map(s=>off(1,3).map(row=>scale(row,s)));
  check(passStack(Wk)&&tied(degenerate,Wk)&&stackRank(Wk)===2&&!tied(identity,Wk),"kernel-bearing tied cheat");
  check(zeroes(z(degenerate,e(3))),"kernel vector");
  const Ktie=kernel(columns(vec(copies*m,k=>{const W=stack(unit(k,copies*m));return [...W.flatMap(M=>direct(S,M)),...tie(identity,W)]})),copies*m);
  // Certify no nonzero passing tied stack of rank <= 3, by testing every
  // possible projective right-null vector. A rank <= 3 stack must have one.
  let nullsChecked=0,lowRankSpaces=0;
  for(const u of projective(n)){
    nullsChecked++;
    if(!Ktie.length)continue;
    const E=columns(Ktie.map(v=>stack(v).flatMap(M=>matvec(M,u))));
    if(kernel(E,Ktie.length).length)lowRankSpaces++;
  }
  check(lowRankSpaces===0,"injective false fixture admits low-rank tied stack");
  // Guessing bound, independent sampler r_i in {2,3,4}, exactly 81 vectors.
  function gp(W){const freq=new Map();let total=0;for(let k=0;k<81;k++){let x=k,r=vec(n,()=>{const v=2+x%3;x=Math.floor(x/3);return v});let key=W.flatMap(M=>matvec(M,r)).join(",");freq.set(key,(freq.get(key)||0)+1);total++}return {max:Math.max(...freq.values()),total}}
  const g2=gp(W2),g3=gp(W3),gk=gp(Wk);
  check(g2.max===9&&g3.max===3&&gk.max===9,"guessing probability");
  report.cheats={rank2:{passes:true,tied:false,gp:g2},rank3:{passes:true,tied:false,gp:g3},degenerate_kernel_rank2:{passes:true,tied:true,gp:gk,kernel_vector:e(3)}};
  report.injective_false={passing_tied_dimension:Ktie.length,projective_null_vectors_checked:nullsChecked,nonzero_low_rank_nullspaces:lowRankSpaces};
  report.scope="Toy exact arithmetic; independent sampler only; no MSIS hardness, ciphertext, extraction theorem, or security claim.";
  return report;
}
console.log(JSON.stringify(main(), null, 2));
