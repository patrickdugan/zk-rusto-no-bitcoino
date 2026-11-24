'use strict';
// PRAXIS-08: BQS compiler primitive for non-native BN254 base-field multiplication.
function runNonnative(){
 const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
 const Q=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
 const B=65536n,L=16,S=1n<<24n,W=25;
 const arr=(n,f)=>Array.from({length:n},(_,i)=>f(i)),ck=(v,s)=>{if(!v)throw Error(s)},mod=x=>((x%Q)+Q)%Q;
 const digits=x=>arr(L,i=>(x>>BigInt(16*i))&(B-1n)),pd=digits(P);
 // BQS witness has w0=1; remaining entries are bits. Each equation is
 // sum of products of sparse linear forms = one sparse linear form.
 function build(a,b,r=a*b%P,k=a*b/P){
  let w=[1n],eq=[],names={},lcount=0,maxTerms=0;
  const bit=(v,name)=>{ck(v===0n||v===1n,"not a bit");w.push(v);let id=w.length-1;names[name]=id;return [[id,1n]]};
  const con=x=>x?[[0,x]]:[],scale=(p,c)=>p.map(([i,x])=>[i,x*c]),add=(...ps)=>ps.flat(),neg=p=>scale(p,-1n);
  const linear=(name,p)=>{eq.push({name,ab:[],c:p});lcount++};
  const quad=(name,ab,c)=>{eq.push({name,ab,c});maxTerms=Math.max(maxTerms,ab.length)};
  const bits=(v,n,name)=>{ck(v>=0n&&v<(1n<<BigInt(n)),"out of bit range "+name);return arr(n,i=>scale(bit((v>>BigInt(i))&1n,name+"."+i),1n<<BigInt(i))).flat()};
  const limbs=(v,name)=>{ck(v>=0n&&v<(1n<<256n),"operand range");return digits(v).map((x,i)=>bits(x,16,name+"."+i))};
  // For canonical x, enforce x + slack = p-1 as integers using binary carries.
  // A noncanonical x still gets a bit assignment (slack=0); some local equality fails.
  function canonical(x,xs,name){let sl=x<P?P-1n-x:0n,ss=limbs(sl,name+".slack"),xd=digits(x),sd=digits(sl),td=digits(P-1n);let c=0n,cl=con(0n);for(let j=0;j<L;j++){
   let t=xd[j]+sd[j]+c-td[j],next=t>=B?1n:0n;
   if(x<P){ck(t%B===0n&&(t===0n||t===B),"canonical trace");next=t/B}
   let nl=j===L-1?con(0n):bit(next,name+".canoncarry."+j);
   linear(name+".canonical."+j,add(xs[j],ss[j],cl,con(-td[j]),scale(nl,-B)));cl=nl;c=next
  }}
  const aa=limbs(a,"a"),bb=limbs(b,"b"),rr=limbs(r,"r"),kk=limbs(k,"k");canonical(a,aa,"a");canonical(b,bb,"b");canonical(r,rr,"r");canonical(k,kk,"k");
  const ad=digits(a),bd=digits(b),rd=digits(r),kd=digits(k);let carry=0n,carryL=con(0n);
  for(let j=0;j<2*L;j++){
   let pairs=[],sum=carry-(rd[j]||0n),rhs=add(rr[j]||[],neg(carryL));
   for(let i=0;i<L;i++){let h=j-i;if(h>=0&&h<L){pairs.push([aa[i],bb[h]]);sum+=ad[i]*bd[h]-pd[i]*kd[h];rhs=add(rhs,scale(kk[h],pd[i]))}}
   // For bad traces, floor-style division creates a legal assignment but
   // leaves a nonzero column residual; endpoints are forced to zero.
   let next=sum/B;
   ck(next>=-S&&next<S,"carry overflow");
   let nl=j===2*L-1?con(0n):add(bits(next+S,W,"mulcarry."+j),con(-S));
   quad("mul."+j,pairs,add(rhs,scale(nl,B)));carry=next;carryL=nl;
  }
  function check(v){if(v.length!==w.length||v[0]!==1n||v.some(x=>x!==0n&&x!==1n))return "boolean";let ev=p=>p.reduce((a,[i,c])=>a+v[i]*c,0n);
   for(const t of eq){let delta=t.ab.reduce((s,[a,b])=>s+ev(a)*ev(b),0n)-ev(t.c);if(mod(delta)!==0n)return t.name}
   return null}
  return {w,eq,names,check,lcount,maxTerms}
 }
 // Range argument for every possible binary assignment: each product term
 // is < B^2, at most L such terms per side; each signed carry is < S+1.
 const bound=2n*BigInt(L)*(B-1n)**2n+B-1n+S+B*S;
 ck(bound<Q,"column wrap");
 const canonBound=3n*B+2n;ck(canonBound<Q,"canonical wrap");
 let state=23n;const rnd=()=>{state=(state*6364136223846793005n+1442695040888963407n)&((1n<<256n)-1n);return state%P};
 const vals=[0n,1n,B-1n,B,B+1n,P-1n,Q-1n,Q,P-2n],fixtures=[];
 for(const a of vals)for(const b of vals)fixtures.push([a,b]);for(let i=0;i<24;i++)fixtures.push([rnd(),rnd()]);
 let checked=0,mutations=0,receipt;
 for(const [a,b] of fixtures){let t=build(a,b);ck(t.check(t.w)===null,"valid product");checked++;
  for(const name of ["a.0.0","b.0.0","r.0.0","k.0.0","mulcarry.0.0","a.slack.0.0"]){
   let v=t.w.slice();v[t.names[name]]^=1n;ck(t.check(v)!==null,"mutated trace "+name);mutations++}
  if(!receipt)receipt={boolean_unknowns:t.w.length-1,equations:t.eq.length,linear_equations:t.lcount,max_products_per_equation:t.maxTerms};
 }
 for(const [a,b,r,k] of [[P,1n,0n,1n],[1n,P,0n,1n],[1n,1n,P+1n,0n],[P-1n,P-1n,2n,P-2n],[2n,3n,6n,1n]]){
  let t=build(a,b,r,k);ck(t.check(t.w)!==null,"invalid relation");mutations++}
 return {scope:"BQS non-native Fp multiplication primitive in Fr; full Groth16 verifier absent",field_moduli:{p:P.toString(),q:Q.toString()},radix:B.toString(),max_integer_residual:bound.toString(),canonical_residual_bound:canonBound.toString(),valid_products:checked,negative_controls:mutations,...receipt};
}
console.log(JSON.stringify(runNonnative(),null,2));
