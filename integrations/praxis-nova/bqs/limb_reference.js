'use strict';
// PNS-04B: shared canonical Pasta limb equations; research reference.
function run(){
const MODS={PallasBase:0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001n,VestaBase:0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n};
const Q=21888242871839275222246405745257275088548364400416034343698204186575808495617n,B=1n<<32n,L=8,S=1n<<36n,W=37;
const ck=(v,m)=>{if(!v)throw Error(m)},A=(n,f)=>Array.from({length:n},(_,i)=>f(i)),mod=(x,p)=>((x%p)+p)%p,digit=(x,i)=>(x>>BigInt(32*i))&(B-1n);
const shape=[];let gateTests=0;for(let tt=0;tt<16;tt++){const d=tt&1,l=((tt>>2)&1)-d,r=((tt>>1)&1)-d,m=((tt>>3)&1)-d-l-r;for(let a of [0,1])for(let b of [0,1])for(let z of [0,1]){ck((d+l*a+r*b+m*a*b===z)===(z===((tt>>(2*a+b))&1)),"truth polynomial");gateTests++}}
class BQS{
 constructor(p){this.p=p;this.w=[1];this.rows=[];this.names={}}
 bit(v,name){ck(v===0n||v===1n,"bit");let i=this.w.length;this.w.push(Number(v));if(name)this.names[name]=i;return [[i,1n]]}
 con(x){return x?[[0,x]]:[]}
 sc(a,k){return a.map(([i,c])=>[i,c*k])}
 add(...a){return a.flat()}
 bits(v,n,name){ck(v>=0n&&v<(1n<<BigInt(n)),"bit range "+name);return A(n,i=>this.sc(this.bit((v>>BigInt(i))&1n,name+"."+i),1n<<BigInt(i))).flat()}
 linear(name,c){this.rows.push({name,ab:[],c})}
 row(name,ab,c){this.rows.push({name,ab,c})}
 eval(a,w=this.w){return a.reduce((v,[i,c])=>v+BigInt(w[i])*c,0n)}
 int(v,n,name){let k=Math.ceil(n/32),parts=A(k,i=>this.bits(digit(v,i),Math.min(32,n-32*i),name+"."+i));ck(v>=0n&&v<(1n<<BigInt(n)),"int width");return {v,parts}}
 // Canonical 255-bit Pasta values. A bit-valued carry chain for x+slack=p-1.
 scalar(v,name){const x=this.int(v,255,name),sl=this.int(v<this.p?this.p-1n-v:0n,255,name+".slack");let carry=0n,cl=[];
 for(let i=0;i<L;i++){let t=digit(v,i)+digit(sl.v,i)+carry-digit(this.p-1n,i),next=t>=B?1n:0n;
 if(v<this.p)ck(t===B*next,"canonical trace");
 let nl=i===L-1?[]:this.bit(next,name+".rc."+i);
 this.linear(name+".canonical."+i,this.add(x.parts[i],sl.parts[i],cl,this.con(-digit(this.p-1n,i)),this.sc(nl,-B)));cl=nl;carry=next}
 return x}
 // Every operation consumes preallocated canonical inputs and allocates
 // canonical output once. Multiplication columns use signed 37-bit carries.
 mul(a,b,name,override=null){const r=this.scalar(override?.r??a.v*b.v%this.p,name+".r"),k=this.scalar(override?.k??a.v*b.v/this.p,name+".k");let carry=0n,cl=[];
 for(let j=0;j<2*L;j++){let ab=[],v=carry-digit(r.v,j),rhs=this.add(r.parts[j]||[],this.sc(cl,-1n));
 for(let i=0;i<L;i++){let h=j-i;if(h>=0&&h<L){ab.push([a.parts[i],b.parts[h]]);v+=digit(a.v,i)*digit(b.v,h)-digit(this.p,i)*digit(k.v,h);rhs=this.add(rhs,this.sc(k.parts[h],digit(this.p,i)))}}
 let next=v/B;let nl=j===2*L-1?[]:this.add(this.bits(next+S,W,name+".carry."+j),this.con(-S));this.row(name+".mul."+j,ab,this.add(rhs,this.sc(nl,B)));cl=nl;carry=next}
 return r}
 // a + b = r + k*p or a - b + k*p = r; k is exactly a bit.
 addsub(a,b,name,sub=false){let v=sub?a.v-b.v:a.v+b.v,r=this.scalar(mod(v,this.p),name+".r"),k=sub?BigInt(v<0n):BigInt(v>=this.p),kl=this.bit(k,name+".k");let carry=0n,cl=[];
 for(let j=0;j<L;j++){let t=digit(a.v,j)+(sub?-1n:1n)*digit(b.v,j)+(sub?1n:-1n)*k*digit(this.p,j)-digit(r.v,j)+carry;
 let next=t/B;ck(t===next*B&&next>=-2n&&next<=1n,"add carry");
 let nl=j===L-1?[]:this.add(this.bits(next+2n,2,name+".carry."+j),this.con(-2n));
 this.linear(name+".addsub."+j,this.add(a.parts[j],this.sc(b.parts[j],sub?-1n:1n),this.sc(kl,(sub?1n:-1n)*digit(this.p,j)),this.sc(r.parts[j],-1n),cl,this.sc(nl,-B)));carry=next;cl=nl}
 return r}
 // Reduction of the full 512-bit Fiat-Shamir output. In integration the
 // wide bits must be the actual Keccak output wires, not free input bits.
 wide(x,name,wrong=null){const r=this.scalar(wrong??x.v%this.p,name+".r"),k=this.int(x.v/this.p,258,name+".k");let carry=0n,cl=[];
 for(let j=0;j<16;j++){let t=digit(x.v,j)-digit(r.v,j)+carry,expr=this.add(x.parts[j],this.sc(r.parts[j]||[],-1n),cl);
 for(let i=0;i<L;i++){let h=j-i;if(h>=0&&h<k.parts.length){t-=digit(this.p,i)*digit(k.v,h);expr=this.add(expr,this.sc(k.parts[h],-digit(this.p,i)))}}
 let next=t/B,nl=j===15?[]:this.add(this.bits(next+S,W,name+".carry."+j),this.con(-S));this.linear(name+".wide."+j,this.add(expr,this.sc(nl,-B)));carry=next;cl=nl}
 return r}
 pin(x,v,name){for(let j=0;j<x.parts.length;j++)this.linear(name+"."+j,this.add(x.parts[j],this.con(-digit(v,j))))}
 check(w=this.w){if(w.length!==this.w.length||w[0]!==1||w.some(x=>x!==0&&x!==1))return false;for(let r of this.rows){let z=r.ab.reduce((s,[a,b])=>s+this.eval(a,w)*this.eval(b,w),0n)-this.eval(r.c,w);if(mod(z,Q)!==0n)return false}return true}
 stats(){return {boolean_unknowns:this.w.length-1,equations:this.rows.length,max_products:Math.max(0,...this.rows.map(r=>r.ab.length))}}
}
const max=2n*BigInt(L)*(B-1n)**2n+B-1n+S+B*S;ck(max<Q,"no wrap");
let rng=19n;const random=p=>{rng=(rng*6364136223846793005n+1442695040888963407n)&((1n<<512n)-1n);return rng%p};
const results=[];
for(let [field,p] of Object.entries(MODS)){
 let counts={},pos=0,neg=0;
 const vals=[0n,1n,B-1n,B,p-2n,p-1n];const pairs=vals.flatMap(a=>vals.map(b=>[a,b]));for(let i=0;i<12;i++)pairs.push([random(p),random(p)]);
 for(let [a,b] of pairs){let g=new BQS(p),aa=g.scalar(a,"a"),bb=g.scalar(b,"b");const before=g.stats();g.mul(aa,bb,"m");ck(g.check(),"mul");pos++;
 const full=g.stats();counts.mul_standalone=full;counts.mul_incremental={boolean_unknowns:full.boolean_unknowns-before.boolean_unknowns,equations:full.equations-before.equations,max_products:full.max_products};for(let name of ["m.r.0.0","m.k.0.0","m.carry.0.0","a.slack.0.0"]){let w=g.w.slice();w[g.names[name]]^=1;ck(!g.check(w),"mul mutate");neg++}
 let h=new BQS(p),x=h.scalar(a,"a"),y=h.scalar(b,"b"),base=h.stats();h.addsub(x,y,"add");const add=h.stats();counts.add_incremental={boolean_unknowns:add.boolean_unknowns-base.boolean_unknowns,equations:add.equations-base.equations,max_products:add.max_products};h.addsub(x,y,"sub",true);ck(h.check(),"add/sub");pos+=2;
 }
 for(let x of [0n,p-1n,p,1n<<511n,(1n<<512n)-1n,random(1n<<512n)]){let g=new BQS(p),xx=g.int(x,512,"hash"),b=g.stats();g.wide(xx,"reduce");let s=g.stats();counts.wide_incremental={boolean_unknowns:s.boolean_unknowns-b.boolean_unknowns,equations:s.equations-b.equations,max_products:s.max_products};ck(g.check(),"wide reduce");pos++;let w=g.w.slice();w[g.names["reduce.k.0.0"]]^=1;ck(!g.check(w),"wrong quotient");neg++}
 // A whole quadratic/cubic sumcheck arithmetic transition with one shared
 // assignment and pinned initial/final claims; challenge supplied as input.
 for(let d of [2,3]){
  let g=new BQS(p),claim=g.scalar(p-1n,"claim"),a0=g.scalar(p-2n,"a0"),a2=g.scalar(3n,"a2"),a3=d===3?g.scalar(5n,"a3"):null,r=g.scalar(random(p),"challenge");
  let twice=g.addsub(a0,a0,"double"),a1=g.addsub(claim,twice,"d0",true);a1=g.addsub(a1,a2,"d1",true);if(a3)a1=g.addsub(a1,a3,"d2",true);
  let v=a3||a2;if(a3){v=g.mul(v,r,"h3");v=g.addsub(v,a2,"h3add")}v=g.mul(v,r,"h2");v=g.addsub(v,a1,"h2add");v=g.mul(v,r,"h1");v=g.addsub(v,a0,"h1add");
  let linear=mod(claim.v-2n*a0.v-a2.v-(a3?.v||0n),p),want=mod(a0.v+linear*r.v+a2.v*r.v*r.v+(a3?.v||0n)*r.v*r.v*r.v,p);
  ck(v.v===want,"native integer reference");g.pin(claim,claim.v,"pinclaim");g.pin(v,want,"pinnext");ck(g.check(),"sumcheck arithmetic");pos++;counts["sumcheck_degree_"+d+"_arithmetic_only"]=g.stats();
  let w=g.w.slice();w[g.names["h1add.r.0.0"]]^=1;ck(!g.check(w),"next mutation");neg++;
 }
 let g=new BQS(p);g.scalar(p,"invalid");ck(!g.check(),"noncanonical");neg++;
 results.push({field,positive_checks:pos,negative_controls:neg,counts})
}
return {scope:"Exact limb BQS arithmetic reference; challenge hash must be bound by actual transcript circuit",radix:"2^32",signed_carry_width:W,max_integer_residual_bound:max.toString(),gate_truth_table_assignments:gateTests,fields:results};
}
console.log(JSON.stringify(run(),null,2));
