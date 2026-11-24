'use strict';
// PNS-04E: exact wide reduction of actual transcript wires.
function wideLibrary(lib){
  const {ck,PALLAS,VESTA,Q,Bqs}=lib,B=1n<<86n,S=1n<<90n;
  const A=(n,f)=>Array.from({length:n},(_,i)=>f(i)),d=(x,i)=>(x>>BigInt(i*86))&(B-1n),con=x=>x?[[0,x]]:[],sc=(l,k)=>l.map(([i,c])=>[i,c*k]),add=(...l)=>l.flat();
  const parts=(g,w)=>A(Math.ceil(w.ids.length/86),i=>g.lcBits(w.ids.slice(i*86,i*86+86)));
  const bound=3n*(B-1n)**2n+2n*(B-1n)+S+B*S;ck(bound<Q,"integer wrap");
  function reduce(g,ids,p,override={}){
    ck((p===PALLAS||p===VESTA)&&ids.length===512,"wide reduction shape");
    const x=g.word(ids),k=g.integer(override.k??x.v/p,258),r=g.scalar(override.r??x.v%p,p);
    const xl=parts(g,x),kl=parts(g,k),rl=parts(g,r);
    let carry=0n,cl=[],carries=[];
    for(let j=0;j<6;j++){
      let t=d(x.v,j)-d(r.v,j)+carry,expr=add(xl[j],sc(rl[j]||[],-1n),cl);
      for(let i=0;i<3;i++){let h=j-i;if(h>=0&&h<3){let pd=d(p,i);t-=pd*d(k.v,h);expr=add(expr,sc(kl[h],-pd))}}
      let next=t/B;
      // Use a legal bounded assignment even for intentionally wrong quotient/remainder;
      // its nonzero residual is caught by the relation.
      ck(next>=-S&&next<S,"carry range");
      const bits=j===5?[]:g.bits(next+S,91);
      const nl=j===5?[]:add(g.lcBits(bits),con(-S));
      g.lin(add(expr,sc(nl,-B)),"wide reduce column");
      carries.push(bits);carry=next;cl=nl;
    }
    return {r,k,carries};
  }
  function selftest(){
    const fields=[];let seed=27n;const random=()=>{seed=(seed*6364136223846793005n+1442695040888963407n)&((1n<<512n)-1n);return seed};
    for(const [field,p] of [["PallasBase",PALLAS],["VestaBase",VESTA]]){
      let pos=0,neg=0,shape;
      for(const x of [0n,1n,p-1n,p,p+1n,p*p-1n,1n<<511n,(1n<<512n)-1n,...A(16,()=>random())]){
        const g=new Bqs(null,true),w=g.integer(x,512),before=g.stats(),a=reduce(g,w.ids,p),after=g.stats();
        ck(a.r.v===x%p&&a.k.v===x/p&&g.failed===0&&g.replay(),"valid reduction");
        const counts={boolean_unknowns:after.boolean_unknowns-before.boolean_unknowns,equations:after.equations-before.equations};
        if(shape)ck(JSON.stringify(shape)===JSON.stringify(counts),"shape invariance");shape=counts;pos++;
        for(const id of [a.r.ids[0],a.k.ids[0],a.carries[0][0],w.ids[0]]){
          const old=g.w.at(id);g.w.set(id,old^1);ck(!g.replay(),"mutated witness/digest");g.w.set(id,old);neg++;
        }
      }
      // The exact identity holds but r=p is noncanonical; this must fail.
      const g=new Bqs(),w=g.integer(p,512);reduce(g,w.ids,p,{k:0n,r:p});ck(g.failed>0,"noncanonical alias");neg++;
      fields.push({field,positives:pos,negative_controls:neg,incremental:shape});
    }
    return {scope:"Exact 512-bit transcript digest reduction with shared input slots; native hash integration separate CI",limb_bits:86,carry_bits:91,max_integer_residual_bound:bound.toString(),fields};
  }
  return {reduce,selftest};
}
module.exports=wideLibrary(require('./ipa_bqs.js'));
if(require.main===module)console.log(JSON.stringify(module.exports.selftest(),null,2));
