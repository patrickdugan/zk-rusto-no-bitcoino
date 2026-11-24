//! Fixed-shape Nova settlement fold, pilot only. No Bitcoin spend authorization.
//! Reuses M18's Pallas field, Poseidon parameters and range gadget.
use ff::Field;
use m18_utxo_window::{cost::G, elem::{f_from_le, f_to_le, fu, hash, F}};
use nova_snark::frontend::gadgets::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;
use sha2::{Digest,Sha256};

pub const DEPTH: usize = 8; // pilot: 256 indexed claims
pub const CAP: u64 = 1 << DEPTH;
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
pub const NZ: usize = 11;
pub const LEAF: u64 = 1001;
pub const NODE: u64 = 1002;
pub const PAY: u64 = 1003;
pub const START: u64 = 1004;
pub const EMPTY: u64 = 1005;
// z: scope limbs, claims root, context digest limbs, payout count, initial
// net budget, processed count, next allowed claim index, remaining, payout hash.
pub type State = [F; NZ];

#[derive(Clone,Debug)]
pub struct Claim {
    pub index: u64,
    pub script_sha256: [u8;32],
    pub amount: u64,
    pub siblings: [F;DEPTH],
}
impl Default for Claim {
    fn default()->Self {Self{index:0,script_sha256:[0;32],amount:1,siblings:[F::ZERO;DEPTH]}}
}
#[derive(Clone,Debug,Default)]
pub struct SettlementStep {pub claim: Claim}

pub fn limbs(bytes: &[u8;32])->[F;2] {
    // Two independent 128-bit little-endian integers, bytes as written.
    [f_from_le(&bytes[..16]),f_from_le(&bytes[16..])]
}
pub fn state_bytes(z:&[F])->Vec<u8> {z.iter().flat_map(f_to_le).collect()}
pub fn u64_field(x:F)->Option<u64>{
    let b=f_to_le(&x);
    if b[8..].iter().any(|&v|v!=0){None}else{Some(u64::from_le_bytes(b[..8].try_into().unwrap()))}
}
pub fn leaf(scope:[F;2],c:&Claim)->F{
    let s=limbs(&c.script_sha256);
    hash(&[fu(LEAF),scope[0],scope[1],fu(c.index),s[0],s[1],fu(c.amount)])
}
pub fn node(a:F,b:F)->F{hash(&[fu(NODE),a,b])}
pub fn root(scope:[F;2],c:&Claim)->F{
    let mut t=leaf(scope,c);
    for (i,s) in c.siblings.iter().enumerate(){
        t=if (c.index>>i)&1==0{node(t,*s)}else{node(*s,t)}
    }
    t
}
pub fn append(acc:F,c:&Claim)->F{
    let s=limbs(&c.script_sha256);
    hash(&[fu(PAY),acc,fu(c.index),s[0],s[1],fu(c.amount)])
}
pub fn initial(scope:[u8;32],claims_root:F,context:[u8;32],count:u64,budget:u64)->Result<State,&'static str>{
    if count==0||count>CAP||budget>MAX_MONEY{return Err("invalid batch limits")}
    let s=limbs(&scope);let c=limbs(&context);
    Ok([s[0],s[1],claims_root,c[0],c[1],fu(count),fu(budget),F::ZERO,F::ZERO,fu(budget),
        hash(&[fu(START),s[0],s[1]])])
}
pub fn native(z:&State,c:&Claim)->Result<State,&'static str>{
    let get=|i:usize|u64_field(z[i]).ok_or("noncanonical integer state");
    let (count,budget,done,next,remaining)=(get(5)?,get(6)?,get(7)?,get(8)?,get(9)?);
    if count>CAP||done>=count||budget>MAX_MONEY||remaining>budget||
       c.index>=CAP||c.index<next||c.amount==0||c.amount>remaining{return Err("range/accounting/order")}
    if root([z[0],z[1]],c)!=z[2]{return Err("claim membership")}
    let mut o=*z;o[7]=fu(done+1);o[8]=fu(c.index+1);o[9]=fu(remaining-c.amount);o[10]=append(z[10],c);
    Ok(o)
}
/// A verifier must reconstruct z0 from its authenticated policy and transaction
/// context. This checks the final boundary, not the proof itself.
pub fn check_final(z0:&State,zn:&[F],expected_payout:F,expected_change:u64,steps:usize)->bool{
    zn.len()==NZ&&zn[..7]==z0[..7]&&z0[7]==F::ZERO&&z0[8]==F::ZERO&&z0[9]==z0[6]&&
    z0[10]==hash(&[fu(START),z0[0],z0[1]])&&
    u64_field(z0[5])==Some(steps as u64)&&steps>0&&steps<=CAP as usize&&
    zn[7]==z0[5]&&u64_field(zn[8]).is_some_and(|i|i>0&&i<=CAP)&&
    expected_change<=MAX_MONEY&&zn[9]==fu(expected_change)&&zn[10]==expected_payout
}
type N=AllocatedNum<F>;
type LC=LinearCombination<F>;
fn v(x:&N)->F{x.get_value().unwrap_or(F::ZERO)}
fn lc(x:&N)->LC{LC::zero()+x.get_variable()}
fn cst<CS:ConstraintSystem<F>>(x:u64)->LC{LC::zero()+(fu(x),CS::one())}
fn eq<CS:ConstraintSystem<F>>(g:&mut G<'_,CS>,name:String,a:LC,b:LC){
    g.cs.enforce(||name,|l|l+&a,|l|l+CS::one(),|l|l+&b);
}
fn constant<CS:ConstraintSystem<F>>(g:&mut G<'_,CS>,name:&str,x:u64)->N{
    let a=g.alloc(fu(x));eq(g,name.into(),lc(&a),cst::<CS>(x));a
}
fn diff_range<CS:ConstraintSystem<F>>(g:&mut G<'_,CS>,name:&str,x:F,expr:LC,n:usize)->N{
    let a=g.alloc(x);eq(g,name.into(),lc(&a),expr);g.range(&a,n);a
}
impl StepCircuit<F> for SettlementStep{
    fn arity(&self)->usize{NZ}
    fn synthesize<CS:ConstraintSystem<F>>(&self,cs:&mut CS,z:&[N])->Result<Vec<N>,SynthesisError>{
        let mut g=G::new(cs);
        for i in [0,1,3,4]{g.range(&z[i],128);}
        for i in [5,7,8]{g.range(&z[i],DEPTH+1);}
        for i in [6,9]{g.range(&z[i],51);}
        diff_range(&mut g,"count_cap",fu(CAP)-v(&z[5]),cst::<CS>(CAP)-&lc(&z[5]),DEPTH+1);
        diff_range(&mut g,"budget_cap",fu(MAX_MONEY)-v(&z[6]),cst::<CS>(MAX_MONEY)-&lc(&z[6]),51);
        diff_range(&mut g,"remaining_budget",v(&z[6])-v(&z[9]),lc(&z[6])-&lc(&z[9]),51);
        diff_range(&mut g,"step_available",v(&z[5])-v(&z[7])-F::ONE,lc(&z[5])-&lc(&z[7])-CS::one(),DEPTH);
        let idx=g.alloc(fu(self.claim.index));let bits=g.range(&idx,DEPTH);
        diff_range(&mut g,"strict_order",v(&idx)-v(&z[8]),lc(&idx)-&lc(&z[8]),DEPTH);
        let amount=g.alloc(fu(self.claim.amount));g.range(&amount,51);
        diff_range(&mut g,"positive_amount",v(&amount)-F::ONE,lc(&amount)-CS::one(),51);
        let rem=diff_range(&mut g,"debit",v(&z[9])-v(&amount),lc(&z[9])-&lc(&amount),51);
        let s=limbs(&self.claim.script_sha256);let sl=g.alloc(s[0]);let sh=g.alloc(s[1]);g.range(&sl,128);g.range(&sh,128);
        let lt=constant(&mut g,"leaf_domain",LEAF);let nt=constant(&mut g,"node_domain",NODE);
        let pt=constant(&mut g,"payout_domain",PAY);
        let mut cur=g.hash(&[lt,z[0].clone(),z[1].clone(),idx.clone(),sl.clone(),sh.clone(),amount.clone()]);
        for (i,bit) in bits.iter().enumerate(){
            let sib=g.alloc(self.claim.siblings[i]);
            let delta=g.alloc(if bit.get_value().unwrap_or(false){v(&sib)-v(&cur)}else{F::ZERO});
            let dv=delta.get_variable();let bv=bit.get_variable();let sv=sib.get_variable();let cv=cur.get_variable();
            g.cs.enforce(||format!("choose_{i}"),|l|l+bv,|l|l+sv-cv,|l|l+dv);
            let left=g.alloc(v(&cur)+v(&delta));let right=g.alloc(v(&sib)-v(&delta));
            eq(&mut g,format!("left_{i}"),lc(&left),lc(&cur)+&lc(&delta));
            eq(&mut g,format!("right_{i}"),lc(&right),lc(&sib)-&lc(&delta));
            cur=g.hash(&[nt.clone(),left,right]);
        }
        eq(&mut g,"membership".into(),lc(&cur),lc(&z[2]));
        let done=g.alloc(v(&z[7])+F::ONE);eq(&mut g,"advance_count".into(),lc(&done),lc(&z[7])+CS::one());
        let next=g.alloc(v(&idx)+F::ONE);eq(&mut g,"advance_index".into(),lc(&next),lc(&idx)+CS::one());
        let acc=g.hash(&[pt,z[10].clone(),idx,sl,sh,amount]);
        let mut out=z.to_vec();out[7]=done;out[8]=next;out[9]=rem;out[10]=acc;Ok(out)
    }
}
pub fn fixture()->(State,Vec<Claim>,F,u64){
    let scope:[u8;32]=Sha256::digest(b"TEST ONLY scope").into();
    let mut claims=vec![
        Claim{index:3,amount:1200,script_sha256:Sha256::digest(b"test script A").into(),..Default::default()},
        Claim{index:17,amount:800,script_sha256:Sha256::digest(b"test script B").into(),..Default::default()},
        Claim{index:245,amount:500,script_sha256:Sha256::digest(b"test script C").into(),..Default::default()}];
    let empty=hash(&[fu(EMPTY)]);let mut layers=vec![vec![empty;CAP as usize]];
    for c in &claims{layers[0][c.index as usize]=leaf(limbs(&scope),c);}
    for i in 0..DEPTH{layers.push(layers[i].chunks_exact(2).map(|p|node(p[0],p[1])).collect());}
    for c in &mut claims{for i in 0..DEPTH{c.siblings[i]=layers[i][((c.index as usize)>>i)^1];}}
    let rt=layers[DEPTH][0];let ctx:[u8;32]=Sha256::digest(b"TEST ONLY context").into();
    let z=initial(scope,rt,ctx,claims.len() as u64,3000).unwrap();
    let mut end=z;for c in &claims{end=native(&end,c).unwrap();}
    (z,claims,end[10],500)
}
pub fn synth(z:&State,w:&Claim)->(usize,bool,Vec<F>){
    use nova_snark::frontend::util_cs::test_cs::TestConstraintSystem;
    let mut cs=TestConstraintSystem::<F>::new();
    let zi=z.iter().enumerate().map(|(i,x)|AllocatedNum::alloc_infallible(cs.namespace(||format!("z{i}")),||*x)).collect::<Vec<_>>();
    let out=SettlementStep{claim:w.clone()}.synthesize(&mut cs,&zi).unwrap();
    (cs.num_constraints(),cs.is_satisfied(),out.iter().map(|x|v(x)).collect())
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn positive_and_boundary(){
        let (z,claims,expected,change)=fixture();let mut cur=z;let mut n=0;
        for c in &claims{
            let want=native(&cur,c).unwrap();let (nc,ok,got)=synth(&cur,c);
            if n==0{n=nc;}assert_eq!(n,nc);assert!(ok);assert_eq!(got,want);cur=want;
        }
        assert!(check_final(&z,&cur,expected,change,claims.len()));
        assert!(!check_final(&z,&cur,expected+F::ONE,change,claims.len()));
        assert!(!check_final(&z,&cur,expected,change+1,claims.len()));
        assert!(!check_final(&z,&cur,expected,change,claims.len()-1));
        let mut wrong=cur;wrong[3]+=F::ONE;assert!(!check_final(&z,&wrong,expected,change,claims.len()));
        println!("pilot_step_constraints={n}");
    }
    #[test]fn adversarial_constraints(){
        let (z,claims,_,_)=fixture();let c=&claims[0];let n=synth(&z,c).0;
        let reject=|s:&State,w:&Claim|{let(nc,ok,_)=synth(s,w);assert_eq!(nc,n);assert!(!ok);};
        let mut w=c.clone();w.amount+=1;reject(&z,&w);
        let mut w=c.clone();w.script_sha256[0]^=1;reject(&z,&w);
        let mut w=c.clone();w.siblings[0]+=F::ONE;reject(&z,&w);
        let mut w=c.clone();w.index+=1;reject(&z,&w);
        let mut w=c.clone();w.index=CAP;reject(&z,&w);
        let mut s=z;s[0]+=F::ONE;reject(&s,c);
        let mut s=z;s[2]+=F::ONE;reject(&s,c);
        let mut s=z;s[5]=F::ZERO;reject(&s,c);
        let mut s=z;s[9]=fu(c.amount-1);reject(&s,c);
        let mut s=z;s[9]=z[6]+F::ONE;reject(&s,c);
        let mut s=z;s[6]=fu(MAX_MONEY+1);reject(&s,c);
        let mut s=z;s[9]=-F::ONE;reject(&s,c);
        let mut s=z;s[7]=s[5];reject(&s,c);
        let s=native(&z,c).unwrap();reject(&s,c);
        let s=native(&s,&claims[1]).unwrap();reject(&s,c);
        let mut s=z;s[2]=root([s[0],s[1]],&Claim{amount:0,..c.clone()});
        reject(&s,&Claim{amount:0,..c.clone()});
    }
}
