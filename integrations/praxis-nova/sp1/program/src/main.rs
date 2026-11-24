//! SP1 guest PREPARATION: authenticate a pinned Nova key and verify a folded
//! payout list against PNS1. This guest does not verify a Bitcoin transaction,
//! header proof, UTXO proof or liabilities registry. No settlement authorization.
#![no_main]
sp1_zkvm::entrypoint!(main);
use bincode::Options;
use ff::{Field,PrimeField};
use generic_array::typenum::U5;
use nova_snark::{
    frontend::{num::AllocatedNum,ConstraintSystem,SynthesisError},
    frontend::gadgets::poseidon::{IOPattern,Simplex,Sponge,SpongeAPI,SpongeOp,SpongeTrait,Strength},
    nova::{CompressedSNARK,VerifierKey},
    provider::{PallasEngine,VestaEngine,ipa_pc},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit,Engine},
};
use sha2::{Digest,Sha256};
type E1=PallasEngine;type E2=VestaEngine;
type F=<E1 as Engine>::Scalar;
type S1=RelaxedR1CSSNARK<E1,ipa_pc::EvaluationEngine<E1>>;
type S2=RelaxedR1CSSNARK<E2,ipa_pc::EvaluationEngine<E2>>;
const NZ:usize=11;
const CAP:u64=256;
const MAX_MONEY:u64=2_100_000_000_000_000;
const JOURNAL_BYTES:usize=440;
const MAX_KEY:usize=256*1024*1024;
const MAX_PROOF:usize=8*1024*1024;
#[derive(Clone,Debug)]
struct Arity11;
impl StepCircuit<F> for Arity11{
    fn arity(&self)->usize{NZ}
    fn synthesize<CS:ConstraintSystem<F>>(&self,_:&mut CS,_:&[AllocatedNum<F>])->Result<Vec<AllocatedNum<F>>,SynthesisError>{
        panic!("verification-only circuit marker");
    }
}
type VK=VerifierKey<E1,E2,Arity11,S1,S2>;
type Proof=CompressedSNARK<E1,E2,Arity11,S1,S2>;
fn pin()->[u8;32]{
    let s=include_str!("../nova-vk.sha256").trim().as_bytes();
    assert_eq!(s.len(),64,"Nova VK pin not provisioned");
    let n=|c:u8|match c{b'0'..=b'9'=>c-b'0',b'a'..=b'f'=>c-b'a'+10,_=>panic!("pin hex")};
    let p=core::array::from_fn(|i|n(s[2*i])<<4|n(s[2*i+1]));
    assert_ne!(p,[0;32]);p
}
fn fe(b:&[u8])->F{
    let mut repr=<F as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(b);
    Option::<F>::from(F::from_repr(repr)).expect("canonical field")
}
fn u64f(x:&F)->u64{
    let r=x.to_repr();let b=r.as_ref();assert!(b[8..].iter().all(|&v|v==0));
    u64::from_le_bytes(b[..8].try_into().unwrap())
}
fn limb(x:&F){
    let r=x.to_repr();assert!(r.as_ref()[16..].iter().all(|&b|b==0));
}
fn initial_acc(a:F,b:F)->F{
    let constants=Sponge::<F,U5>::api_constants(Strength::Standard);
    let mut sponge=Sponge::new_with_constants(&constants,Simplex);
    let acc=&mut ();
    sponge.start(IOPattern(vec![SpongeOp::Absorb(3),SpongeOp::Squeeze(1)]),None,acc);
    SpongeAPI::absorb(&mut sponge,3,&[F::from(1004),a,b],acc);
    let out=SpongeAPI::squeeze(&mut sponge,1,acc);sponge.finish(acc).unwrap();out[0]
}
fn sha(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn main(){
    // Stop before reading proof inputs if no compile-time key has been registered.
    let vkpin=pin();
    let journal=sp1_zkvm::io::read_vec();
    assert_eq!(journal.len(),JOURNAL_BYTES);assert_eq!(&journal[..4],b"PNS1");
    let steps=u32::from_le_bytes(journal[4..8].try_into().unwrap()) as usize;
    assert!(steps>0&&steps<=CAP as usize);
    let z0=journal[8..360].chunks_exact(32).map(fe).collect::<Vec<_>>();
    let expected_payout=fe(&journal[360..392]);
    let change=u64::from_le_bytes(journal[392..400].try_into().unwrap());
    let next=u64::from_le_bytes(journal[400..408].try_into().unwrap());
    assert_eq!(&journal[408..440],vkpin.as_slice());
    assert!(next>0&&next<=CAP&&change<=MAX_MONEY);
    for i in [0,1,3,4]{limb(&z0[i]);}
    assert_eq!(u64f(&z0[5]),steps as u64);
    let budget=u64f(&z0[6]);assert!(budget<=MAX_MONEY&&change<=budget);
    assert_eq!(z0[7],F::ZERO);assert_eq!(z0[8],F::ZERO);
    assert_eq!(z0[9],z0[6]);assert_eq!(z0[10],initial_acc(z0[0],z0[1]));
    let kb=sp1_zkvm::io::read_vec();assert!(kb.len()<=MAX_KEY);
    assert_eq!(sha(&kb),vkpin,"Nova verifier-key pin");
    let vk:VK=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_KEY as u64).deserialize(&kb).expect("pinned key");
    let pb=sp1_zkvm::io::read_vec();assert!(pb.len()<=MAX_PROOF);
    let proof:Proof=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes()
        .with_limit(MAX_PROOF as u64).deserialize(&pb).expect("proof");
    let zn=proof.verify(&vk,steps,&z0).expect("Nova verification");
    assert_eq!(zn.len(),NZ);assert_eq!(&zn[..7],&z0[..7]);
    assert_eq!(zn[7],z0[5]);assert_eq!(zn[8],F::from(next));
    assert_eq!(zn[9],F::from(change));assert_eq!(zn[10],expected_payout);
    // Journal is the exact public value bytes, not bincode of the Vec.
    sp1_zkvm::io::commit_slice(&journal);
}
