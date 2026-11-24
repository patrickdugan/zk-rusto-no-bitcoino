//! Read only locally generated, pinned Nova 0.76 compressed VK fixtures.
//! Bincode layout mirrors private fields. No production/untrusted VK parser.
use nova_snark::{
    provider::{PallasEngine,VestaEngine,pedersen::{CommitmentEngine,CommitmentKey,DerandKey},
        traits::DlogGroupExt},
    r1cs::R1CSShape,traits::{Engine,ROConstants},
};
use serde::{Serialize,Deserialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};

#[derive(Serialize,Deserialize)]
#[serde(bound="")]
struct IpaKey<E:Engine<CE=CommitmentEngine<E>>> where E::GE:DlogGroupExt {
    ck_v:CommitmentKey<E>,ck_s:CommitmentKey<E>,
}
#[derive(Serialize,Deserialize)]
#[serde(bound="")]
struct SpartanKey<E:Engine<CE=CommitmentEngine<E>>> where E::GE:DlogGroupExt {
    vk_ee:IpaKey<E>,shape:R1CSShape<E>,
}
#[derive(Serialize,Deserialize)]
struct NovaKey {
    arity:usize,
    ro_primary:ROConstants<PallasEngine>,
    ro_secondary:ROConstants<VestaEngine>,
    pp_digest:<PallasEngine as Engine>::Scalar,
    primary:SpartanKey<PallasEngine>,
    secondary:SpartanKey<VestaEngine>,
    dk_primary:DerandKey<PallasEngine>,
    dk_secondary:DerandKey<VestaEngine>,
    // The native C phantom serializes as unit, zero bytes under bincode.
    phantom:(),
}
fn side<E:Engine<CE=CommitmentEngine<E>>>(k:&SpartanKey<E>,unpad_cons:usize,unpad_vars:usize)->Value
where E::GE:DlogGroupExt {
    let cons=k.shape.num_cons();let vars=k.shape.num_vars();
    assert!(cons.is_power_of_two()&&vars.is_power_of_two());
    assert!(cons>=unpad_cons&&vars>=unpad_vars);
    let n=cons.max(vars);
    let keylen=k.vk_ee.ck_v.generators().len();
    assert!(keylen>=n&&k.vk_ee.ck_s.generators().len()==1);
    let ell=n.ilog2() as usize;
    json!({"unaugmented_label":"augmented Nova R1CS, before Spartan padding",
        "unpad_constraints":unpad_cons,"unpad_variables":unpad_vars,
        "padded_constraints":cons,"padded_variables":vars,"public_io":k.shape.num_io(),
        "ipa_domain":n,"ipa_rounds":ell,"commitment_key_generators":keylen,
        "ipa_fixed_bases":n+1,"ipa_variable_bases":2*ell,
        "outer_sumcheck_rounds":cons.ilog2(),"inner_sumcheck_rounds":vars.ilog2()+1,
        "matrix_nonzeros":{"a":k.shape.A().iter().count(),"b":k.shape.B().iter().count(),"c":k.shape.C().iter().count()}})
}
pub fn inventory(raw:&[u8],arity:usize,cons:(usize,usize),vars:(usize,usize))->Value {
    let k:NovaKey=bincode::deserialize(raw).expect("pinned Nova key layout");
    assert_eq!(bincode::serialize(&k).unwrap(),raw,"layout roundtrip");
    assert_eq!(k.arity,arity);
    json!({"vk_sha256":hex::encode(Sha256::digest(raw)),"arity":arity,
        "primary":side(&k.primary,cons.0,vars.0),"secondary":side(&k.secondary,cons.1,vars.1),
        "scope":"locally generated 0.76 fixture; key layout roundtrip; IPA opening domain derived from padded shape"})
}
