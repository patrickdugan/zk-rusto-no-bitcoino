//! Mirror structs that deserialize/serialize byte-for-byte like nova-snark 0.76.0's private types,
//! used to split vk and proof bytes into named regions.
use halo2curves::pasta::{Fp, Fq, PallasAffine, VestaAffine};
use nova_snark::nova::nifs::{NIFSRelaxed, NIFS};
use nova_snark::provider::pedersen::Commitment;
use nova_snark::provider::poseidon::PoseidonConstantsCircuit;
use nova_snark::provider::traits::DlogGroup;
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::r1cs::{R1CSInstance, RelaxedR1CSInstance};
use nova_snark::spartan::sumcheck::SumcheckProof;
use nova_snark::traits::Engine;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Ck<A> {
    pub ck: Vec<A>,
    pub h: A,
}

#[derive(Serialize, Deserialize)]
pub struct IpaVk<A> {
    pub ck_v: Ck<A>,
    pub ck_s: Ck<A>,
}

#[derive(Serialize, Deserialize)]
pub struct SparkComm {
    pub n: u64,
    pub comm_row: [u8; 32],
    pub comm_col: [u8; 32],
    pub comm_val_a: [u8; 32],
    pub comm_val_b: [u8; 32],
    pub comm_val_c: [u8; 32],
    pub comm_ts_row: [u8; 32],
    pub comm_ts_col: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct PpVk<A> {
    pub num_cons: u64,
    pub num_vars: u64,
    pub vk_ee: IpaVk<A>,
    pub s_comm: SparkComm,
}

#[derive(Serialize, Deserialize)]
pub struct Vk {
    pub f_arity: u64,
    pub ro_consts_primary: PoseidonConstantsCircuit<Fp>,
    pub ro_consts_secondary: PoseidonConstantsCircuit<Fq>,
    pub pp_digest: Fq,
    pub vk_primary: PpVk<PallasAffine>,
    pub vk_secondary: PpVk<VestaAffine>,
    pub dk_primary: [u8; 32],
    pub dk_secondary: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct IpaArg<E: Engine>
where
    E::GE: DlogGroup,
{
    pub l_vec: Vec<Commitment<E>>,
    pub r_vec: Vec<Commitment<E>>,
    pub a_hat: E::Scalar,
}

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PpSnark<E: Engine>
where
    E::GE: DlogGroup,
{
    pub comm_l_row: Commitment<E>,
    pub comm_l_col: Commitment<E>,
    pub comm_t_plus_r_inv_row: Commitment<E>,
    pub comm_w_plus_r_inv_row: Commitment<E>,
    pub comm_t_plus_r_inv_col: Commitment<E>,
    pub comm_w_plus_r_inv_col: Commitment<E>,
    pub sc_outer: SumcheckProof<E>,
    pub eval_az_at_r_outer: E::Scalar,
    pub eval_bz_at_r_outer: E::Scalar,
    pub eval_cz_at_r_outer: E::Scalar,
    pub eval_e_at_r_outer: E::Scalar,
    pub sc_inner_batched: SumcheckProof<E>,
    pub eval_e: E::Scalar,
    pub eval_l_row: E::Scalar,
    pub eval_l_col: E::Scalar,
    pub eval_val_a: E::Scalar,
    pub eval_val_b: E::Scalar,
    pub eval_val_c: E::Scalar,
    pub eval_w: E::Scalar,
    pub eval_t_plus_r_inv_row: E::Scalar,
    pub eval_row: E::Scalar,
    pub eval_w_plus_r_inv_row: E::Scalar,
    pub eval_ts_row: E::Scalar,
    pub eval_t_plus_r_inv_col: E::Scalar,
    pub eval_col: E::Scalar,
    pub eval_w_plus_r_inv_col: E::Scalar,
    pub eval_ts_col: E::Scalar,
    pub eval_arg: IpaArg<E>,
}

#[derive(Serialize, Deserialize)]
pub struct ProofMirror {
    pub r_u_secondary: RelaxedR1CSInstance<VestaEngine>,
    pub ri_secondary: Fp,
    pub l_u_secondary: R1CSInstance<VestaEngine>,
    pub nifs_uf_secondary: NIFS<VestaEngine>,
    pub l_ur_secondary: RelaxedR1CSInstance<VestaEngine>,
    pub nifs_un_secondary: NIFSRelaxed<VestaEngine>,
    pub r_u_primary: RelaxedR1CSInstance<PallasEngine>,
    pub ri_primary: Fq,
    pub l_ur_primary: RelaxedR1CSInstance<PallasEngine>,
    pub nifs_un_primary: NIFSRelaxed<PallasEngine>,
    pub wit_blind_r_wn_primary: Fq,
    pub err_blind_r_wn_primary: Fq,
    pub wit_blind_r_wn_secondary: Fp,
    pub err_blind_r_wn_secondary: Fp,
    pub snark_primary: PpSnark<PallasEngine>,
    pub snark_secondary: PpSnark<VestaEngine>,
    pub zn: Vec<Fq>,
}

pub fn size<T: Serialize>(t: &T) -> usize {
    bincode::serialized_size(t).unwrap() as usize
}

/// (name, offset, length) for the regions of a proof; nested regions use dotted names.
pub fn proof_layout(p: &ProofMirror) -> Vec<(String, usize, usize)> {
    let mut v = Vec::new();
    let mut off = 0usize;
    macro_rules! top {
        ($n:expr, $f:expr) => {{
            let l = size(&$f);
            v.push(($n.to_string(), off, l));
            off += l;
            l
        }};
    }
    top!("r_U_secondary", p.r_u_secondary);
    top!("ri_secondary", p.ri_secondary);
    top!("l_u_secondary", p.l_u_secondary);
    top!("nifs_Uf_secondary", p.nifs_uf_secondary);
    top!("l_ur_secondary", p.l_ur_secondary);
    top!("nifs_Un_secondary", p.nifs_un_secondary);
    top!("r_U_primary", p.r_u_primary);
    top!("ri_primary", p.ri_primary);
    top!("l_ur_primary", p.l_ur_primary);
    top!("nifs_Un_primary", p.nifs_un_primary);
    top!("wit_blind_r_Wn_primary", p.wit_blind_r_wn_primary);
    top!("err_blind_r_Wn_primary", p.err_blind_r_wn_primary);
    top!("wit_blind_r_Wn_secondary", p.wit_blind_r_wn_secondary);
    top!("err_blind_r_Wn_secondary", p.err_blind_r_wn_secondary);
    macro_rules! snark {
        ($pre:expr, $s:expr) => {{
            let s = &$s;
            let base = off;
            let mut o = off;
            macro_rules! f {
                ($n:expr, $f:expr) => {{
                    let l = size(&$f);
                    v.push((format!("{}.{}", $pre, $n), o, l));
                    o += l;
                }};
            }
            f!("comm_L_row", s.comm_l_row);
            f!("comm_L_col", s.comm_l_col);
            f!("comm_t_plus_r_inv_row", s.comm_t_plus_r_inv_row);
            f!("comm_w_plus_r_inv_row", s.comm_w_plus_r_inv_row);
            f!("comm_t_plus_r_inv_col", s.comm_t_plus_r_inv_col);
            f!("comm_w_plus_r_inv_col", s.comm_w_plus_r_inv_col);
            f!("sc_outer", s.sc_outer);
            f!("eval_Az_at_r_outer", s.eval_az_at_r_outer);
            f!("eval_Bz_at_r_outer", s.eval_bz_at_r_outer);
            f!("eval_Cz_at_r_outer", s.eval_cz_at_r_outer);
            f!("eval_E_at_r_outer", s.eval_e_at_r_outer);
            f!("sc_inner_batched", s.sc_inner_batched);
            f!("eval_E", s.eval_e);
            f!("eval_L_row", s.eval_l_row);
            f!("eval_L_col", s.eval_l_col);
            f!("eval_val_A", s.eval_val_a);
            f!("eval_val_B", s.eval_val_b);
            f!("eval_val_C", s.eval_val_c);
            f!("eval_W", s.eval_w);
            f!("eval_t_plus_r_inv_row", s.eval_t_plus_r_inv_row);
            f!("eval_row", s.eval_row);
            f!("eval_w_plus_r_inv_row", s.eval_w_plus_r_inv_row);
            f!("eval_ts_row", s.eval_ts_row);
            f!("eval_t_plus_r_inv_col", s.eval_t_plus_r_inv_col);
            f!("eval_col", s.eval_col);
            f!("eval_w_plus_r_inv_col", s.eval_w_plus_r_inv_col);
            f!("eval_ts_col", s.eval_ts_col);
            f!("eval_arg.L_vec", s.eval_arg.l_vec);
            f!("eval_arg.R_vec", s.eval_arg.r_vec);
            f!("eval_arg.a_hat", s.eval_arg.a_hat);
            let total = o - base;
            assert_eq!(total, size(s));
            v.push(($pre.to_string(), base, total));
            off = o;
        }};
    }
    snark!("snark_primary", p.snark_primary);
    snark!("snark_secondary", p.snark_secondary);
    top!("zn", p.zn);
    assert_eq!(off, size(p), "the regions cover the whole proof");
    v
}
