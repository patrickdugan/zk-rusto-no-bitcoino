//! SP1 6.9.0's Poseidon2 over KoalaBear as a circuit: width 16, S-box x^3, 8 external and 20
//! internal rounds, and the padding-free overwrite sponge (rate 8, 8 outputs) SP1 hashes a proof's
//! public values with (`sp1_primitives::poseidon2_hasher`). The final verifier needs it for one
//! check: the wrap proof's public values must hash to the digest the wrap AIR constrains.
//!
//! The permutation is `slop_koala_bear::my_kb_16_perm`:
//! - external linear layer: circ(2 M4, M4, M4, M4) with M4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]];
//! - internal linear layer: p3-koala-bear 0.4.3-succinct's `DiffusionMatrixKoalaBear`. It works on
//!   Montgomery representatives and ends in one Montgomery reduction, so on canonical values it is
//!   y_i = 2^-32 (sum(x) + d_i x_i) with d = (-2, 1, 2, 4, ..., 2^13, 2^15);
//! - round constants: `slop_koala_bear::RC16` (rows 0..4 and 24..28 for the external rounds, the
//!   first element of rows 4..24 for the internal rounds).
//!
//! Inputs must be canonical. Constant inputs fold: a block of constants costs no gates.
use garbled_snark_verifier::CircuitContext;

use crate::field::{self as f, Fe, P, addp, powp, subp};

pub const WIDTH: usize = 16;
pub const RATE: usize = 8;
pub const OUT: usize = 8;

/// 2^-32 mod p, the factor one Montgomery reduction leaves on the internal linear layer.
pub const MONTY_INVERSE: u32 = powp(powp(2, 32), P as u64 - 2);

/// d_1..d_15 as powers of two (d_0 = -2).
const INTERNAL_SHIFTS: [u32; WIDTH - 1] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15];

fn add<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> Fe {
    match (a.as_constant(), b.as_constant()) {
        (Some(x), Some(y)) => Fe::constant(addp(x, y)),
        _ => f::add(c, a, b),
    }
}

fn double<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    match a.as_constant() {
        Some(x) => Fe::constant(addp(x, x)),
        None => f::double(c, a),
    }
}

fn sub<C: CircuitContext>(c: &mut C, a: &Fe, b: &Fe) -> Fe {
    match (a.as_constant(), b.as_constant()) {
        (Some(x), Some(y)) => Fe::constant(subp(x, y)),
        _ => f::sub(c, a, b),
    }
}

fn cube<C: CircuitContext>(c: &mut C, a: &Fe) -> Fe {
    let sq = f::square(c, a);
    f::mul(c, &sq, a)
}

/// p3-poseidon2's `apply_mat4`.
fn mat4<C: CircuitContext>(c: &mut C, x: &mut [Fe]) {
    let t01 = add(c, &x[0], &x[1]);
    let t23 = add(c, &x[2], &x[3]);
    let t0123 = add(c, &t01, &t23);
    let t01123 = add(c, &t0123, &x[1]);
    let t01233 = add(c, &t0123, &x[3]);
    let d0 = double(c, &x[0]);
    let d2 = double(c, &x[2]);
    x[3] = add(c, &t01233, &d0);
    x[1] = add(c, &t01123, &d2);
    x[0] = add(c, &t01123, &t01);
    x[2] = add(c, &t01233, &t23);
}

/// `Poseidon2ExternalMatrixGeneral` at width 16.
fn external_linear<C: CircuitContext>(c: &mut C, s: &mut [Fe; WIDTH]) {
    for block in s.chunks_mut(4) {
        mat4(c, block);
    }
    let sums: Vec<Fe> = (0..4)
        .map(|k| {
            let mut acc = s[k].clone();
            for j in (4..WIDTH).step_by(4) {
                acc = add(c, &acc, &s[j + k]);
            }
            acc
        })
        .collect();
    for i in 0..WIDTH {
        s[i] = add(c, &s[i], &sums[i % 4]);
    }
}

/// `DiffusionMatrixKoalaBear` on canonical values.
fn internal_linear<C: CircuitContext>(c: &mut C, s: &mut [Fe; WIDTH]) {
    let mut sum = s[0].clone();
    for x in &s[1..] {
        sum = add(c, &sum, x);
    }
    for i in 0..WIDTH {
        // Factors 2 go through `double`: the small-constant multiplier builds, for 2, a gate that
        // execution counts and the garbler does not emit.
        let t = match i {
            0 => {
                let twice = double(c, &s[0]);
                sub(c, &sum, &twice)
            }
            1 => add(c, &sum, &s[1]),
            2 => {
                let twice = double(c, &s[2]);
                add(c, &sum, &twice)
            }
            _ => {
                let scaled = f::mul_const(c, &s[i], 1 << INTERNAL_SHIFTS[i - 1]);
                add(c, &sum, &scaled)
            }
        };
        s[i] = f::mul_const(c, &t, MONTY_INVERSE);
    }
}

fn external_round<C: CircuitContext>(c: &mut C, s: &mut [Fe; WIDTH], rc: &[u32; WIDTH]) {
    for i in 0..WIDTH {
        let t = add(c, &s[i], &Fe::constant(rc[i]));
        s[i] = cube(c, &t);
    }
    external_linear(c, s);
}

/// The permutation, in place.
pub fn permute<C: CircuitContext>(c: &mut C, s: &mut [Fe; WIDTH]) {
    external_linear(c, s);
    for rc in &EXTERNAL_INITIAL {
        external_round(c, s, rc);
    }
    for &rc in &INTERNAL {
        let t = add(c, &s[0], &Fe::constant(rc));
        s[0] = cube(c, &t);
        internal_linear(c, s);
    }
    for rc in &EXTERNAL_FINAL {
        external_round(c, s, rc);
    }
}

/// `PaddingFreeSponge<_, 16, 8, 8>::hash_iter`: from the zero state, each chunk of up to 8 inputs
/// overwrites the first elements of the state, then the state is permuted; the first 8 elements
/// are the digest.
pub fn hash<C: CircuitContext>(c: &mut C, input: &[Fe]) -> [Fe; OUT] {
    let mut state: [Fe; WIDTH] = std::array::from_fn(|_| Fe::zero());
    for chunk in input.chunks(RATE) {
        for (s, x) in state.iter_mut().zip(chunk) {
            *s = x.clone();
        }
        permute(c, &mut state);
    }
    std::array::from_fn(|i| state[i].clone())
}

/// Round constants of the first four external rounds (`KoalaBear_BEGIN_EXT_CONSTS`).
pub const EXTERNAL_INITIAL: [[u32; WIDTH]; 4] = [
    [
        0x7ee56a48, 0x11367045, 0x12e41941, 0x7ebbc12b, 0x1970b7d5, 0x662b60e8, 0x3e4990c6, 0x679f91f5,
        0x350813bb, 0x00874ad4, 0x28a0081a, 0x18fa5872, 0x5f25b071, 0x5e5d5998, 0x5e6fd3e7, 0x5b2e2660,
    ],
    [
        0x6f1837bf, 0x3fe6182b, 0x1edd7ac5, 0x57470d00, 0x43d486d5, 0x1982c70f, 0x0ea53af9, 0x61d6165b,
        0x51639c00, 0x2dec352c, 0x2950e531, 0x2d2cb947, 0x08256cef, 0x1a0109f6, 0x1f51faf3, 0x5cef1c62,
    ],
    [
        0x3d65e50e, 0x33d91626, 0x133d5a1e, 0x0ff49b0d, 0x38900cd1, 0x2c22cc3f, 0x28852bb2, 0x06c65a02,
        0x7b2cf7bc, 0x68016e1a, 0x15e16bc0, 0x5248149a, 0x6dd212a0, 0x18d6830a, 0x5001be82, 0x64dac34e,
    ],
    [
        0x5902b287, 0x426583a0, 0x0c921632, 0x3fe028a5, 0x245f8e49, 0x43bb297e, 0x7873dbd9, 0x3cc987df,
        0x286bb4ce, 0x640a8dcd, 0x512a8e36, 0x03a4cf55, 0x481837a2, 0x03d6da84, 0x73726ac7, 0x760e7fdf,
    ],
];

/// Round constants of the 20 internal rounds, added to element 0 (`KoalaBear_PARTIAL_CONSTS`).
pub const INTERNAL: [u32; 20] = [
    0x54dfeb5d, 0x7d40afd6, 0x722cb316, 0x106a4573, 0x45a7ccdb,
    0x44061375, 0x154077a5, 0x45744faa, 0x4eb5e5ee, 0x3794e83f,
    0x47c7093c, 0x5694903c, 0x69cb6299, 0x373df84c, 0x46a0df58,
    0x46b8758a, 0x3241ebcb, 0x0b09d233, 0x1af42357, 0x1e66cec2,
];

/// Round constants of the last four external rounds (`KoalaBear_END_EXT_CONSTS`).
pub const EXTERNAL_FINAL: [[u32; WIDTH]; 4] = [
    [
        0x43e7dc24, 0x259a5d61, 0x27e85a3b, 0x1b9133fa, 0x343e5628, 0x485cd4c2, 0x16e269f5, 0x165b60c6,
        0x25f683d9, 0x124f81f9, 0x174331f9, 0x77344dc5, 0x5a821dba, 0x5fc4177f, 0x54153bf5, 0x5e3f1194,
    ],
    [
        0x3bdbf191, 0x088c84a3, 0x68256c9b, 0x3c90bbc6, 0x6846166a, 0x03f4238d, 0x463335fb, 0x5e3d3551,
        0x6e59ae6f, 0x32d06cc0, 0x596293f3, 0x6c87edb2, 0x08fc60b5, 0x34bcca80, 0x24f007f3, 0x62731c6f,
    ],
    [
        0x1e1db6c6, 0x0ca409bb, 0x585c1e78, 0x56e94edc, 0x16d22734, 0x18e11467, 0x7b2c3730, 0x770075e4,
        0x35d1b18c, 0x22be3db5, 0x4fb1fbb7, 0x477cb3ed, 0x7d5311c6, 0x5b62ae7d, 0x559c5fa8, 0x77f15048,
    ],
    [
        0x3211570b, 0x490fef6a, 0x77ec311f, 0x2247171b, 0x4e0ac711, 0x2edf69c9, 0x3b5a8850, 0x65809421,
        0x5619b4aa, 0x362019a7, 0x6bf9d4ed, 0x5b413dff, 0x617e181e, 0x5e7ab57b, 0x33ad7833, 0x3466c7ca,
    ],
];
