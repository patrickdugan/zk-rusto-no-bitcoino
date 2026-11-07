//! KoalaBear operation counts. Real values need the `opcount` feature and the
//! patched p3-koala-bear (`opcount/patch_koala_bear.py`); without them the
//! functions report `None`.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldOps {
    pub add: u64,
    pub sub: u64,
    /// Multiplications with both operands outside the small-constant window.
    pub mul_full: u64,
    /// Multiplications with an operand within 2^8 of 0 or of p.
    pub mul_const: u64,
    /// Additions inside n-ary sums (n - 1 per sum).
    pub sum_adds: u64,
    pub halve: u64,
    pub mul_2exp: u64,
}

#[cfg(feature = "opcount")]
pub fn reset() {
    p3_koala_bear::opcount::reset();
}

#[cfg(feature = "opcount")]
pub fn snapshot() -> Option<FieldOps> {
    let s = p3_koala_bear::opcount::snapshot();
    Some(FieldOps { add: s[0], sub: s[1], mul_full: s[2], mul_const: s[3], sum_adds: s[4], halve: s[5], mul_2exp: s[6] })
}

#[cfg(not(feature = "opcount"))]
pub fn reset() {}

#[cfg(not(feature = "opcount"))]
pub fn snapshot() -> Option<FieldOps> {
    None
}
