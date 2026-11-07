#!/usr/bin/env python3
"""Copy p3-koala-bear 0.4.3-succinct out of the cargo registry and add
operation counters to its scalar arithmetic.

Every field operation SP1's verifier performs reaches KoalaBear's scalar
`Add`, `Sub`, `Mul`, `Sum`, `halve` or `mul_2exp_u64` (negation is
`zero - x`, squaring is `x * x`, the degree-4 extension multiplies
coefficient-wise through these, inversion is an addition chain of squarings
and multiplications). Built without AVX2/AVX-512/NEON, `Field::Packing` is the
scalar type, so packed code paths reduce to the same operations.

A multiplication is counted as `mul_const` when either operand's canonical
value is within 2^8 of 0 or of p (0, 1, -1, the extension's W = 3, small
AIR coefficients); every other one as `mul_full`.

usage: patch_koala_bear.py REGISTRY_SRC_DIR OUT_DIR
  REGISTRY_SRC_DIR: the directory holding p3-koala-bear-0.4.3-succinct/
                    (~/.cargo/registry/src/index.crates.io-*/)
"""
import pathlib
import shutil
import sys

CRATE = 'p3-koala-bear-0.4.3-succinct'

OPCOUNT_RS = '''//! Operation counters added for nova-bitvm3/m13 (not part of Plonky3).
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub static ADD: AtomicU64 = AtomicU64::new(0);
pub static SUB: AtomicU64 = AtomicU64::new(0);
pub static MUL_FULL: AtomicU64 = AtomicU64::new(0);
pub static MUL_CONST: AtomicU64 = AtomicU64::new(0);
pub static SUM_ADDS: AtomicU64 = AtomicU64::new(0);
pub static HALVE: AtomicU64 = AtomicU64::new(0);
pub static MUL_2EXP: AtomicU64 = AtomicU64::new(0);

pub const NAMES: [&str; 7] = ["add", "sub", "mul_full", "mul_const", "sum_adds", "halve", "mul_2exp"];
const ALL: [&AtomicU64; 7] = [&ADD, &SUB, &MUL_FULL, &MUL_CONST, &SUM_ADDS, &HALVE, &MUL_2EXP];
const P: u32 = 0x7f00_0001;
const SMALL: u32 = 1 << 8;

#[inline(always)]
pub fn bump(c: &AtomicU64) {
    c.fetch_add(1, Relaxed);
}

#[inline(always)]
pub fn bump_by(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Relaxed);
}

#[inline(always)]
pub fn count_mul(a: u32, b: u32) {
    let small = |x: u32| x < SMALL || x > P - SMALL;
    if small(a) || small(b) {
        bump(&MUL_CONST)
    } else {
        bump(&MUL_FULL)
    }
}

pub fn snapshot() -> [u64; 7] {
    let mut out = [0u64; 7];
    for (o, c) in out.iter_mut().zip(ALL) {
        *o = c.load(Relaxed);
    }
    out
}

pub fn reset() {
    for c in ALL {
        c.store(0, Relaxed);
    }
}
'''

EDITS = [
    ('src/lib.rs', 'mod poseidon2;\n', 'mod poseidon2;\npub mod opcount;\n'),
    ('src/koala_bear.rs',
     '    fn add(self, rhs: Self) -> Self {\n        let mut sum = self.value + rhs.value;',
     '    fn add(self, rhs: Self) -> Self {\n        crate::opcount::bump(&crate::opcount::ADD);\n        let mut sum = self.value + rhs.value;'),
    ('src/koala_bear.rs',
     '    fn sub(self, rhs: Self) -> Self {\n        let (mut diff, over) = self.value.overflowing_sub(rhs.value);',
     '    fn sub(self, rhs: Self) -> Self {\n        crate::opcount::bump(&crate::opcount::SUB);\n        let (mut diff, over) = self.value.overflowing_sub(rhs.value);'),
    ('src/koala_bear.rs',
     '    fn mul(self, rhs: Self) -> Self {\n        let long_prod = self.value as u64 * rhs.value as u64;',
     '    fn mul(self, rhs: Self) -> Self {\n        crate::opcount::count_mul(from_monty(self.value), from_monty(rhs.value));\n        let long_prod = self.value as u64 * rhs.value as u64;'),
    ('src/koala_bear.rs',
     '        let sum = iter.map(|x| (x.value as u64)).sum::<u64>();',
     '        let mut terms = 0u64;\n        let sum = iter.map(|x| { terms += 1; x.value as u64 }).sum::<u64>();\n        crate::opcount::bump_by(&crate::opcount::SUM_ADDS, terms.saturating_sub(1));'),
    ('src/koala_bear.rs',
     '    fn halve(&self) -> Self {\n        KoalaBear {',
     '    fn halve(&self) -> Self {\n        crate::opcount::bump(&crate::opcount::HALVE);\n        KoalaBear {'),
    ('src/koala_bear.rs',
     '        let product = (self.value as u64) << exp;',
     '        crate::opcount::bump(&crate::opcount::MUL_2EXP);\n        let product = (self.value as u64) << exp;'),
]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src = pathlib.Path(sys.argv[1]) / CRATE
    out = pathlib.Path(sys.argv[2])
    if not (src / 'src' / 'koala_bear.rs').exists():
        print(f'{src} not found; run `cargo fetch` first', file=sys.stderr)
        return 1
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(src, out)
    (out / 'src' / 'opcount.rs').write_text(OPCOUNT_RS, newline='\n')
    for rel, old, new in EDITS:
        p = out / rel
        text = p.read_text()
        n = text.count(old)
        if n != 1:
            print(f'{rel}: expected exactly one match, found {n}:\n{old}', file=sys.stderr)
            return 1
        p.write_text(text.replace(old, new), newline='\n')
    print(f'patched copy at {out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
