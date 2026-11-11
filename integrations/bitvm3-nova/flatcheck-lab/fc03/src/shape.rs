//! Pinned R1CS shapes: canonical digest, fixed-width row records and the matrix commitment.
//!
//! z = W (num_vars, zero-padded) || u || X (num_io), as in Nova 0.76's relaxed R1CS. A row record
//! carries, for each of A, B, C, its non-zero count and exactly K_m (column, coefficient) slots,
//! unused slots all-zero, so one fixed circuit reads any row.
use crate::{
    enc::{self, tag, Enc},
    field::{fe_bytes, fe_from_bytes},
    sha,
};
use ff::PrimeField;
use nova_snark::{
    r1cs::{R1CSShape, SparseMatrix},
    traits::Engine,
};

pub const ROW_DOMAIN: &[u8; 11] = b"FC03/row/v1";

#[derive(Clone, Debug)]
pub struct Shape<F: PrimeField> {
    pub num_cons: usize,
    pub num_vars: usize,
    pub num_io: usize,
    /// rows[m][i]: entries of matrix m (A, B, C) in row i, ascending column.
    pub rows: [Vec<Vec<(u32, F)>>; 3],
}

impl<F: PrimeField> Shape<F> {
    pub fn n_cols(&self) -> usize {
        self.num_vars + 1 + self.num_io
    }

    pub fn from_nova<E: Engine<Scalar = F>>(s: &R1CSShape<E>) -> Self {
        let conv = |m: &SparseMatrix<F>| -> Vec<Vec<(u32, F)>> {
            (0..s.num_cons())
                .map(|r| (m.indptr[r]..m.indptr[r + 1]).map(|k| (m.indices[k] as u32, m.data[k])).collect())
                .collect()
        };
        Shape { num_cons: s.num_cons(), num_vars: s.num_vars(), num_io: s.num_io(), rows: [conv(s.A()), conv(s.B()), conv(s.C())] }
    }

    pub fn to_nova<E: Engine<Scalar = F>>(&self) -> R1CSShape<E> {
        let m = |rows: &Vec<Vec<(u32, F)>>| -> SparseMatrix<F> {
            let t: Vec<(usize, usize, F)> =
                rows.iter().enumerate().flat_map(|(r, es)| es.iter().map(move |&(c, v)| (r, c as usize, v))).collect();
            SparseMatrix::new(&t, self.num_cons, self.n_cols())
        };
        R1CSShape::new(self.num_cons, self.num_vars, self.num_io, m(&self.rows[0]), m(&self.rows[1]), m(&self.rows[2]))
            .expect("valid shape")
    }

    /// Maximum non-zeros per row in A, B, C.
    pub fn k(&self) -> [usize; 3] {
        let f = |m: &Vec<Vec<(u32, F)>>| m.iter().map(|r| r.len()).max().unwrap_or(0).max(1);
        [f(&self.rows[0]), f(&self.rows[1]), f(&self.rows[2])]
    }

    pub fn digest(&self, field_id: u8) -> [u8; 32] {
        let mut e = Enc::new("r1cs-shape");
        e.u8("field", field_id).u32("num_cons", self.num_cons as u32).u32("num_vars", self.num_vars as u32).u32("num_io", self.num_io as u32);
        for (name, m) in ["A", "B", "C"].iter().zip(&self.rows) {
            for (r, es) in m.iter().enumerate() {
                e.u32(&format!("{name}.row"), r as u32).u32("nnz", es.len() as u32);
                for (c, v) in es {
                    e.u32("col", *c).field("coef", &fe_bytes(v));
                }
            }
        }
        e.digest()
    }

    pub fn row_record(&self, field_id: u8, row: usize, k: [usize; 3]) -> Vec<u8> {
        let mut out = Vec::with_capacity(row_record_len(k));
        out.extend_from_slice(ROW_DOMAIN);
        out.push(field_id);
        out.extend_from_slice(&(row as u32).to_be_bytes());
        for m in 0..3 {
            let es = &self.rows[m][row];
            assert!(es.len() <= k[m]);
            out.extend_from_slice(&(es.len() as u32).to_be_bytes());
            for slot in 0..k[m] {
                match es.get(slot) {
                    Some((c, v)) => {
                        out.extend_from_slice(&c.to_be_bytes());
                        out.extend_from_slice(&fe_bytes(v));
                    }
                    None => out.extend_from_slice(&[0u8; 36]),
                }
            }
        }
        out
    }

    pub fn matrix_items(&self, field_id: u8, k: [usize; 3]) -> Vec<[u8; 64]> {
        let items = (0..self.num_cons)
            .map(|r| enc::item(field_id, tag::ROW, r as u32, &sha::sha256(&self.row_record(field_id, r, k))))
            .collect();
        enc::pad_items(field_id, items)
    }

    /// (A z, B z, C z) at one row, z = W || u || X.
    pub fn row_products(&self, row: usize, w: &[F], u: F, x: &[F]) -> [F; 3] {
        let z = |c: usize| -> F {
            if c < self.num_vars {
                w.get(c).copied().unwrap_or(F::ZERO)
            } else if c == self.num_vars {
                u
            } else {
                x[c - self.num_vars - 1]
            }
        };
        let mut out = [F::ZERO; 3];
        for m in 0..3 {
            for &(c, v) in &self.rows[m][row] {
                out[m] += v * z(c as usize);
            }
        }
        out
    }
}

pub fn row_record_len(k: [usize; 3]) -> usize {
    ROW_DOMAIN.len() + 1 + 4 + k.iter().map(|km| 4 + 36 * km).sum::<usize>()
}

#[derive(Clone, Debug, PartialEq)]
pub struct RowRecord<F> {
    pub row: u32,
    pub nnz: [u32; 3],
    /// slots[m][j] = (column, coefficient), unused slots (0, 0).
    pub slots: [Vec<(u32, F)>; 3],
}

/// Strict parse: exact length, domain, field byte, nnz <= K, canonical coefficients, unused slots
/// all-zero, columns in range.
pub fn parse_row_record<F: PrimeField>(b: &[u8], field_id: u8, k: [usize; 3], n_cols: usize) -> Option<RowRecord<F>> {
    if b.len() != row_record_len(k) || &b[..11] != ROW_DOMAIN || b[11] != field_id {
        return None;
    }
    let row = u32::from_be_bytes(b[12..16].try_into().unwrap());
    let mut off = 16;
    let mut nnz = [0u32; 3];
    let mut slots: [Vec<(u32, F)>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for m in 0..3 {
        nnz[m] = u32::from_be_bytes(b[off..off + 4].try_into().unwrap());
        off += 4;
        if nnz[m] as usize > k[m] {
            return None;
        }
        for j in 0..k[m] {
            let c = u32::from_be_bytes(b[off..off + 4].try_into().unwrap());
            let v: F = fe_from_bytes(b[off + 4..off + 36].try_into().unwrap())?;
            if j as u32 >= nnz[m] && (c != 0 || !bool::from(v.is_zero())) {
                return None;
            }
            if c as usize >= n_cols {
                return None;
            }
            slots[m].push((c, v));
            off += 36;
        }
    }
    Some(RowRecord { row, nnz, slots })
}
