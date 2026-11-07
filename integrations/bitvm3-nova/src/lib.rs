//! Conformance harness for the Boolean Pasta kernels. No bridge transactions.
#[cfg(test)]
mod tests {
    use garbled_snark_verifier::{
        AesCcrGateHasher, Blake3AccumulatingHash, CircuitContext, EvaluatedWire, GarbledWire, GateHasher, S, WireId,
        circuit::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, ExecuteMode,
            GarbleMode, EvaluateMode, CiphertextHandler, CiphertextSource, FileSource, StreamingResult},
        nova::{self, PastaField, Word},
    };
    use num_bigint::BigUint;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaChaRng;
    use std::io::{BufWriter, Write};

    const CAPACITY: usize = 32768; // allocator reservation, NOT an enforced RAM cap
    fn modulus(f: PastaField) -> BigUint {
        BigUint::from_bytes_le(&f.modulus_le().iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<_>>())
    }
    fn bits(a: &BigUint, b: &BigUint, z: &BigUint) -> [bool; 768] {
        std::array::from_fn(|i| [a, b, z][i / 256].bit((i % 256) as u64))
    }
    fn circuit<C: CircuitContext>(ctx: &mut C, f: PastaField, multiply: bool, wires: &[WireId; 768]) -> WireId {
        let a: Word = wires[..256].try_into().unwrap();
        let b: Word = wires[256..512].try_into().unwrap();
        let z: Word = wires[512..].try_into().unwrap();
        if multiply { nova::check_mul(ctx, f, &a, &b, &z) } else { nova::check_add(ctx, f, &a, &b, &z) }
    }
    fn execute(f: PastaField, mul: bool, a: &BigUint, b: &BigUint, z: &BigUint) -> bool {
        let r: StreamingResult<ExecuteMode, _, bool> = CircuitBuilder::streaming_execute(
            bits(a, b, z), CAPACITY, |ctx, wires| circuit(ctx, f, mul, wires));
        r.output_value
    }
    #[test]
    fn canonical_boundaries_and_false_additions() {
        for f in [PastaField::PallasBase, PastaField::VestaBase] {
            let p = modulus(f); let zero = BigUint::from(0u8); let one = BigUint::from(1u8);
            let last = &p - &one;
            for (a, b) in [(&zero, &zero), (&last, &one), (&last, &last), (&one, &one)] {
                let z = (a + b) % &p;
                assert!(execute(f, false, a, b, &z));
                assert!(!execute(f, false, a, b, &((&z + &one) % &p)));
            }
            for invalid in [p.clone(), &p + &one, BigUint::from(1u8) << 255, (BigUint::from(1u8) << 256) - &one] {
                assert!(!execute(f, false, &invalid, &zero, &zero));
                assert!(!execute(f, false, &zero, &invalid, &zero));
                assert!(!execute(f, false, &zero, &zero, &invalid));
            }
        }
    }
    #[test]
    fn randomized_additions_match_biguint() {
        let mut rng = ChaChaRng::seed_from_u64(20261106);
        for f in [PastaField::PallasBase, PastaField::VestaBase] {
            let p = modulus(f);
            for _ in 0..32 {
                let mut bytes = [0u8; 64]; rng.fill_bytes(&mut bytes);
                let a = BigUint::from_bytes_le(&bytes[..32]) % &p;
                let b = BigUint::from_bytes_le(&bytes[32..]) % &p;
                assert!(execute(f, false, &a, &b, &((&a + &b) % &p)));
            }
        }
    }
    #[test]
    fn multiplication_matches_biguint_and_rejects_aliases() {
        for f in [PastaField::PallasBase, PastaField::VestaBase] {
            let p = modulus(f); let one = BigUint::from(1u8); let zero = BigUint::from(0u8);
            for (a,b) in [(zero.clone(), &p - &one), (&p - &one, &p - &one),
                (BigUint::from(123456789u64), BigUint::from(987654321u64))] {
                let z = (&a * &b) % &p;
                assert!(execute(f, true, &a, &b, &z));
                assert!(!execute(f, true, &a, &b, &((&z + &one) % &p)));
            }
            assert!(!execute(f, true, &zero, &p, &zero));
            assert!(!execute(f, true, &p, &zero, &zero));
            assert!(!execute(f, true, &zero, &zero, &p));
        }
    }

    #[test]
    fn randomized_radix4_mul_matches_biguint() {
        let mut rng = ChaChaRng::seed_from_u64(20261106);
        for f in [PastaField::PallasBase, PastaField::VestaBase] {
            let p = modulus(f);
            for _ in 0..24 {
                let mut bytes = [0u8; 64];
                rng.fill_bytes(&mut bytes);
                let a = BigUint::from_bytes_le(&bytes[..32]) % &p;
                let b = BigUint::from_bytes_le(&bytes[32..]) % &p;
                let z = (&a * &b) % &p;
                assert!(execute(f, true, &a, &b, &z));
                assert!(!execute(f, true, &a, &b, &((&z + 1u8) % &p)));
            }
            // Both high nonzero digit and boundary reducers must be exercised.
            let a = &p - 1u8;
            for b in [BigUint::from(1u8) << 254, BigUint::from(1u8) << 253, &p - 1u8, &p - 2u8] {
                let z = (&a * &b) % &p;
                assert!(execute(f, true, &a, &b, &z));
            }
        }
    }

    // Inputs are allocated from the garbler's own delta and RNG.
    struct GarbleInput;
    impl CircuitInput for GarbleInput {
        type WireRepr = [WireId; 768];
        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr { std::array::from_fn(|_| issue()) }
        fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.to_vec() }
    }
    impl<H: GateHasher, T: CiphertextHandler> EncodeInput<GarbleMode<H, T>> for GarbleInput {
        fn encode(&self, w: &Self::WireRepr, mode: &mut GarbleMode<H, T>) {
            for id in w { let value = mode.issue_garbled_wire(); mode.feed_wire(*id, value); }
        }
    }
    struct EvalInput(Vec<EvaluatedWire>);
    impl CircuitInput for EvalInput {
        type WireRepr = [WireId; 768];
        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr { std::array::from_fn(|_| issue()) }
        fn collect_wire_ids(w: &Self::WireRepr) -> Vec<WireId> { w.to_vec() }
    }
    impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvalInput {
        fn encode(&self, w: &Self::WireRepr, mode: &mut M) {
            for (id, value) in w.iter().zip(&self.0) { mode.feed_wire(*id, value.clone()); }
        }
    }
    #[derive(Default)]
    struct Tables(Vec<S>);
    impl CiphertextHandler for Tables {
        type Result = Vec<S>;
        fn handle(&mut self, ct: S) { self.0.push(ct); }
        fn finalize(self) -> Vec<S> { self.0 }
    }
    struct Source(std::vec::IntoIter<S>);
    impl CiphertextSource for Source {
        type Result = ();
        fn recv(&mut self) -> Option<S> { self.0.next() }
        fn finalize(mut self) { assert!(self.0.next().is_none(), "unconsumed ciphertexts"); }
    }
    // Test-only bounded-buffer disk writer. The hash is recomputed while
    // streaming, and compared to FileSource's evaluation-side digest.
    struct DigestFileSink {
        writer: BufWriter<std::fs::File>,
        digest: Blake3AccumulatingHash,
    }
    impl CiphertextHandler for DigestFileSink {
        type Result = [u8; 32];
        fn handle(&mut self, ct: S) {
            self.writer.write_all(&ct.to_bytes()).expect("write ciphertext");
            self.digest.update(ct);
        }
        fn finalize(mut self) -> Self::Result {
            self.writer.flush().expect("flush ciphertext");
            self.digest.finalize()
        }
    }

    #[test]
    fn file_backed_garbling_replays_and_checks_digest() {
        let field = PastaField::PallasBase;
        let seed = 20261106u64; // reproducible tests only
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let hasher = AesCcrGateHasher::from_rng(&mut rng);
        let path = std::env::temp_dir().join(format!(
            "nova-bitvm3-{}-{seed}.ciphertexts", std::process::id()
        ));
        let sink = DigestFileSink {
            writer: BufWriter::with_capacity(
                64 * 1024, std::fs::File::create(&path).expect("create ciphertext stream")
            ),
            digest: Blake3AccumulatingHash::default(),
        };
        let g: StreamingResult<GarbleMode<AesCcrGateHasher, DigestFileSink>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling(GarbleInput, CAPACITY, seed, sink,
                |ctx, wires| circuit(ctx, field, true, wires));
        let bytes = std::fs::metadata(&path).expect("ciphertext metadata").len();
        assert!(bytes > 0 && bytes % 16 == 0);
        let p = modulus(field);
        let a = &p - 1u8;
        let b = BigUint::from(1u8) << 254;
        let z = (&a * &b) % &p;
        let input = EvalInput(
            g.input_wire_values.iter().zip(bits(&a, &b, &z))
                .map(|(w, bit)| EvaluatedWire::new_from_garbled(w, bit))
                .collect()
        );
        let evaluation: StreamingResult<EvaluateMode<AesCcrGateHasher, FileSource>, _, EvaluatedWire> =
            CircuitBuilder::streaming_evaluation(
                input,
                CAPACITY,
                g.true_wire_constant.label1.to_u128(),
                g.false_wire_constant.label0.to_u128(),
                hasher,
                FileSource::from_path(&path).expect("open ciphertext stream"),
                |ctx, wires| circuit(ctx, field, true, wires)
            );
        assert_eq!(evaluation.output_value.active_label, g.output_value.select(true));
        assert_eq!(evaluation.ciphertext_handler_result, g.ciphertext_handler_result);
        eprintln!("radix4_disk_ciphertext_bytes={bytes} digest_consistent=true");
        std::fs::remove_file(&path).expect("remove ciphertext stream");
    }

    #[test]
    fn garble_evaluate_matches_execute() {
        for (f, multiply) in [(PastaField::PallasBase, false), (PastaField::VestaBase, false),
            (PastaField::PallasBase, true), (PastaField::VestaBase, true)] {
            // Fixed seeds are ONLY for reproducible tests, never production garbling.
            let seed = 317u64;
            let mut rng = ChaChaRng::seed_from_u64(seed);
            let hasher = AesCcrGateHasher::from_rng(&mut rng);
            let g: StreamingResult<GarbleMode<AesCcrGateHasher, Tables>, _, GarbledWire> =
                CircuitBuilder::streaming_garbling(GarbleInput, CAPACITY, seed, Tables::default(),
                    |ctx, wires| circuit(ctx, f, multiply, wires));
            eprintln!("Pasta field={f:?} multiply={multiply} gates={} ciphertext_bytes={}", g.gate_count, g.ciphertext_handler_result.len() * 16);
            let p = modulus(f); let a = &p - 1u8;
            let b = if multiply { BigUint::from(0u8) } else { BigUint::from(1u8) };
            for (z, expected) in [(BigUint::from(0u8), true), (BigUint::from(1u8), false), (p.clone(), false)] {
                let bs = bits(&a, &b, &z);
                let input = EvalInput(g.input_wire_values.iter().zip(bs).map(|(w,b)| EvaluatedWire::new_from_garbled(w, b)).collect());
                let e: StreamingResult<EvaluateMode<AesCcrGateHasher, Source>, _, EvaluatedWire> =
                    CircuitBuilder::streaming_evaluation(input, CAPACITY,
                        g.true_wire_constant.label1.to_u128(), g.false_wire_constant.label0.to_u128(),
                        hasher.clone(), Source(g.ciphertext_handler_result.clone().into_iter()),
                        |ctx, wires| circuit(ctx, f, multiply, wires));
                assert_eq!(e.output_value.active_label, g.output_value.select(expected));
            }
        }
    }
}
