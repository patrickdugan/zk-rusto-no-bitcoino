# Measured corpus results

## Proof denominators and acceptance

| Dataset | Proof cohort | Identified proofs | Native | Eligible native | Strict | Eligible within capacity |
|---|---:|---:|---:|---:|---:|---:|
| owned | 6,213 | 6,213 | 50 | 50 | 48 | 40 |
| solved | 511 | 511 | 0 | 0 | 0 | 0 |

Coverage uses the measured proof cohort. Declaration counts for unbuilt and unselected source files remain unknown.

| Combined measure | Fraction | Percent |
|---|---:|---:|
| native_certificate_accepted | 50/6724 | 0.743605% |
| eligible_native_accepted | 50/6724 | 0.743605% |
| strict_whole_declaration_accepted | 48/6724 | 0.713861% |
| eligible_current_arithmetic_capacity | 40/6724 | 0.594884% |

## Remaining blockers

Labels overlap and count each identified proof once.

| Feature | Proof declarations |
|---|---:|
| definition_unavailable | 6,571 |
| unknown_constant | 6,571 |
| unsupported_inductive | 6,086 |
| unsupported_constructor | 5,825 |
| unsupported_recursor | 4,916 |
| projection | 4,553 |
| symbolic_universe | 952 |
| nat_literal_limit | 733 |
| axiom | 321 |
| resource_limit | 240 |
| primitive_signature_mismatch | 222 |
| unsupported_universe_instance | 222 |
| quotient | 209 |
| propositional_extensionality | 110 |
| string_literal | 67 |
| unsupported_literal | 67 |
| function_extensionality | 44 |

## Source families

| Family | Identified proofs | Eligible native | Strict |
|---|---:|---:|---:|
| owned/MoralityLabAI/BPD | 175 | 0 | 0 |
| owned/MoralityLabAI/Compactification-Theory | 16 | 1 | 1 |
| owned/MoralityLabAI/EvalMath | 288 | 6 | 6 |
| owned/MoralityLabAI/HybridTRMLDT | 48 | 0 | 0 |
| owned/MoralityLabAI/LoopedTransformers | 1,057 | 31 | 29 |
| owned/patrickdugan/BitAgent | 62 | 0 | 0 |
| owned/patrickdugan/MathCan | 2,065 | 2 | 2 |
| owned/patrickdugan/TradeLayer-Rust | 1,122 | 0 | 0 |
| owned/patrickdugan/UTXO-Ref | 644 | 0 | 0 |
| owned/patrickdugan/beyond-bayes | 99 | 8 | 8 |
| owned/patrickdugan/bitcoin-rs | 264 | 0 | 0 |
| owned/patrickdugan/btc-verified | 114 | 0 | 0 |
| owned/patrickdugan/cryptanalytic-discovery-lab | 8 | 0 | 0 |
| owned/patrickdugan/leanp2p | 120 | 0 | 0 |
| owned/patrickdugan/neoplatonic-lean | 131 | 2 | 2 |
| solved-conjectures/fan-tringali-power-monoid-lengths | 350 | 0 | 0 |
| solved-conjectures/feldheim-weighted-tail | 161 | 0 | 0 |

## Transitive axioms

| Axiom | Identified proof declarations |
|---|---:|
| propext | 2,844 |
| Quot.sound | 2,227 |
| Classical.choice | 558 |
| UTXORefAxioms.sha256_binding | 4 |
| UTXORefAxioms.signatures_unforgeable | 2 |

## Duplicate proof and goal pairs

| Fingerprint | Declarations | Unique pairs | Duplicate groups | Duplicate excess |
|---|---:|---:|---:|---:|
| raw_receipt_pairs | 6,724 | 6,638 | 43 | 86 |
| exact_expr_pairs | 6,724 | 6,638 | 43 | 86 |
| lowered_fixed_kernel_pairs | 50 | 45 | 4 | 5 |

Fingerprint definitions and every duplicate member are recorded in JSON. The declaration denominator remains unchanged.

## Accepted native certificates

| Declaration | Source | Rows | Eligible | Strict | Within capacity |
|---|---|---:|---|---|---|
| `fc11_native_prop` | [MoralityLabAI/Compactification-Theory/research/refutation_bench/fc11/native_first_smoke.lean](https://github.com/MoralityLabAI/Compactification-Theory/blob/218526faec6334a65f0046b800ed26d6edd3a3a7/research/refutation_bench/fc11/native_first_smoke.lean) | 33 | True | True | True |
| `thm_bpd2_exact_d1_r0_pos` | [MoralityLabAI/EvalMath/fixtures/bpd_lean_curriculum_v2/test_positives.lean](https://github.com/MoralityLabAI/EvalMath/blob/958b3fc797cdc8fda927eff153d056b5e65be861/fixtures/bpd_lean_curriculum_v2/test_positives.lean) | 372 | True | True | True |
| `thm_bpd2_exact_d1_r1_pos` | [MoralityLabAI/EvalMath/fixtures/bpd_lean_curriculum_v2/dev_positives.lean](https://github.com/MoralityLabAI/EvalMath/blob/958b3fc797cdc8fda927eff153d056b5e65be861/fixtures/bpd_lean_curriculum_v2/dev_positives.lean) | 1034 | True | True | False |
| `thm_bpd2_exact_d2_r0_pos` | [MoralityLabAI/EvalMath/fixtures/bpd_lean_curriculum_v2/train_positives.lean](https://github.com/MoralityLabAI/EvalMath/blob/958b3fc797cdc8fda927eff153d056b5e65be861/fixtures/bpd_lean_curriculum_v2/train_positives.lean) | 549 | True | True | True |
| `thm_bpd2_exact_d2_r1_pos` | [MoralityLabAI/EvalMath/fixtures/bpd_lean_curriculum_v2/train_positives.lean](https://github.com/MoralityLabAI/EvalMath/blob/958b3fc797cdc8fda927eff153d056b5e65be861/fixtures/bpd_lean_curriculum_v2/train_positives.lean) | 1621 | True | True | False |
| `thm_bpd2_exact_d3_r0_pos` | [MoralityLabAI/EvalMath/fixtures/bpd_lean_curriculum_v2/test_positives.lean](https://github.com/MoralityLabAI/EvalMath/blob/958b3fc797cdc8fda927eff153d056b5e65be861/fixtures/bpd_lean_curriculum_v2/test_positives.lean) | 758 | True | True | True |
| `thm_bpd2_exact_d3_r1_pos` | [MoralityLabAI/EvalMath/fixtures/bpd_lean_curriculum_v2/train_positives.lean](https://github.com/MoralityLabAI/EvalMath/blob/958b3fc797cdc8fda927eff153d056b5e65be861/fixtures/bpd_lean_curriculum_v2/train_positives.lean) | 2332 | True | True | False |
| `RAM06ExactCurriculum.exact_dev_forward` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 106 | True | True | True |
| `RAM06ExactCurriculum.exact_dev_two_arguments` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 220 | True | True | True |
| `RAM06ExactCurriculum.exact_train_implication` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 105 | True | True | True |
| `RAM06ExactCurriculum.exact_train_implication_reverse` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 106 | True | True | True |
| `RAM06ExactCurriculum.exact_train_nat_equality` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 122 | True | True | True |
| `RAM06ExactCurriculum.exact_train_prop` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 33 | True | True | True |
| `RAM06ExactCurriculum.exact_train_prop_two` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 48 | True | True | True |
| `RAM06ExactCurriculum.exact_train_two_arguments` | [MoralityLabAI/LoopedTransformers/experiments/lean_ram06/ExactCurriculum.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/experiments/lean_ram06/ExactCurriculum.lean) | 214 | True | True | True |
| `LBF17AbstractInterp.subset_refl` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/lean/LBF17AbstractInterp.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/lean/LBF17AbstractInterp.lean) | 347 | True | False | True |
| `LBF17AbstractInterp.subset_trans` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/lean/LBF17AbstractInterp.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/lean/LBF17AbstractInterp.lean) | 1353 | True | False | False |
| `LBF12Cert.cf_12._proof_1` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean) | 893 | True | True | True |
| `LBF12Cert.cf_13._proof_6` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean) | 656 | True | True | True |
| `LBF12Cert.cf_16._proof_2` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean) | 761 | True | True | True |
| `LBF12Cert.cf_20._proof_4` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/counterfactuals/Proofs.lean) | 656 | True | True | True |
| `LBF12Cert.train_train_001_506860d0ab2e._proof_2` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 761 | True | True | True |
| `LBF12Cert.train_train_001_506860d0ab2e._proof_8` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 656 | True | True | True |
| `LBF12Cert.train_train_003_3657dbf57e27._proof_4` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 884 | True | True | True |
| `LBF12Cert.train_train_005_7b027be9f01d._proof_7` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 883 | True | True | True |
| `LBF12Cert.train_train_011_fc12c6dc9651._proof_5` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 657 | True | True | True |
| `LBF12Cert.train_train_015_6e2070475693._proof_6` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 761 | True | True | True |
| `LBF12Cert.train_train_017_a5bb4f9a461d._proof_6` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 881 | True | True | True |
| `LBF12Cert.train_train_023_d369a34d9e47._proof_4` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 886 | True | True | True |
| `LBF12Cert.train_train_031_283706a99e06._proof_4` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 764 | True | True | True |
| `LBF12Cert.train_train_033_b2200c08abad._proof_10` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 776 | True | True | True |
| `LBF12Cert.train_train_033_b2200c08abad._proof_4` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 663 | True | True | True |
| `LBF12Cert.train_train_035_12186cde8e30._proof_8` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 771 | True | True | True |
| `LBF12Cert.train_train_049_2748215170cf._proof_5` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 893 | True | True | True |
| `LBF12Cert.train_train_057_46045570a142._proof_10` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 729 | True | True | True |
| `LBF12Cert.train_train_057_46045570a142._proof_2` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 778 | True | True | True |
| `LBF12Cert.train_train_059_a6a36bbf7cf7._proof_7` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 769 | True | True | True |
| `LBF12Cert.train_train_063_94c37bd8b9f6._proof_3` | [MoralityLabAI/LoopedTransformers/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean](https://github.com/MoralityLabAI/LoopedTransformers/blob/b14a51015996f0dee81ef033e2e198d9f84951b2/research/lite_braille_fresco/results/lbf18/train_teacher_certificates/references/Proofs.lean) | 879 | True | True | True |
| `MathCan.PeriodOne.one_step_fixed_point_unique` | [patrickdugan/MathCan/MathCan/PeriodOne.lean](https://github.com/patrickdugan/MathCan/blob/b3eb33ed10485264fe7a593e3b0ace418d9f9a6d/MathCan/PeriodOne.lean) | 1054 | True | True | False |
| `MathCan.RHGaloisRowInputs.galois_row_from_geometry_and_theta_lift` | [patrickdugan/MathCan/MathCan/RHGaloisRowInputs.lean](https://github.com/patrickdugan/MathCan/blob/b3eb33ed10485264fe7a593e3b0ace418d9f9a6d/MathCan/RHGaloisRowInputs.lean) | 542 | True | True | True |
| `ACE.Campaign.honest_single_successor` | [patrickdugan/beyond-bayes/lean/ACE/Campaign.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/Campaign.lean) | 1410 | True | True | False |
| `ACE.Campaign.only_one_action_after_consume` | [patrickdugan/beyond-bayes/lean/ACE/Campaign.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/Campaign.lean) | 503 | True | True | True |
| `ACE.RootOrdering.one_start_per_reservation` | [patrickdugan/beyond-bayes/lean/ACE/RootOrdering.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/RootOrdering.lean) | 802 | True | True | True |
| `ACE.Scope.parent_grant_single_successor` | [patrickdugan/beyond-bayes/lean/ACE/Scope.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/Scope.lean) | 1410 | True | True | False |
| `ACE.common_honest_anchor_rejects_fork` | [patrickdugan/beyond-bayes/lean/ACE/AnchorQuorum.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/AnchorQuorum.lean) | 1410 | True | True | False |
| `ACE.quorum_acknowledgment_cannot_be_omitted` | [patrickdugan/beyond-bayes/lean/ACE/WitnessQuorum.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/WitnessQuorum.lean) | 1531 | True | True | False |
| `ACE.recovery_uses_certified_sequence` | [patrickdugan/beyond-bayes/lean/ACE/AnchorQuorum.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/AnchorQuorum.lean) | 156 | True | True | True |
| `ACE.shared_honest_signer_rules_out_split_view` | [patrickdugan/beyond-bayes/lean/ACE/WitnessQuorum.lean](https://github.com/patrickdugan/beyond-bayes/blob/abc89f73d223f00305eb0416a34fe5aee602494d/lean/ACE/WitnessQuorum.lean) | 1423 | True | True | False |
| `Unveiling.simpleProvabilityModel._proof_1` | [patrickdugan/neoplatonic-lean/Unveiling.lean](https://github.com/patrickdugan/neoplatonic-lean/blob/0f6d3e470ca0f132729a32895ce7a5b04418b008/Unveiling.lean) | 213 | True | True | True |
| `Unveiling.simpleProvabilityModel._proof_2` | [patrickdugan/neoplatonic-lean/Unveiling.lean](https://github.com/patrickdugan/neoplatonic-lean/blob/0f6d3e470ca0f132729a32895ce7a5b04418b008/Unveiling.lean) | 246 | True | True | True |

Original goal/proof hashes, certificate file hashes, target line hashes and source pins accompany each accepted declaration in JSON.
