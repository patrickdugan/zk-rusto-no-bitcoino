# Measurement report: Nova soldering and authenticated local disputes

## Scope and provenance

Current protocol: `RBZK-BABE-NOVA-PILOT-AUTHENTICATED-V2`, results schema `2`.

The original preregistration, `RBZK-BABE-NOVA-PILOT-2026-11`, was committed at `23bd390`. The implementation and report reviewed at `991118c8f1cadcc0ae4fa96303bbf65e4f75e00c` are the historical version-one experiment. Subsequent hardening changes the dispute statement, setup API, and Bitcoin label-selection rule. [SPECIFICATION.md](SPECIFICATION.md) defines the corrected relation; [PREREGISTRATION.md](PREREGISTRATION.md) retains the initial predictions and records a later addendum.

The hardened baseline CPU run in [RESULTS.json](RESULTS.json) identifies source commit `7977c344d620be9199f5699f5344a328e80d51f7` and a 14-file source manifest with SHA-256 `4a31ce04b21c7c24354ca498d4da45df35cf2198184b4f2e73a0018e287ba91a`. The optimized build used Rust 1.90.0 on Linux x86_64 with `RAYON_NUM_THREADS=2`; the host reported nine available logical CPUs. GPU use was false. Seeds were deterministic test fixtures, unsuitable for funded sessions.

Timings describe one recorded run. Variance and deployment throughput remain unmeasured. Serialized bytes and gate counts apply to the fixed claims and source manifest in that run. The security claims depend on the relation and protocol assumptions.

## Audit corrections

| Reviewed issue | Corrected evidence boundary |
| --- | --- |
| Arithmetic auxiliaries could be changed by a challenger; authentication failure could yield a refutation | The operator commits the full tuple, including quotient and coordinate data. Refutation requires a matching full SHA-256 opening and an invalid committed transition. |
| The prechallenge commitment was obtained from the submitted finalized bundle | Verification compares the bundle with an independently supplied `expected_commit1`. Callers establish its pre-nonce provenance. |
| Retained evaluation accepted unverified setup objects | Evaluation uses an immutable capability produced by complete setup verification. |
| Session reuse could expose labels across conflicting challenges | The baseline has in-memory guards. The integration increment adds a fsynced journal, an independent CAS authority and exact artifact recovery; see INTEGRATION.md. |
| The Bitcoin witness selected either hashlock for a wire | Each constructed assertion leaf embeds the hashlock selected by the caller's independently agreed input bit. |
| Serialized transaction fixtures were described as Core-valid and standard | Size and witness-shape checks describe those fixtures. The integration increment records funded Core execution and policy decisions in a separate receipt. |
| Small local gadget counts were compared with complete verifiers as speedups | Each relation is identified by its coverage. A common full-verifier experiment remains open. |

## Historical version-one data

The [original results at the reviewed commit](https://github.com/patrickdugan/zk-rusto-no-bitcoino/blob/991118c8f1cadcc0ae4fa96303bbf65e4f75e00c/integrations/bitvm3-nova/babe-pilot/RESULTS.json) preserve the first experiment's artifact sizes and timings. Its local circuits used the superseded authentication relation. The measurements below were regenerated after that relation changed.

The runs used different execution environments, so their timing differences do not establish a speedup. This report carries no retained-artifact or production sizing claim derived from the old gate counts. The earlier full-scale runtime forecasts, claimed reductions against M14/FC03/Groth16, and assertions of Bitcoin Core standardness have been withdrawn.

## Hardened local circuit measurements

| Measured relation | Input bits | Non-free gates | Ciphertext bytes | Garble seconds | Evaluate seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| Indexed Mersenne-31 opening with complete SHA-256 authentication | 128 | 44,566 | 713,056 | 0.010051 | 0.007683 |
| One Pallas addition opening with complete authentication, canonical encodings and on-curve endpoints | 3,832 | 2,738,804 | 43,820,864 | 0.517068 | 0.439637 |

For both rows, `ExecuteMode` gate counts equal the measured garbling ciphertext counts. Each ciphertext is 16 bytes. The benchmark's constant claim commitments affect constant folding, so reproduction must retain the fixed claim specification. The Pallas row checks one step with the fixed generator `(-1,2)`; the full seven-instance soldering run below uses the 128-bit indexed relation.

## Local setup, certificate and evaluation

The run generated `N=7` instances, opened four seeds and retained `M=3` instances. The soldering circuit processes two wires per Nova step, giving 64 steps for the 128-wire input.

| Artifact or count | Measured value | Scope |
| --- | ---: | --- |
| Generated ciphertext bytes | 4,991,392 | All seven instances |
| Generated ciphertexts, headers and hashlocks | 5,050,992 bytes | The generator's counted setup components |
| Retained ciphertext bytes | 2,139,168 | Three instances |
| Opened seed payload | 160 bytes | Four seeds and their serialized indices |
| Base SHA-256 hashlock table | 8,192 bytes | Both label hashes for each of 128 wires |
| Soldering translation payload | 4,128 bytes | Two target instances |
| Nova compressed certificate | 11,688 bytes | Serialized `CompressedSNARK` |
| Reusable verifier key | 52,884,552 bytes | The measured Nova circuit shape |
| Finalized public setup | 2,165,704 bytes | Exact serialized session bundle |
| Active base labels | 2,048 raw bytes; 2,128 serialized bytes | One selected label per base wire |
| Public setup and verifier key | 55,050,256 bytes | Excludes the separately serialized active-label delivery |
| Artifact directory total | 55,052,384 bytes | Public setup, verifier key and active-label delivery |
| Nova primary / secondary constraints | 122,856 / 10,349 | Counts returned by the selected public parameters |
| Peak resident memory | 465,320 KiB, or 454.414 MiB | Process high-water mark for this run |

Three independent selected-label vectors would contain 6,144 raw bytes. The soldered delivery uses 2,048 raw bytes while adding the certificate and translation artifacts reported above. This payload accounting covers label delivery within the measured local experiment.

| Measured operation | Seconds |
| --- | ---: |
| Generate all seven garblings and roots | 0.285608 |
| Nova public-parameter setup | 8.788378 |
| Compressed-proof key setup | 0.408527 |
| Recursive folding, 64 steps | 26.771975 |
| Compression proving | 28.740675 |
| Certificate verification | 0.637004 |
| Challenger verification of the complete public setup | 0.814666 |
| Evaluation of all three retained instances | 0.022497 |

Folding and compression total 55.512650 seconds for this fixture. Key setup has its own rows because it can be reused for this circuit shape. This measurement supplies no estimate for a full application proving job or a production-size soldering configuration.

## Bitcoin serialization evidence

The following values come from constructed transactions with fixture outpoints and dummy signatures. Every corresponding record in `RESULTS.json` has `consensus_verified:false` and `standardness_verified:false`.

| Constructed fixture | Inputs | Virtual bytes | Weight units |
| --- | ---: | ---: | ---: |
| Selected-label assertion, 128 wires | 1 | 1,801 | 7,203 |
| Withholding CSV branch | 1 | 137 | 548 |
| Refutation branch, three retained instances | 1 | 158 | 629 |
| Operator CSV branch, three retained instances | 1 | 145 | 580 |
| Selected-label assertion, 3,832 wires chunked at 480 | 8 | 50,540 | 202,158 |
| Refutation branch, 39-instance tree at depth six | 1 | 190 | 757 |
| Operator branch, 39-instance tree at depth six | 1 | 177 | 708 |

The 128-wire assertion uses a 4,514-byte script and 129 initial stack items. The chunked Pallas fixture has at most 481 initial stack items per input, a maximum initial item size of 64 bytes, and 134,392 total script bytes. Its configured stack and weight checks pass. These checks describe the serialized fixture's bounds.

Separate tests check the exact selected-hash script template, Taproot commitments, and a native BIP341 sighash with a real Schnorr signature. The funded integration records separate Core Script execution and policy results for its real transactions. Its pre-funding graph reservation, post-confirmation release and exact CSV boundary tests are described in INTEGRATION.md. They preserve the serialization-only scope of the baseline samples above.

## Security parameters and comparison scope

The runnable configuration uses `N=7`, `M=3`. Under one ideal uniform selection and a fixed set of three malicious instances, the probability that all bad instances are retained while all opened instances pass is `1/35`. The corresponding arithmetic factor for `N=115`, `M=39` is approximately `2^-102.585`; complete protocol security also depends on the assumptions in the specification.

M14 verifies a full wrapped proof. FC03 investigates authenticated local verifier checks with its own relation and trace requirements. Babylon's BABE paper measures its specified verifier and protocol. The Pallas gadget here checks one fixed-generator addition opening. These artifacts answer different measurement questions. A replacement decision needs the complete common statement, every required local check, setup and retained artifacts, proof cost, challenge data, and the enforceable Bitcoin transaction path.

## Integration increment

[INTEGRATION.md](INTEGRATION.md) describes the complete Boolean trace compiler, its real Nova certificate test, durable session recovery and funded indexed transaction graph. The optional M14 adapter calls the existing complete final verifier with independently pinned proof, key and public statement. Its current bounded test refuses partial compilation at an explicit resource cap. A complete M14 publication and scalable funded selection across its entire check schedule remain the next measurement boundary.

Application custody also requires the concrete DLC/CET and successor-UTXO mapping, a deployed independent authority, reorganization behavior and a production cut-and-choose parameter choice. The new regtest evidence does not supply a full application proving-time estimate.
