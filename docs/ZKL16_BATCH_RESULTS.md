# ZKL-16: verified paired affine Nova batch

Evidence: hosted CPU job [45575163808/139071180804](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45575163808/job/139071180804), completed successfully. Measured circuit source 26223c2775affe6d44eaa10e2c56acc2bdf1ae70. Pinned public DataGoblin source e7394fced457c059f20ef54128dbc80b0cc747a5. The same eight source proofs also pass Lean 4.19.0 with explicit hypotheses and no axioms: [kernel replay](https://github.com/MoralityLabAI/DataGoblin/actions/runs/45575521759/job/139072378667).

| arm | cases | rows | raw step constraints | fold seconds | compression prove seconds | compressed verify seconds |
|---|---:|---:|---:|---:|---:|---:|
| optimal A* | 4/4 | 25 | 272025 | 4.723023213 | 34.079525245 | 0.753328774 |
| weighted tree shared | 4/4 | 28 | 304668 | 5.382018750 | 34.014940578 | 0.754498111 |

Actual Nova 0.76.0, Spartan/IPA; rule depth 5, memory depth 6, maximum arity 2. Raw constraints per step 10881; augmented constraints primary/secondary 22257/10349. Public parameter setup 3.931160454 s, shared compression setup 0.207939748 s. Each serialized compressed proof 11032 bytes; shared serialized VK 26908088 bytes. Process elapsed 92.64 s, peak RSS 258164 KiB. Eight verified proofs after deserialization, five malformed transports and eight forged constraint assignments rejected. Wrong step count and three wrong initial-state components rejected per compressed proof.

Retained artifact ID 15004546056, name zkl-affine-batch-evidence. ZIP SHA-256 9e23e7b20e91c1519bfeeaf271840e3c3feeaffb6837aad9bb0d6bb9039b3e46. Receipt SHA-256 31c9d31253221d02745035bf57fcadbab77814d5af4d22abd52336d24c748642. Transport SHA-256 2d305d145514b39111e2eb06570f91c4bf3d5a0c8ca66afbb9a1d366ae50fce3. VK SHA-256 c8993930e77537fa58399e39060e63fe50bde0494162ad56b4dc66365fc18a9a. The adjacent JSON is the parsed job-log receipt, not a byte-for-byte copy of the retained pretty-printed artifact. Download the CI artifact for exact proof and receipt bytes.

EvalMath's pinned scorer (2a7fd3c0263d6b65937d3157c46c583e03357203) ran locally against the downloaded official artifact and checked all proof/VK hashes, receipt and transport digests, case identities and costs. Both arms have coverage one; equal-root efficiency is 1 versus 25/28. This measures fixed-shape raw step work (10.714% reduction), not total Nova constraints or total proving time. The 0.659 s lower aggregate folding time is exploratory, with one timed execution per proof. Compression dominated the measured work and proof sizes were identical. Four public diagnostic roots do not establish a model advantage.

The affine circuit verifies conditional derivations under normalized public hypotheses. Source Lean replay and the native compiler are separate trust boundaries. No general Lean kernel, private witness guarantee, BitVM3 settlement or production security claim. No paid GPU use.
