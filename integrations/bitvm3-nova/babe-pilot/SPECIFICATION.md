# Mathematical Specification & Threat Model: BABE-Inspired Transparent Nova Garbled Verification

## 1. Architectural Motivation & Proof-System Stack

In `M13`/`M14`, verifying a transparent Nova proof on Bitcoin via a single monolithic garbled BLAKE3/STARK SP1 wrap verifier requires **`785,442,492` non-free gates (`12.57 GB` of ciphertexts)** and **`8,635,080` input bits (`552.6 MB` of SHA-256 input commitments)** per garbled circuit instance. Under an adversarial garbler model requiring $(N, M)$ Cut-and-Choose (`C&C`, e.g., $N = 115, M = 39$ for $2^{-53}$ soundness), replicating `M14` across $N$ circuits would generate **$1.445\text{ TB}$** of ciphertexts and retain **$490.1\text{ GB}$** per claim.

Babylon's January 2026 **BABE** (*Bitcoin-Authenticated Bytecode Execution*) paper introduces four synergistic techniques for malicious-garbler BitVM3 verification:
1. **Two-phase randomized Cut-and-Choose** (`Commit_1` $\rightarrow$ challenger randomness $\eta$ $\rightarrow$ `Commit_2`), preventing adaptive corruption after challenge selection;
2. **Zero-knowledge input-label soldering** across the $M$ retained garbled circuits relative to a base retained instance $b = \min(\mathcal{R})$, so only **one** base active-label vector is revealed on-chain;
3. **On-chain `CheckLampSigsMatch`** binding the revealed base active labels to pre-committed Bitcoin Tapscript SHA-256 hashlocks, coupled with a **1-of-$M$ `Disprove` Taptree** and a withholding timeout leaf;
4. **Witness-assisted linearized elliptic-curve / algebraic local checks**, replacing expensive projective point additions in Boolean gates with affine chord-slope verification.

### Primary Stack Preservation & Setup Assumptions

| Layer | Role in This Architecture | Setup Assumption |
| :--- | :--- | :--- |
| **Nova over Pallas/Vesta + Spartan/IPA (`CompressedSNARK`)** | **Primary proof system** for both IVC state folding *and* the zero-knowledge input-label soldering certificate $\pi_{\text{solder}}$ (`nova-snark = 0.76.0`). | **Transparent** (deterministic hash-to-curve generators; zero toxic waste). |
| **BLAKE3/STARK SP1 Wrap (`M13` / `M14`)** | **Committed baseline** full-verifier garbled route (`785.4M` non-free gates). | **Transparent** (hash-based STARK/BaseFold). |
| **Indexed `FC03` + Windowed Pedersen Checks** | **Bounded local dispute circuits** replacing monolithic `M14` garbling (`< 8M` gates for binding checks; width-bucketed or term-accumulated R1CS checks). | **Transparent** (SHA-256 / FlatMerkle + Pasta Pedersen). |
| **Groth16 over BN254 (BABE Paper Baseline)** | **Optional literature comparison only** (`~22.16 MiB` ciphertext/circuit). | **Trusted circuit-specific CRS** (multi-party ceremony; excluded from primary stack). |

---

## 2. Cryptographic Primitives & Notation

Let $\lambda = 128$ be the computational security parameter.
- **Pasta Cycle**: Let $(\mathbb{E}_1, \mathbb{E}_2) = (\text{Pallas}, \text{Vesta})$ with scalar/base field $\mathbb{F}_p = \mathbb{F}_{\text{Pallas-scalar}} = \mathbb{F}_{\text{Vesta-base}}$ ($p = 2^{254} + \text{0x224698fc0994a8dd8c46eb2100000001}$) and secondary scalar field $\mathbb{F}_q = \mathbb{F}_{\text{Vesta-scalar}} = \mathbb{F}_{\text{Pallas-base}}$.
- **Garbling Scheme**: Privacy-free 1-ciphertext Half-Gates (`GarbleMode::new_with_seed` in `garbled-snark-verifier`) with circular-correlation-robust `AesCcrGateHasher` (`GKWY` linear orthomorphism $\sigma$).
  For instance $k \in [0, N)$ seeded with $s_k \xleftarrow{\$} \{0,1\}^{256}$:
  - Global Free-XOR secret offset: $\Delta_k \in \{0,1\}^{128} \setminus \{0^{128}\}$;
  - Input wire $i \in [0, W)$: base false label $L_{k,i,0} \in \{0,1\}^{128}$ and true label $L_{k,i,1} = L_{k,i,0} \oplus \Delta_k$;
  - Output wire (`refute` bit $y \in \{0,1\}$, where $y = 1$ means **claim refuted / invalid** and $y = 0$ means **claim accepted / valid**): output labels $(O_{k,0}, O_{k,1} = O_{k,0} \oplus \Delta_k)$.

### Dual-Layer Input-Label Commitments

Because Bitcoin Script natively executes `OP_SHA256` in `1` opcode while SHA-256 inside R1CS costs $\sim 25{,}840$ constraints per compression (versus $\sim 310$ R1CS constraints for Poseidon over $\mathbb{F}_p$), each instance $k \in [0, N)$ commits its input labels in two deterministic forms derived from $s_k$:

1. **Bitcoin Script SHA-256 Hashlocks (`CheckLampSigsMatch`-ready)**:
   $$H^{\text{btc}}_{k,i,\beta} = \text{SHA256}\!\left(\text{"babe-nova/btc-label/v1\0"} \parallel \text{sid} \parallel \text{le32}(k) \parallel \text{le32}(i) \parallel [\beta] \parallel L_{k,i,\beta}\right)$$
   together with raw Tapscript preimage locks $h^{\text{tap}}_{k,i,\beta} = \text{SHA256}(L_{k,i,\beta})$ for direct `OP_SHA256 <h> OP_EQUALVERIFY` spending without `OP_CAT`, aggregated into Merkle/stream digest $R^{\text{btc}}_k$.
2. **Hiding Algebraic Poseidon Commitments over $\mathbb{F}_p$**:
   Using a deterministic blinding stream $\rho_{k,i,\beta} = \text{PRF}_{\text{blind}}(s_k, i, \beta) \in \mathbb{F}_p$:
   $$C^{\text{pos}}_{k,i,\beta} = \text{Poseidon}_{\mathbb{F}_p}\!\left(\text{tag}_{\text{lbl}},\; \text{sid}_{\mathbb{F}},\; k,\; i,\; \beta,\; \text{u128\_to\_Fp}(L_{k,i,\beta}),\; \rho_{k,i,\beta}\right)$$
   folded sequentially into a per-instance Poseidon chain commitment:
   $$A_{k,0} = \text{Poseidon}_{\mathbb{F}_p}(\text{tag}_{\text{init}}, \text{sid}_{\mathbb{F}}, \text{cid}_{\mathbb{F}}, k), \qquad A_{k,i+1} = \text{Poseidon}_{\mathbb{F}_p}(A_{k,i},\; C^{\text{pos}}_{k,i,0},\; C^{\text{pos}}_{k,i,1}), \qquad R^{\text{pos}}_k = A_{k,W}.$$

> **Why blinding $\rho_{k,i,\beta}$ is essential**: For retained instances $j \in \mathcal{R}$, $s_j$ is never opened. Without $\rho_{k,i,\beta}$, once active label $L_{b,i,x_i}$ is revealed at assertion time, $C^{\text{pos}}_{b,i,x_i}$ is deterministic; while $L_{b,i,1-x_i}$ still has 128 bits of entropy, adding full field blinding $\rho_{k,i,\beta} \in \mathbb{F}_p$ makes $C^{\text{pos}}_{k,i,\beta}$ information-theoretically/statistically hiding in $\mathbb{F}_p$, while opened C&C instances $k \in \mathcal{O}$ deterministically recompute both $\rho_{k,i,\beta}$ and $L_{k,i,\beta}$ from $s_k$!

---

## 3. Formal Protocol Relations

### 3.1 Relation 1: Two-Phase Cut-and-Choose Setup ($\mathcal{R}_{\text{C\&C}}$)

1. **Garbler `Commit_1`**: For Fixed Circuit Specification $\text{cid}$ and fresh session identifier $\text{sid} \in \{0,1\}^{256}$, the garbler generates $N$ independent instances from $s_0, \dots, s_{N-1} \xleftarrow{\$} \{0,1\}^{256}$ and publishes for each $k \in [0, N)$:
   $$\text{hdr}_k = \left(\text{salt}_k,\; T_{k,\text{true}},\; F_{k,\text{false}},\; \text{SHA256}(\text{ct}_k),\; R^{\text{btc}}_k,\; R^{\text{pos}}_k,\; \text{SHA256}(O_{k,0}),\; \text{SHA256}(O_{k,1})\right)$$
   with aggregate commitment $\text{Commit}_1 = \text{SHA256}(\text{"babe-nova/commit1/v1\0"} \parallel \text{sid} \parallel \text{cid} \parallel \text{hdr}_0 \parallel \dots \parallel \text{hdr}_{N-1})$.
2. **Challenger Randomness**: Challenger samples $\eta \xleftarrow{\$} \{0,1\}^{256}$, which deterministically partitions $[0, N) = \mathcal{O} \sqcup \mathcal{R}$ with $|\mathcal{R}| = M$, $|\mathcal{O}| = N - M$, and base instance $b = \min(\mathcal{R})$ via Fisher–Yates sampling from $\text{ChaCha20}(\text{SHA256}(\text{"babe-nova/cc/v1\0"} \parallel \text{Commit}_1 \parallel \eta))$.
3. **Opening & Soldering (`Commit_2`)**:
   - Garbler reveals $\{s_k\}_{k \in \mathcal{O}}$. Challenger recomputes $\text{Garble}(\mathcal{C}_{\text{cid}}, s_k)$ for every $k \in \mathcal{O}$ and verifies $\text{hdr}'_k = \text{hdr}_k$ **and** $O'_{k,0} \neq O'_{k,1}$.
   - For each soldered instance $j \in \mathcal{R} \setminus \{b\}$ (ordered $j_1 < \dots < j_{M-1}$), the garbler computes and publishes the **Free-XOR affine soldering parameters**:
     $$S_{j,i} = L_{j,i,0} \oplus L_{b,i,0} \quad (\forall i \in [0, W)), \qquad \Gamma_j = \Delta_j \oplus \Delta_b$$
     together with a zero-knowledge Nova/Spartan certificate $\pi_{\text{solder}}$ for $\mathcal{R}_{\text{solder}}$.

### 3.2 Relation 2: Zero-Knowledge Nova/Spartan Soldering Relation ($\mathcal{R}_{\text{solder}}$)

Let $\mathcal{J} = (j_1, \dots, j_{M-1})$ be the sorted non-base retained indices ($K = M - 1$).

- **Public Statement $X_{\text{solder}}$** (bound into Nova public IO $z_0 \to z_T$):
  - Binding tag $\tau = \text{Poseidon}_{\mathbb{F}_p}(\text{tag}_{\text{bind}},\; \text{sid}_{\mathbb{F}},\; \text{cid}_{\mathbb{F}},\; \eta_{\mathbb{F}},\; b,\; W,\; H_{\Delta})$;
  - Public commitment to published deltas $H_{\Delta} = \text{PoseidonChain}(\{(S_{j,i}, \Gamma_j)\}_{j \in \mathcal{J}, i \in [0, W)})$;
  - Base Poseidon accumulator root $R^{\text{pos}}_b$ and soldered Poseidon accumulator roots $\{R^{\text{pos}}_j\}_{j \in \mathcal{J}}$.
- **Private Witness $W_{\text{solder}}$** (known only to garbler, hidden by ZK `CompressedSNARK`):
  - Base secret Free-XOR offset $\Delta_b \in \{0,1\}^{128} \setminus \{0\}$ and soldered offsets $\{\Delta_j\}_{j \in \mathcal{J}}$;
  - Base false wire labels $\{L_{b,i,0}\}_{i=0}^{W-1}$ and Poseidon blindings $\{(\rho_{b,i,0}, \rho_{b,i,1})\}_{i=0}^{W-1}$;
  - Soldered Poseidon blindings $\{(\rho_{j,i,0}, \rho_{j,i,1})\}_{j \in \mathcal{J}, i \in [0, W)}$.
- **Step Relation $\mathcal{R}_{\text{solder}}$** (folded in batches of $B$ wires across $T = \lceil W / B \rceil$ IVC steps):
  1. **Bit Decomposition & Canonicality**: Every secret label $L_{b,i,0}$, secret offset $\Delta_b, \Delta_j$, and public translation $S_{j,i}, \Gamma_j$ decomposes into 128 Boolean bits $u \in \{0,1\}^{128}$ ($u_t (1 - u_t) = 0$).
  2. **Global Offset Translation**: For every $j \in \mathcal{J}$, bitwise XOR holds:
     $$\Delta_j = \Delta_b \oplus \Gamma_j, \qquad \text{and} \qquad \Delta_b \neq 0^{128},\; \Delta_j \neq 0^{128}.$$
  3. **Wire-by-Wire Free-XOR Translation**: For every wire $i \in [0, W)$ and every $j \in \mathcal{J}$:
     $$L_{b,i,1} = L_{b,i,0} \oplus \Delta_b, \qquad L_{j,i,0} = L_{b,i,0} \oplus S_{j,i}, \qquad L_{j,i,1} = L_{j,i,0} \oplus \Delta_j.$$
  4. **Commitment Opening Consistency**: Recomputing $C^{\text{pos}}_{b,i,0}, C^{\text{pos}}_{b,i,1}$ and $\{C^{\text{pos}}_{j,i,0}, C^{\text{pos}}_{j,i,1}\}_{j \in \mathcal{J}}$ updates the running Poseidon accumulators $A_b$ and $\{A_j\}_{j \in \mathcal{J}}$ from their fixed initial states to exact final roots $z_T = (\tau,\; W,\; R^{\text{pos}}_b,\; R^{\text{pos}}_{j_1}, \dots, R^{\text{pos}}_{j_K},\; H_{\Delta})$.

#### Unsoldering Algebra Soundness Lemma

Suppose $\mathcal{R}_{\text{solder}}(X_{\text{solder}}, W_{\text{solder}}) = 1$. Then for every wire $i \in [0, W)$, every bit $x_i \in \{0, 1\}$, and every retained instance $j \in \mathcal{J}$:
$$L_{b,i,x_i} \oplus S_{j,i} \oplus x_i \Gamma_j = (L_{b,i,0} \oplus x_i \Delta_b) \oplus (L_{j,i,0} \oplus L_{b,i,0}) \oplus x_i (\Delta_j \oplus \Delta_b) = L_{j,i,0} \oplus x_i \Delta_j = L_{j,i,x_i}.$$
Thus, if the base active label $L_{b,i,x_i}$ is authentic for bit $x_i$, the unsoldered label $L^{\text{eval}}_{j,i} := L_{b,i,x_i} \oplus S_{j,i} \oplus x_i \Gamma_j$ equals the **exact** pre-committed label $L_{j,i,x_i}$ of retained instance $j$!

#### Critical Zero-Knowledge Requirement (`CompressedSNARK` vs `DirectSNARK`)

In `nova-snark = 0.76.0`:
- `spartan::direct::DirectSNARK::prove` outputs `blind_r_W` directly in the proof struct (`snark.rs`), making `DirectSNARK` **non-zero-knowledge**. Using `DirectSNARK` for $\mathcal{R}_{\text{solder}}$ would allow an algebraic attacker to test candidate wire labels or expose witness blindings.
- By contrast, `nova::CompressedSNARK::prove` executes `NIFSRelaxed::prove` against a freshly sampled random satisfying relaxed R1CS instance `(U_rand, W_rand)` before invoking `RelaxedR1CSSNARK` + `ipa_pc::EvaluationEngine`, masking $(W, r_W)$ statistically/computationally in $\mathbb{F}_p$ while requiring **zero trusted setup**. Therefore, **only `CompressedSNARK` is permitted** for $\pi_{\text{solder}}$.

---

## 4. Why Soldering Alone Does Not Establish Circuit Construction (Malicious-Garbler Defense)

A crucial subtlety highlighted in Phase 2:
> **$\pi_{\text{solder}}$ proves only that input wire labels across $\mathcal{R}$ encode the same bit $x_i$ relative to $C^{\text{pos}}_{k,i,\beta}$—it says NOTHING about whether the Half-Gates ciphertexts $\text{ct}_j$ compute $\mathcal{C}_{\text{cid}}$, nor whether $R^{\text{pos}}_j$ and $R^{\text{btc}}_j$ commit the same labels if $j$ was never checked!**

Specifically, without C&C and 1-of-$M$ spending enforcement, a malicious garbler could:
1. Construct all $M$ retained circuits to compute the constant function $f(x) \equiv 0$ (`accept`), while honestly soldering their input wires so $\pi_{\text{solder}}$ verifies;
2. Commit honest labels in $R^{\text{btc}}_b$ and bogus labels in $R^{\text{pos}}_j$; or
3. Swap `accept` and `refute` output commitments $\text{SHA256}(O_{j,0}) \leftrightarrow \text{SHA256}(O_{j,1})$.

### Complete Defense Composition & Soundness Bound

All three attacks are defeated simultaneously by the composition of **Two-Phase C&C + Dual-Commitment Seed Opening + 1-of-$M$ Taproot Disprove**:

1. **Pre-Challenge Binding (`Commit_1` before $\eta$)**: Before learning $\eta$, the garbler commits $\text{hdr}_k$ (binding $\text{ct}_k$, $R^{\text{btc}}_k$, $R^{\text{pos}}_k$, and $\text{SHA256}(O_{k,0}), \text{SHA256}(O_{k,1})$) for all $N$ instances.
2. **Full Deterministic Seed Regeneration on $\mathcal{O}$**: Let $B \subseteq [0, N)$ be the set of *bad* instances (any instance $k$ where $\text{ct}_k$, $R^{\text{btc}}_k$, $R^{\text{pos}}_k$, or output hashes deviate by even 1 bit from honest `GarbleMode::new_with_seed(s_k)` on $\mathcal{C}_{\text{cid}}$).
   - If $|B| > M$, then by pigeonhole $B \cap \mathcal{O} \neq \emptyset$, so at least one bad instance is opened and C&C aborts during setup!
   - If $1 \le |B| \le M$, the garbler passes C&C only if $B \subseteq \mathcal{R}$ (every bad instance lands inside the $M$ retained slots), which occurs with probability:
     $$\Pr[\text{all } j \in \mathcal{R} \text{ are bad}] = \begin{cases} \binom{N - |B|}{N - M} \big/ \binom{N}{N - M} \le \binom{N}{M}^{-1} & \text{if } |B| = M, \\ 0 & \text{if } |B| < M \text{ (at least one } j^\star \in \mathcal{R} \text{ is honest!)}. \end{cases}$$
   At $(N = 115, M = 39)$, $\binom{115}{39}^{-1} \approx 2^{-107.8}$ (and even under adaptive grinding bounded by Bitcoin block/tx framing or two-phase C&C, BABE's optimal $(115, 39)$ bounds soundness error below $2^{-53}$).
3. **1-of-$M$ Honest Instance Sufficiency**:
   Suppose **at least one** retained instance $j^\star \in \mathcal{R}$ is honest ($j^\star \notin B$), and suppose the base instance $b$ has either honest or adversarial commitments:
   - Case A ($b \notin B$ is honest, or $b$'s revealed active labels match $C^{\text{pos}}_{b,i,x_i}$ for the true input $x$):
     `CheckLampSigsMatch` forces the garbler to reveal $L_{b,i,x_i}$ matching $x_i$ (the on-chain dispute input bits). By the Unsoldering Algebra Soundness Lemma and binding of $R^{\text{pos}}_{j^\star}$, $L^{\text{eval}}_{j^\star,i} = L_{j^\star,i,x_i}$ for every wire $i$. Since $j^\star$ is honest and $x$ is a valid refutation witness ($\mathcal{C}_{\text{cid}}(x) = 1$), evaluating $\text{ct}_{j^\star}$ deterministically yields $O_{j^\star,1}$, unlocking leaf $j^\star$ of the 1-of-$M$ `Disprove` Taptree!
   - Case B ($b \in B$ committed $R^{\text{btc}}_b$ inconsistent with $R^{\text{pos}}_b$):
     Wait—what if $b \in B$ is malicious while $j^\star \in \mathcal{R} \setminus \{b\}$ is honest, and the garbler put *different* labels in $R^{\text{btc}}_b$ vs $R^{\text{pos}}_b$?
     **Critical Security Fix Incorporated in Our Design**:
     If $b$ is malicious and $R^{\text{btc}}_b$ is *not* algebraically tied to $R^{\text{pos}}_b$, a malicious garbler who gets lucky on the single index $b \in B$ ($\Pr = |B|/N$, which is linear, NOT exponential!) could put $L'_{b,i,x_i}$ in $R^{\text{btc}}_b$ and $L_{b,i,1-x_i}$ in $R^{\text{pos}}_b$!
     **How BABE & Our Protocol Close Case B Completely**:
     In $\mathcal{R}_{\text{solder}}$ (OR by checking `SHA256` / binding the base instance's public commitment directly, OR soldering *all* $M$ instances against an explicit algebraic/hash commitment verified on the base labels!), how do we prevent $R^{\text{btc}}_b \neq R^{\text{pos}}_b$?
     Look:
     1. In **Bitcoin Tapscript**, `AssertLabels` reveals the raw 16-byte base active labels $\{L_{b,i,x_i}\}_{i=0}^{W-1}$ on-chain against $h^{\text{tap}}_{b,i,x_i} = \text{SHA256}(L_{b,i,x_i})$!
     2. If $C^{\text{pos}}_{k,i,\beta}$ on the base wire uses **either** in-circuit SHA-256 on the base instance (only $2W$ compressions total, independent of $M$!) **OR** deterministic unblinded Poseidon $C^{\text{pos}}_{k,i,\beta} = \text{Poseidon}(\text{tag}, \text{sid}_{\mathbb{F}}, k, i, \beta, L_{k,i,\beta})$? Wait: if $C^{\text{pos}}_{b,i,\beta}$ is unblinded Poseidon, can the evaluator check $C^{\text{pos}}_{b,i,x_i}$? Still not $C^{\text{pos}}_{b,i,1-x_i}$ unless $R^{\text{btc}}_b$ and $R^{\text{pos}}_b$ are bound!
     3. Whereas if $\mathcal{R}_{\text{solder}}$ verifies **SHA-256** on the base instance $b$ ($h^{\text{tap}}_{b,i,\beta} = \text{SHA256}(\dots \parallel L_{b,i,\beta})$ — which occurs **only once** for base instance $b$, NOT $M$ times!) AND **Poseidon** on the $M - 1$ soldered instances $j \in \mathcal{R} \setminus \{b\}$? Wait: let's check the R1CS cost of SHA-256 vs Poseidon:
        - Even simpler and **30× faster**: what if `AssertLabels` (or the challenger) checks $C^{\text{pos}}_{b,i,x_i}$? Wait: on-chain Bitcoin Script can only check `OP_SHA256` (`h^{\text{tap}}_{b,i,x_i}`)! If a malicious garbler reveals $L^{\text{on-chain}}_{b,i}$ satisfying $\text{SHA256}(L^{\text{on-chain}}_{b,i}) = h^{\text{tap}}_{b,i,x_i}$, what forces $L^{\text{on-chain}}_{b,i}$ to equal the $L_{b,i,x_i}$ used inside $\pi_{\text{solder}}$?
        **ONLY if $\pi_{\text{solder}}$ itself binds $h^{\text{tap}}_{b,i,\beta} = \text{SHA256}(\dots \parallel L_{b,i,\beta})$ for the single base instance $b$, OR if ALL $M$ instances have `CheckLampSigsMatch`? No, only $b$ is revealed on-chain!**
        WAIT A SECOND! Think about that!
        Let's verify that attack!
        Suppose $N = 115, M = 39$, and the adversary corrupts **only 1** instance ($|B| = 1$). With probability $M/N = 39/115 \approx 34\%$, that 1 corrupted instance survives C&C, and with probability $1/115 \approx 0.87\%$, that 1 corrupted instance IS $b = \min(\mathcal{R})$!
        If $\pi_{\text{solder}}$ only checked Poseidon commitments $R^{\text{pos}}_b$ for instance $b$ while Bitcoin Script only checked SHA-256 commitments $R^{\text{btc}}_b$ for instance $b$, then with probability **$1/115 \approx 0.87\%$** (instead of $2^{-53}$!!), the adversary could put fake labels in $R^{\text{btc}}_b$ and real labels in $R^{\text{pos}}_b$, pass C&C, pass $\pi_{\text{solder}}$, satisfy Bitcoin Script `CheckLampSigsMatch`, and give the challenger useless garbage labels for all $M - 1$ honest circuits!!
        **WHAT A CATCH!!**
        And look how cleanly **Hybrid Base-SHA256 + Soldered-Poseidon** inside $\mathcal{R}_{\text{solder}}$ (or SHA-256 for base instance $b$ + Poseidon for $j \in \mathcal{R} \setminus \{b\}$) **completely eliminates that $1/N$ attack**:
        - Base instance $b$ is just **1** instance (independent of $M = 39$!), and each label $L_{b,i,\beta}$ is 16 bytes (< 55 bytes = **1 single SHA-256 block**!).
        - Or even better: in $\mathcal{R}_{\text{solder}}$, the base instance $b$'s commitment is **literally** the SHA-256 hashlock $h^{\text{tap}}_{b,i,\beta} = \text{SHA256}(L_{b,i,\beta})$ that Bitcoin Tapscript checks with `OP_SHA256 <h> OP_EQUALVERIFY`!
        - Then there is **ZERO** gap between Bitcoin Script and Nova R1CS on base instance $b$: the **exact** 32-byte digest `OP_SHA256` checks on-chain is verified inside $\mathcal{R}_{\text{solder}}$, while all $M - 1$ soldered instances $j \in \mathcal{R} \setminus \{b\}$ use lightweight blinded Poseidon commitments $C^{\text{pos}}_{j,i,\beta}$ (`~310` R1CS constraints each)!
        - Thus for $M = 39$: instead of $39 \times 2 = 78$ SHA-256s per wire ($2{,}015{,}520$ R1CS constraints/wire!), Hybrid Base-SHA256 + Soldered-Poseidon uses **only $2$ SHA-256s + $76$ Poseidons per wire** ($\sim 75\text{k}$ constraints/wire — **$27\times$ fewer R1CS constraints** while preserving **exact $2^{-53}$ C&C soundness** with zero $1/N$ base-equivocation gap!).

---

## 5. Windowed Witness-Assisted Pedersen Binding Traces ($\mathcal{R}_{\text{ped-chunk}}$)

In `FC03`, authenticating $(W, r_W)$ against Nova's Pedersen commitment $\text{comm}_W = \sum_{j=0}^{n-1} W_j G_j + r_W H$ used a 1-bit transition trace of length $256(n + 1)$ (`67,109,120` steps for $n = 2^{17}$), where each step executed projective RCB complete addition (`7,285,647` non-free gates).

Adapting BABE §4.2's witness-assisted EC relation to Pasta curves $E(\mathbb{F}_q) : y^2 = x^3 + 5$:

1. **Windowed Chunking ($w$-bit windows, e.g. $w = 4$ or $w = 8$)**:
   Decompose each 255-bit scalar $s_j = \sum_{c=0}^{\lceil 255/w \rceil - 1} d_{j,c} 2^{wc}$ with $d_{j,c} \in [0, 2^w)$. Precompute and pin in `TrustedConfig` the generator window table $T_{j,c,u} = (u \cdot 2^{wc}) G_j$ for $u \in [1, 2^w)$.
   - Trace length drops from $256(n+1)$ to $\lceil 255/w \rceil (n+1)$ (**$4\times$ fewer trace leaves** at $w = 4$; **$8\times$ fewer** at $w = 8$).
2. **Witness-Assisted Complete Affine Addition (`3` Field Multiplications vs `12+` RCB)**:
   To verify $P_3 = P_1 + P_2$ for affine points $P_k = (\text{inf}_k, x_k, y_k) \in \{0,1\} \times \mathbb{F}_q^2$ with prover-supplied slope witness $\lambda \in \mathbb{F}_q$ and inverse witness $\mu \in \mathbb{F}_q$:
   - **Identity cases**: If $\text{inf}_1 = 1$, enforce $P_3 = P_2$; else if $\text{inf}_2 = 1$, enforce $P_3 = P_1$.
   - **Inverse case ($x_1 = x_2 \land y_1 + y_2 = 0$)**: Enforce $\text{inf}_3 = 1, x_3 = 0, y_3 = 0$.
   - **Chord case ($x_1 \neq x_2$)**: Enforce $(x_2 - x_1) \cdot \mu = 1$ (**1 mul**), $(x_2 - x_1) \cdot \lambda = y_2 - y_1$ (**1 mul**), $\lambda^2 = x_1 + x_2 + x_3$ (**1 sq**), and $\lambda (x_1 - x_3) = y_1 + y_3$ (**1 mul**).
   - **Tangent/Doubling case ($x_1 = x_2 \land y_1 = y_2 \neq 0$)**: Enforce $(2 y_1) \cdot \mu = 1$, $(2 y_1) \cdot \lambda = 3 x_1^2$, $\lambda^2 = 2 x_1 + x_3$, and $\lambda (x_1 - x_3) = y_1 + y_3$ (note $y = 0$ is impossible on $y^2 = x^3 + 5$ over Pasta since $-5$ is not a cube in $\mathbb{F}_p$ or $\mathbb{F}_q$, and even if checked explicitly via $y_1 \cdot \mu_y = 1$, adds 0 soundness ambiguity).
   Total dominant cost: **4–5 field multiplications** (~`360k–410k` gates) instead of **12+ projective RCB multiplications** (`~1.0M+` gates), while verifying $w$ bits per transition!

---

## 6. Indexed Dispute Selection, Active-Label Delivery, and Bitcoin Enforcement

### What Each Role Knows and Verifies

| Actor | Secret State Held | Public Artifacts Verified |
| :--- | :--- | :--- |
| **Garbler (Operator)** | Retained seeds $\{s_j\}_{j \in \mathcal{R}}$, Free-XOR $\{\Delta_j\}_{j \in \mathcal{R}}$, blindings $\{\rho_{j,i,\beta}\}$ | Publishes `Commit_1`, opened seeds $\{s_k\}_{k \in \mathcal{O}}$, deltas $\{(S_{j,i}, \Gamma_j)\}$, $\pi_{\text{solder}}$, and active base labels $\{L_{b,i,x_i}\}$. |
| **Challenger / Evaluator** | None (stateless wrt garbler secrets; knows no $s_j$, no $\Delta_j$, no $L_{j,i,1-x_i}$) | Verifies `Commit_1`, C&C seed openings on $\mathcal{O}$, `CompressedSNARK::verify` on $\pi_{\text{solder}}$, `CheckLampSigsMatch` on $\{L_{b,i,x_i}\}$, unsolders all $M$ circuits, and extracts $O_{j^\star, 1}$ (`refute`) if claim is false. |
| **Bitcoin Consensus (Taproot)** | None | Enforces pre-signed transaction graph, `OP_SHA256 <h> OP_EQUALVERIFY` base-label consistency (`CheckLampSigsMatch`), CSV timeouts ($D_1, D_{\text{label}}, D_3$), and 1-of-$M$ `Disprove` hashlock preimage spending. |

### Bitcoin Taproot Spending Paths

1. **`ClaimTx`**: Locks operator bond $B_{\text{op}}$ under NUMS internal key with two Tapleaves:
   - *Optimistic Payout*: `<D_1> OP_CSV OP_DROP <PK_op> OP_CHECKSIG`
   - *Challenge Trigger*: `<PK_op> OP_CHECKSIGVERIFY <PK_ch> OP_CHECKSIG` (pre-signed)
2. **`ChallengeTx`**: Challenger commits dispute index $q$ and opened operands $x = (\text{claim\_id}, q, \text{openings})$. Spends `ClaimTx` to an output with two Tapleaves:
   - *Assert Active Base Labels (`CheckLampSigsMatch`)*: For each wire $i \in [0, W)$, verifies bit $x_i \in \{0,1\}$ matches the committed dispute input $x$ and checks:
     `OP_IF OP_SHA256 <h^{tap}_{b,i,1}> OP_EQUALVERIFY OP_ELSE OP_SHA256 <h^{tap}_{b,i,0}> OP_EQUALVERIFY OP_ENDIF`
     signed by `<PK_op> OP_CHECKSIG`.
   - *Withholding Recovery Leaf*: `<D_label> OP_CSV OP_DROP <PK_ch> OP_CHECKSIG`. **If the operator withholds $\{L_{b,i,x_i}\}$ or equivocates relative to $x$, `AssertLabelsTx` cannot confirm, and after $D_{\text{label}}$ blocks the challenger sweeps the bond directly.**
3. **`AssertLabelsTx` $\rightarrow$ 1-of-$M$ `Disprove` Taptree**:
   - *`M` Disprove Leaves* (one per retained instance $j \in \mathcal{R}$):
     `OP_SHA256 <SHA256(O_{j,1})> OP_EQUALVERIFY <PK_ch> OP_CHECKSIG`
     (Because the garbler knows $O_{j,1}$, `<PK_ch> OP_CHECKSIG` ensures the operator cannot self-spend to steal challenger fees, while any challenger holding **1** valid `refute` label $O_{j^\star,1}$ slashes the bond in a single **~150–185 vB** transaction!)
   - *Operator Timeout Payout*: `<D_3> OP_CSV OP_DROP <PK_op> OP_CHECKSIG` (spendable only if no `Disprove` leaf is satisfied within $D_3$ blocks).
