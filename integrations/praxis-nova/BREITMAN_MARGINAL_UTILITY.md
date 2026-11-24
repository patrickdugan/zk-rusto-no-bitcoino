# Witness encryption: marginal utility and Bitcoin bridge capital

Date: 2026-11-24
Status: research hypothesis and proposed comparison; no new cryptographic implementation or measured capital saving.
Program: PNS-05, dependent on PNS-03 and PNS-04.
Related: [settlement pilot](README.md), [direct verifier](DIRECT_NOVA_BQS.md), [PNS-04F handoff](bqs/CLAUDE_PNS04F.md), [Praxis paper](https://eprint.iacr.org/2026/2971), [Spiral capital-bound campaign](https://github.com/patrickdugan/Spiral/tree/research/capital-bound-stage0/experiments/capital-bound).

## The objection

Arthur Breitman (@ArthurB, X, 24 November 2026; excerpt supplied by the project owner, individual post permalink unverified) argues that witness encryption's incremental utility is narrow: programmable chains already support mathematical bounties through ZK verification, and avoiding subsequent sender cooperation matters principally when the sender disappears. He is skeptical of the incremental benefit for Bitcoin as well.

Accept the same-chain bounty argument. A contract with an appropriate verifier can transfer escrowed assets to the first eligible claimant without further participation by the funder. Any practical evaluation of witness encryption must include this strong baseline rather than treating ZK verification as incapable of autonomous settlement.

## Distinct application: control outside the verifier's execution domain

A witness-encryption ciphertext can protect a secret m under an NP instance x. A valid witness w for R(x,w)=1 permits recovery of m. No contract must execute that predicate at the moment of recovery. A secret may have meaning outside the chain or machine on which a proof was produced. Examples include an off-chain encrypted artifact or a transaction-specific authorization for an independent settlement system.

This is a candidate architectural advantage, not evidence of a trustless bridge. Ordinary witness encryption typically guarantees indistinguishability for false instances; confidentiality for true instances whose witnesses are difficult to find needs the corresponding stronger security notion or assumptions. For the actual Praxis relation, audit which theorem applies, what setup it requires, and which security guarantees are conditional. Nova verification alone does not establish these guarantees. A publicly available valid witness allows other parties to attempt decryption. Sender deletion of plaintext and signing material cannot be inferred from ciphertext generation.

## Proposed Nova-only release path

1. Freeze the independently authenticated PNS1 statement and pinned Nova compressed verification key before producing proofs. Bind the funding outpoint, exact payout transaction, recipient and liability commitments, fee, network, epoch, finality and refund policy through the authenticated context. Complete PNS-03, including actual transaction/sighash checks, rather than trusting a supplied digest.
2. Compile the complete native Nova compressed verification predicate directly to the Praxis Boolean quadratic relation (PNS-04). A proof and constrained verification auxiliaries form the witness. All transcript challenges and both IPA openings must be verified. No Groth16, SP1, STARK or second proof system.
3. Use the corresponding Praxis construction to encrypt a transaction-specific release capability. Investigate encryption of a preauthorized transaction-bound signature as a regtest candidate. Validate signature generation and binding, and specify who can construct the original spend and whether a funding key still exists. Encrypting a general Bitcoin private key is unsafe for this application; an unrestricted key permits spending to a different recipient.
4. A claimant with the necessary witness may recover the capability and submit the exact authorized spend. Design for ciphertext availability, transaction fees, conflict resolution, witness copying, duplicate claims and refund races. A copied witness must not permit redirecting the payout. The underlying outpoint is single-spend, but cross-outpoint/cross-epoch liability replay needs its own authenticated rule. A fixed presigned transaction also creates fee-management and liveness constraints.

The relation must bind the complete transaction and authorization policy; a valid proof alone cannot prevent a creator with retained signing authority from spending the same UTXO by another path. Existing BitVM3 M13/M14 remains a separate baseline. A genuinely keyless result requires an explicit funding/spend construction and a separate proof of its trust properties. A static release ciphertext may also be unsuitable for withdrawal destinations or amounts that are unknown when the funding transaction is created.

## PNS-05A: comparative capital experiment

Hypothesis H1: under identical withdrawal volume, latency target, fault assumptions and settlement policy, a practical witness-conditioned release can reduce incremental locked operator collateral and/or inventory tied up during challenge or reimbursement delays, while keeping the same safety and liveness requirements.

H0: any savings disappear once the equivalent trust assumptions, signing authorization, ciphertext generation, availability, decryption and settlement delays are accounted for, or the proposed construction cannot satisfy the gates.

Compare these four architectures:
- Same-domain programmable escrow with native proof verification (Breitman's bounty baseline; external asset custody reported separately).
- Existing BitVM3/Nova bridge path, including actual challenge, funding and reimbursement mechanics.
- Transaction-specific preauthorization with ordinary signatures, HTLCs/adaptor signatures or pre-signed transaction control where applicable; report which predicates and cooperation models each supports.
- Direct Nova-to-Praxis witness-conditioned release, once implemented. Treat absent components as unknown and any different trust/setup assumptions as an explicit comparison limitation.

Use matched withdrawal traces, including bursty arrivals, operator disappearance, ciphertext/data unavailability, chain congestion, confirmation delay and attempted conflicting spends. Separate user escrow principal from incremental liquidity and collateral. A bridge's economic obligation to have the backing assets persists even when its proof path changes.

For architecture a, define the incremental capital-time over T days:

    K_a = integral_0^T [B_a(t) + L_a(t)] dt

where B is incremental operator bond in sats and L is incremental operator liquidity/inventory in sats, counting a sat in only one category. Report principal P(t) separately, and include all other reserves in a documented sensitivity case. At annual opportunity rate r, capital cost in sats is r*K_a/365. Total comparable cost:

    C_a = r*K_a/365 + F_a + Q_a + A_a + S_a

F = on-chain and settlement fees; Q = amortized setup, proving, ciphertext production and decryption compute; A = availability/storage/distribution cost; S = monitoring, operational and other security costs (avoid double counting). All monetary terms converted to sats under a declared exchange-rate assumption where needed. Compare C_BitVM - C_WE and report latency, risk assumptions, peak bond, peak incremental liquidity, sat-days per settled BTC, cost per successful withdrawal, tail delay and failure rates. Report expected losses separately under explicit scenario probabilities rather than assuming a dollar price for trust.

For a simple stationary sanity check, arrival rate lambda withdrawals/day, mean advance v sats, mean reimbursement duration d days implies mean outstanding advance lambda*v*d sats under stable operation (Little's law). Reducing d by delta days would free lambda*v*delta sats on average if all other obligations remain fixed. This is illustrative only. Simulate actual queueing, batching, fees and reserve constraints for the decision.

The break-even additional WE cost per withdrawal equals the measured avoided capital cost and other avoided operating costs divided by successful settled withdrawals; sensitivity to throughput, opportunity rate, ciphertext reuse, setup amortization and challenge/reimbursement assumptions is mandatory. Same-domain escrow is a useful lower-complexity control but lacks comparable Bitcoin custody absent an external authorization mechanism.

## Prerequisite gates and stop conditions

- Security: independently review the actual WE security notion and setup, direct Nova acceptance soundness and application relation, authorization/key retention, replay, finality and refund races. Treat unmatched security properties as a failed comparison, not a capital improvement.
- Feasibility: PNS-04F reports a group-only baseline estimate of 6,751,647,332 Boolean variables for the two IPA MSMs. This is an estimate from incomplete verifier work, not the size of the finished WE relation. Derive concrete Praxis parameters from measured full relation counts and paper constraints; published Groth16-specific ciphertext figures do not transfer. No external proof wrapper as a shortcut.
- Regtest: require independent valid proofs of a fixed PNS1 statement, matching payout transaction, adversarial witness and key/statement substitution checks, actual WE decryption, and a successful transaction-specific Bitcoin settlement. Test copied witness, malicious original signer, duplicate claims, changed transaction/fee/output, and timeout. No mainnet funds.
- Economics: freeze workloads, baseline implementations, accounting and pass threshold before collecting measurements. Keep missing values as unknown. If exact direct verification is computationally infeasible or signer assumptions dominate, record a bounded no-go; no capital-saving claim.

## Short response to Breitman

A same-chain mathematical bounty already has a good solution using ZK verification. The additional capability worth investigating is witness-conditioned release of a secret whose meaning lies outside the verifier's execution environment. For Bitcoin bridges, the practical test is how much incremental collateral, reimbursement inventory and future counterparty cooperation this can remove under matched security assumptions, after accounting for the cost of witness encryption. A working, transaction-bound construction and measured break-even are required.

## Continuation

After PNS-03 and PNS-04, implement a small deterministic PNS-05A cost model and adversarial regtest pilot in this branch. Cross-reference Spiral's capital-bound campaign without modifying it in this work order. Keep a distinct accounting of native Nova proof cost, direct BQS size, Praxis setup/ciphertext cost, and Bitcoin authorization/settlement cost. No funds, paid compute, mainnet deployment, or merge authorized by this note.
