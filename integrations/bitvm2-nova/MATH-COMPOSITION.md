# Mandatory retained-profile mathematical composition

`retained_verifier.verify_retained_math` joins the independently replayed Nova
and Spartan protocol, all six authenticated matrices and both directly executed
native IPA terminal relations in one call. It is restricted to the retained
testnet4 genesis-to-2020 k=5 proof and its independently pinned key/metadata.
It is a composition-conformance boundary, not general proof acceptance or a
complete Bitcoin Script verifier. No trusted setup or compression backend is
added, and existing optional replay APIs and their false proof flags remain.

## Why a separate mandatory call

The previous matrix benchmark actually checked all matrix obligations, and the
IPA benchmark actually executed both terminal MSMs. Their successful reports
were separate: the IPA benchmark's fresh replay omitted matrix inputs. Neither
one report nor a conjunction of caller-supplied `passed` fields authorizes a
complete result. The new factory requires the direct computations under the
same immutable proof, expected policy and metadata.

```
literal policy + typed pinned inputs
  -> privately owned trace snapshot
  -> fresh protocol replay + six authenticated matrices + two inner equations
  -> fresh IPA requests matched to that replay
  -> direct primary CPU helper + direct secondary CPU helper
  -> immutable retained-math composition summary
```

No replay dictionary, native report, matrix receipt or execution receipt is an
input argument. A stored summary cannot recreate the factory result.

## Preflight and scope

The Linux/GitHub environment guard protects local resources; it is not evidence
authentication. Before matrix table allocation or child execution, preflight
requires the literal retained profile: proof, bundle, end state, key, dimensions,
key bindings, native trace, Poseidon parameters, matrix profile/collection and
generator collection. The whole canonical `ExpectedBundle.json` pin is
`cdfa31622881cc1863abd1eb252c136184501785b4b02e9985e6ba0850b2ac54`
over 1,738 compact sorted ASCII bytes. It includes all 17 initial state scalars
and the checkpoint origin, in addition to network, k and step count.

Unsupported profiles fail before bulk work. Such scope rejection must not be
described as cryptographic verification of an alternative malformed proof. The
underlying native helper has the same retained-fixture scope, including 19/14 IPA
rounds. Caller-owned replacement profiles used by small tests of lower-level
mathematics do not bypass this new literal preflight.

A bounded canonical trace snapshot is privately owned before replay and request
construction. Typed proof/key/parameter/collection inputs retain their existing
immutable identities. Repeated deterministic replay uses those same inputs; the
sealed IPA request identity and mathematical statement must match the mandatory
matrix replay before the native helper is launched.

## Released verifier obligations

Two independent source audits found no additional released-verifier equation
for this exact retained profile once all the following obligations are mandatory.
This source comparison is not a formal security proof.

| Nova 0.76.0 source | Composed obligation |
| --- | --- |
| `src/nova/mod.rs:914-979` | Step/arity policy, output-state binding and both outer Poseidon hashes |
| `src/nova/mod.rs:982-1016` | Three NIFS challenges/folds and commitment derandomization |
| `src/spartan/snark.rs:259-309` | Exact Keccak absorption/challenges, outer and inner sumchecks and outer terminal |
| `src/spartan/snark.rs:311-357` | Full assignment evaluation, six authenticated CSR matrices and both direct inner terminals, including eval_Z=0 |
| `src/spartan/mod.rs:436-483` | Padding, batch sumcheck/terminal, joint commitment and evaluation |
| `src/provider/ipa_pc.rs:286-388` | Ordered IPA challenges, inverses, tensor factors, small side, original generators and complete native CPU MSM |

The authoritative release is the published `nova-snark=0.76.0` crate under the
digest in `SOURCES.json`. Historical inspected Git algebra is not substituted for
that release. Matrix data is authenticated while consumed by the existing
independent evaluator. The direct native helper authenticates the exact ordered
generator bytes it decodes and multiplies.

The configured compiled helper is a trusted verification-library dependency;
its path is operator configuration, never proof-controlled data. The wrapper
retains strict request/output binding, canonical points/scalars, bounded output,
resource limits and failure propagation. An environment variable, arbitrary
binary path or JSON success field does not attest a binary's implementation.

## Evidence and limits

Only `retained_math_checks_composed` can become true after every required stage
succeeds. Independent Python generator MSM, complete/general proof acceptance,
complete IPA API verification, complete BitVM2 Script verification, production
assertion/UTXO/transaction binding and transaction-graph flags remain false.
The native helper executes IPA terminals, not a complete native Nova verify call;
the benchmark records zero complete native proof verifications by this command.

Small orchestration tests use clearly identified mocked internal computation
boundaries. They test policy-before-work, omitted coverage, identity mismatches,
sequential failures, receipt rejection and immutable results; their mocked
positive cases are not verification evidence. Actual matrix/generator payloads
and native execution are confined to the hosted workflow.

`bench_retained_verifier.py` loads small independently pinned fixtures directly,
calls the one sealed API and validates its summary before reporting. It accepts
only matrix directory, generator directory, configured helper and output paths;
it has no external report/receipt option. The existing native workflow retains
all earlier regressions and then runs this composition with a 512 MiB parent
address-space cap. The parent cap permits each existing helper's own 512 MiB
limit; it is not a claim about aggregate concurrent RSS. Worker CPU/wall/output
limits remain unchanged. No raw matrix or generator payload is downloaded to
the local PC or uploaded in artifacts.

Full source-port/proof-parser/hash/sponge and curve/MSM Script lowering, complete
dispute coverage, production single-assertion/signature binding and the Bitcoin
transaction graph remain future work. Mathematical composition does not close
those boundaries or establish deployability.

Hosted execution of this new composition remains pending.
