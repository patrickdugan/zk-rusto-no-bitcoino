# ZKL-NOVA-18: measured Lean corpus import

## Result

The unchanged 30-rule kernel accepted **50 of 6,724 imported proof declarations, or 0.743605%**, after the importer's recorded preprocessing. **48 declarations passed the strict whole-declaration check, or 0.713861%.** The current arithmetic generator can accommodate 40 of the accepted certificates. Four selected certificates received full arithmetic assignment checks across all 1,712 of their rows.

The measured population combines 6,213 proof declarations from the public repositories listed in our owned corpus catalog with 511 fixed theorem constants from two solved-conjectures families. Every imported target proof passed a fresh Lean kernel recheck. The complete catalog's proof denominator remains unknown because source compilation and cohort selection constrain this run.

The strongest immediate follow-up is checked theorem-dependency import. Among the 3,860 proofs with fresh source builds, successful Lean rechecks, safe declarations and complete empty axiom audits, **411 have only observed theorem-dependency blockers**. Their dependencies include `congrArg`, `Eq.symm` and `Eq.trans`. Expanding their proof bodies will measure how many enter the existing fragment and what additional obstacles appear.

### Coverage

| Population | Imported proofs | Eligible native certificates | Strict whole-declaration acceptance | Eligible within current arithmetic capacity |
|---|---:|---:|---:|---:|
| Owned public sources | 6,213 | 50 | 48 | 40 |
| Two fixed solved-conjectures families | 511 | 0 | 0 | 0 |
| Combined | **6,724** | **50** | **48** | **40** |
| Combined percentage | 100% | **0.743605%** | **0.713861%** | **0.594884%** |

Owned-only native acceptance is 0.804764%. The combined percentage describes the imported cohort. The source selection, toolchain compatibility sweep, generated helpers and upstream curriculum fixtures all affect that cohort. Full-catalog coverage is explicitly `null` in the machine-readable report.

Evidence: [measured results](corpus_results/measured_corpus_results.json), [generated tables and accepted-source ledger](corpus_results/measured_corpus_results.md), [arithmetic audit](measured_arithmetic_audit.json).

## Source population and provenance

### Owned mathematical sources

DataGoblin collates repository inventories. Its own tracked tree contains no Lean source files. The intake begins with `training/data/owned_corpus_catalog.json` and `training/data/formal_game_catalog.json` at [MoralityLabAI/DataGoblin commit df662532](https://github.com/MoralityLabAI/DataGoblin/tree/df662532e5ddd645322f1aa1987bb0c8422873e9/training/data).

The historical owned catalog lists 21 repositories and 1,219 Lean files, without historical source commit pins. This run resolved the public repository heads and froze a new source reconstruction in [owned_sources.json](corpus/owned_sources.json). Every source is identified by repository, commit, path, Git blob SHA-1, byte count and SHA-256. The public cohort has 19 repositories. The private repositories `MoralityLabAI/complicency-bench` and `patrickdugan/semaev-index-calculus` are explicitly excluded; their source contents were never fetched for this published cohort.

| Source-stage measure | Count |
|---|---:|
| Public `.lean` blobs at the frozen source commits | 1,223 |
| Lean build configuration files | 6 |
| Actual Lean source files | **1,217** |
| Source files compiled successfully | **316** |
| Build errors | 889 |
| Wall-time limits | 2 |
| Files above the 256 KiB source budget | 10 |
| Compiled modules exported successfully | **316** |
| Final export batches | 47 |
| Value-bearing declarations exported | 11,276 |
| Proof declarations | **6,213** |
| Non-proof declarations | 5,063 |

The 6,213 proofs comprise 6,003 theorem constants, 208 proof-valued definitions and two opaque proofs. Every compiled module entered the final export. The integrity check also verified all 1,327 fetchable source and metadata files against their recorded sizes and hashes.

This was an unchanged-source compatibility sweep using Lean 4.24.0, commit `797c613eb9b6d4ec95db23e3e00af9ac6657f24b`. External packages were absent from that sweep. Missing packages, dependent-module errors, toolchain differences and source errors therefore appear among the 889 build errors. These outcomes remain in the source-build ledger. They cannot supply a proof denominator or an unsupported-expression count until those sources compile. Four public repositories produced no compiled source modules, leaving their proof counts unknown.

### Fixed solved-conjectures families

The formal-game catalog also identifies [1337isnot1337/solved-conjectures](https://github.com/1337isnot1337/solved-conjectures/tree/e1cf80b80c2fe9d22d83f1dc3673410a2ac1bf2e), pinned to `e1cf80b80c2fe9d22d83f1dc3673410a2ac1bf2e`. Its primary source inventory contains 5,215 `.lean` paths under `lean/`. This run used two existing fixed family inventories, selected before compilation:

| Family | Selected source modules | Selected theorem constants | Lean rechecks passed | Native accepted |
|---|---:|---:|---:|---:|
| Feldheim weighted tail | 20 | 161 | 161 | 0 |
| Fan–Tringali power monoid lengths | 18 | 350 | 350 | 0 |
| Total | **38** | **511** | **511** | **0** |

The 511 constants include compiler-generated helpers. They count as declarations; the run makes no claim that they represent 511 independent mathematical problems. The collector retains every selected name in the denominator, including names whose extraction would fail.

Both families were freshly compiled under Lean 4.35.0, commit `eb6cafb7290e8bd5f2937522d8d804f58f02bafc`, with Mathlib pinned to `56a005855ea17e0b0958f73ec801ae140b0a1679`. The source compilation, upstream scoped audits, stock-kernel replay, export and per-declaration checks passed. External dependency objects came from the pinned upstream cache; this run independently rebuilt the selected source families. The existing DataGoblin intake remains in its unreviewed quarantine state, with no change to training admission.

The exact inventory and verifier controls are in [solved_conjectures_manifest.json](corpus/solved_conjectures_manifest.json). [Hosted run 45645867110](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45645867110) passed on implementation commit `6dcffba13f360d04ae494f86407f397c445e036e`. Its resource measurements and artifact checks are retained in [hosted_run.json](corpus_results/hosted_run.json).

## Import and acceptance policy

The exporter records the original Lean `Expr` and `Level` DAGs, exact names and binders, universe arguments, declaration kind, owning module, source hashes, safety and transitive axiom audit. It keeps the goal and proof roots separately. Shared nodes are counted once within each declaration's exported DAG.

The original expression population contains **2,052,339 Expr nodes** and **14,397 Level nodes**. The goal-reachable total is 372,162; the proof-reachable total is 1,969,302. Those reachable sets overlap. Shared terms can also recur in separate declarations, so these totals describe exported records.

The importer attempts the complete declaration against the existing eleven-entry fixed environment. A primitive is admitted only when its instantiated Lean type matches the verifier-owned signature. Declared symbolic universe parameters remain part of the whole-declaration check, even where a special instance would simplify the example. Exported theorem dependencies currently contribute signatures; importing their proof bodies is the next feature.

Permitted preprocessing records metadata removal, let expansion, bounded natural-literal expansion and closed-definition expansion. Original proof and goal hashes stay attached to every result. Strict acceptance requires that the original declaration already fit without those preprocessing events. The two additional accepted declarations used a recorded expansion of `LBF17AbstractInterp.SubsetPred`:

| Declaration | Native certificate rows | Within current capacity |
|---|---:|---|
| `LBF17AbstractInterp.subset_refl` | 347 | Yes |
| `LBF17AbstractInterp.subset_trans` | 1,353 | No |

For each representable declaration, a separate reference inference checks that the goal is a proposition and that the proof has that goal. The certificate builder then emits native rows. Replay reconstructs the exact proof, followed by another reference check. All 50 representable declarations passed this path. Their certificates contain **36,410 rows**, with individual sizes from **33 to 2,332**.

An eligible acceptance additionally requires a fresh source build, verified module/source binding, successful Lean recheck, safe declaration and complete empty transitive axiom audit. All 50 native acceptances meet these requirements. The kernel source and fixed environment remain byte-identical to the stage-17 baseline at `6b3730e23e2f647a5dbd8d9fec072a9ff9f344b0`.

### Resource bounds

| Bound | Value |
|---|---:|
| Expanded natural literal | At most 32 |
| Lowered term depth | At most 72 |
| Lowered term nodes | At most 10,000 |
| Raw traversal depth | At most 256 |
| Definition expansion depth | At most 16 |
| Native relation row limit | 20,000 |
| Native worker time | 3 seconds per declaration |
| Aggregate worker budget | 120 seconds per lane |
| Lean kernel recheck | 2,000,000 heartbeats per declaration |
| Current arithmetic generator capacity | Strictly fewer than 1,024 rows |

Timeouts and traversal limits have separate labels in the results. Conversion features such as eta and proof irrelevance cannot be inferred from the exported expression syntax alone; this run records their use as unassessed.

## Unsupported expression histogram

The following histogram counts proof declarations carrying each remaining blocker after attempted permitted preprocessing. Labels overlap. A single proof can require an inductive type, its constructor, a recursor and a projection; summing the rows would count that proof repeatedly.

| Remaining blocker | Proof declarations |
|---|---:|
| Unknown constants / unavailable declaration bodies | **6,571** |
| Unsupported inductives | **6,086** |
| Unsupported constructors | **5,825** |
| Unsupported recursors | **4,916** |
| Projections | **4,553** |
| Symbolic universes | **952** |
| Natural literal above the expansion cap | **733** |
| Explicit axiom encountered during lowering | 321 |
| Importer resource limits | **240** |
| Unsupported primitive universe instance | **222** |
| Quotients | **209** |
| Direct propositional extensionality | 110 |
| String literals | 67 |
| Direct function extensionality | 44 |

`unknown_constant` and `definition_unavailable` each occur on the same 6,571 declarations. The 222 proofs with unsupported primitive universe instances also carry `primitive_signature_mismatch`. All affected proofs passed the Lean kernel recheck. Retained instance details identify `Eq` at carrier universe 0 or 2 on 107 declarations, beyond the current fixed carrier universe 1: 63 record `Eq.{0}`, 89 record `Eq.{2}`, and 45 record both. The other 115 affected declarations reached the 200-entry detail cap before retaining an instance. The generated JSON keeps the separate blocker labels, recorded instance details, original histogram and histogram after preprocessing.

The largest counts describe a connected dependency problem. They do not establish the incremental acceptance gain from implementing any one rule. The feature analysis therefore also identifies narrower cohorts whose observed remaining blockers permit a bounded next experiment.

## Next implementation selected by the data

### First: checked theorem-dependency import

The final fully eligible population contains **3,860 proofs**. Within it, **411** have only observed theorem-dependency blockers. The current signatures identify the following references:

| Theorem dependency | Proof declarations in the 411-case cohort |
|---|---:|
| `congrArg` | 395 |
| `Eq.symm` | 249 |
| `Eq.trans` | 73 |
| `BPD.OptimalBasis.conjugate_mask_iff_commute` | 1 |
| `Iff.mpr` | 1 |

Counts overlap. The kernel already implements equality transport, so these equality dependencies provide a concrete first test of importing real theorem bodies into the existing relation.

The next stage should export each needed theorem body from the pinned Lean environment, preserve its source and universe arguments, and recursively collect its dependencies with explicit limits. The importer must check the resulting proof term before using it. Each successful result should retain its original declaration identity and report the additional rows and newly exposed blockers. Running this change against the frozen 411 cases will provide an observed acceptance delta.

The 411 cases are a probe cohort. Their dependency bodies can introduce further features or exceed resource bounds. A theorem's type by itself supplies no evidence that the fixed kernel can derive it.

### Broader kernel work: inductives and projections

The overall histogram places inductive types, constructors, recursors and projections at the center of the coverage gap. Even within the fully eligible population, 3,264 proofs carry an extra-inductive blocker and 2,020 carry a projection blocker. The next kernel design should derive an initial declaration set from the most frequent actual dependencies, then add checked declaration formation and the corresponding elimination and computation rules.

Each such extension needs its own authenticated environment representation and arithmetic checks. The measured dependency graph can determine which connected set of declarations to implement first. The source cohort and strict/preprocessed acceptance split should stay fixed for each comparison.

### Universes and numeric bounds

**66 fully eligible proofs have only observed symbolic-universe blockers.** This gives universe support a separate probe cohort. An additional 55 fully eligible proofs contain unsupported ground `Eq` instances: 13 at `Eq.{0}` and 42 at `Eq.{2}`. The overall proof count carrying this blocker is 222, including proofs outside the empty-axiom population and proofs with additional blockers.

The current natural-literal cap affects 733 proofs, and **zero proofs have that cap as their sole observed blocker**. A cap increase therefore has no isolated-case gain demonstrated by this run. Resource-limit failures should be retested under a separately declared budget when a concrete source justifies the cost.

## Axioms and repeated declarations

The transitive axiom audit completed for **6,682** of the 6,724 imported proofs. The remaining 42 bounded audits belong to the Feldheim family, and each already records `propext`. All owned proof audits completed.

| Observed transitive axiom | Proof declarations |
|---|---:|
| `propext` | 2,844 |
| `Quot.sound` | 2,227 |
| `Classical.choice` | 558 |
| `UTXORefAxioms.sha256_binding` | 4 |
| `UTXORefAxioms.signatures_unforgeable` | 2 |
| `sorryAx` | 0 observed |

These labels overlap. Bounded audits can omit further dependencies. The direct-expression histogram and the transitive-axiom histogram answer different questions, so their counts remain separate.

Raw proof/goal receipt fingerprints and exact exported-structure fingerprints both identify **6,638 unique pairs** among 6,724 declarations. There are 43 duplicate groups containing 129 declarations, for a duplicate excess of 86. Among the 50 accepted declarations, there are 49 unique raw pairs and 45 unique lowered fixed-kernel pairs. Exact structural fingerprints preserve binder names and universe context while ignoring local DAG numbering and sharing.

The coverage denominator remains declaration-based. Fingerprints identify repeated representations; independent mathematical problem families require additional provenance. The accepted ledger includes existing upstream curricula, source test fixtures and generated helpers. Newly authored importer tests contribute zero corpus observations.

## Arithmetic sample

Four actual source-bound certificates were selected before the successful arithmetic run. Each passed full evaluation under the unchanged stage-17 authenticated matrix:

| Declaration | Rows checked |
|---|---:|
| `fc11_native_prop` | 33 |
| `thm_bpd2_exact_d1_r0_pos` | 372 |
| `thm_bpd2_exact_d2_r0_pos` | 549 |
| `thm_bpd2_exact_d3_r0_pos` | 758 |
| Total | **1,712** |

The matrix has **41,406 constraints**, **40,263 wires** and **1,021,954 nonzero entries**. Its SHA-256 is `c583f594c0757e1910ec667c13e27ca081778e4167fed58188d1ea9d1dc12c04`. These four certificates exercise 17 of the 30 rule tags, with zero equality-iota or Nat-iota rows. Stage-17's fixtures provide the separately recorded evidence for those rules. The run also rejected 16 direct mutations and 40 regenerated invalid assignments, and performed 1,024 boundary checks.

The successful process took 990.317 seconds with peak RSS 775,216 KiB. The arithmetic batch took 983.068 seconds, or 0.57422 seconds per row when amortizing matrix construction and rejection checks across the batch. An earlier process received SIGKILL after 25.194 seconds at peak RSS 1,748,152 KiB; the operating-system reason is unavailable. Conservative accounting for the bounded experiment totals 1,197.447 seconds within the 1,200-second budget. Enforcement was external monitoring; the helper itself has no automatic wall timeout.

The arithmetic receipt preserves an earlier observation snapshot of 49 eligible native certificates and 39 within capacity. The final source recheck refresh raises those counts to 50 and 40. [refresh_audit.json](corpus_results/refresh_audit.json) maps the four checked semantic certificates exactly to their refreshed provenance. Their arithmetic rows were unchanged.

For the final cohort, **four certificates have actual arithmetic checks, 36 have capacity-only evidence, and ten exceed the current capacity**. This stage generated zero new recursive or compressed Nova proofs. The earlier stage-17 proof receipts remain their own experiment.

Evidence: [selection](measured_arithmetic_selection.json), [arithmetic results](measured_arithmetic_results.json), [cost and integrity audit](measured_arithmetic_audit.json).

## Implementation and validation

`corpus_collect.py` verifies the exact source inventory and rehashes files before compiling. It clears its dedicated generated-object directory for a fresh build, schedules local dependencies, bounds captured output and kills timed-out process groups. `corpus_owned_export.py` partitions the successful modules, refines batches when imports collide, and checks exact module ownership and source/object hashes.

`corpus_export.lean` handles the Lean 4.24 and 4.35 kernel APIs. During the first measurements, a heartbeat accounting error caused successful source proofs to fail repeated rechecks. The original implementation passed an absolute two-million-heartbeat limit while repeated checks shared a thread's cumulative kernel counter. Each recheck now runs in a fresh dedicated thread under the same two-million-heartbeat limit. The regression reproduces the cumulative failure after 2,560 checks, confirms successful isolated checks, and confirms that a one-heartbeat budget still fails.

All 47 owned lanes were refreshed. Across all 11,276 value-bearing declarations, the comparison preserves original proof/goal hashes, node counts, lowered terms, native reference outcomes, replay outcomes and row counts. The semantic payloads of all 50 native certificates also match after excluding refreshed source metadata. Of the initial recheck errors, 3,222 declarations changed to passed, including 2,040 proofs. One already-representable proof gained eligibility, yielding the final 50 accepted declarations. The 81 remaining recheck errors concern non-proof declarations; every imported target proof now passes.

`corpus_import.cjs` streams compact aggregate state so the 47-lane corpus can aggregate within a 256 MiB Node heap. A memory measurement on the initial 47-lane exports, before the heartbeat refresh, used 284,932 KiB process RSS and took 13.72 seconds. Its output matches the previous full-retention implementation on those same inputs. `measured_feature_priorities.py` and `measured_corpus_report.py` rejoin the exact source manifests, target lines, selected declaration names and result hashes before calculating tables.

Validation passed for the 30 importer checks, five runner tests, four feature-analysis tests and structural-fingerprint self-test. Test records explicitly count as zero corpus observations. The hosted solved collector additionally exercised missing/duplicate/foreign declaration rejection, path alias and escape rejection, and nested-process timeout cleanup.

The final [corpus CI run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45645867110) and [Rust CI run](https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45645867082) both passed on `6dcffba13f360d04ae494f86407f397c445e036e`. All 118 recorded artifact hashes were independently verified after download. The hosted archive is 20,430,324 bytes with SHA-256 `dc6dce044d536dff326a89bb888c6610b6a11aa0778bb6f54605287d2ebfbd81`.

## Reproduction and retained evidence

The evidence archive preserves the final owned exports, original source files, source/build receipts, compiled objects and logs, together with the exact hosted solved-corpus archive. It also includes the feature analysis, the final compact report, the heartbeat-refresh audit, and the original inputs that authenticate the earlier arithmetic sample. Every archived file has a SHA-256 entry in the archive manifest.

To rebuild the owned source sweep, run these commands from the repository root with an installed Lean 4.24.0 executable. Choose a new work directory because the collector deliberately clears its generated-object tree before compiling:

```bash
export ZKL18_LEAN=/absolute/path/to/lean-4.24.0-linux/bin/lean
export ZKL18_WORK=/absolute/path/to/new-owned-run
python3 integrations/zklean-nova/corpus_collect.py \
  --manifest integrations/zklean-nova/corpus/owned_sources.json \
  --work-dir "$ZKL18_WORK" --lean "$ZKL18_LEAN"
python3 integrations/zklean-nova/corpus_owned_export.py \
  --build-receipt "$ZKL18_WORK/build_receipt.json" \
  --source-manifest integrations/zklean-nova/corpus/owned_sources.json \
  --output "$ZKL18_WORK/export_final" --lean "$ZKL18_LEAN" \
  --budget-seconds 1200 --batch-seconds 120
```

The solved-source workflow in [zklean-corpus.yml](../../.github/workflows/zklean-corpus.yml) pins its own compiler, source commit, package lock and verifier inputs. It runs both fixed families in one bounded CPU job.

To regenerate the compact analysis from retained evidence, extract the hosted solved ZIP into a directory and provide the two final export roots:

```bash
python3 integrations/zklean-nova/measured_corpus_report.py \
  --owned /absolute/path/to/owned/export_final \
  --owned-build-receipt /absolute/path/to/owned/build_receipt.json \
  --solved /absolute/path/to/extracted-solved-corpus \
  --json-out /absolute/path/to/regenerated-results.json \
  --markdown-out /absolute/path/to/regenerated-results.md
```

Local path fields will follow the evidence location. The source hashes, cohort membership and numerical measurements must agree. The archived arithmetic selection identifies the original certificate bytes; refreshed certificates carry different provenance bytes. Repeating that exact arithmetic sample requires restoring its preserved input layout or creating a separately recorded selection against the refreshed certificates, with an external timeout such as `timeout 20m`. The archive retains the original inputs and audit so the completed sample can be verified without paying its arithmetic cost again.
