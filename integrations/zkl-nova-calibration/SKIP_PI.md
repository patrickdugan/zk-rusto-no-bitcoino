# ZKL-21: authenticated public context jumps

ZKL-20 verified both capacity profiles (raw 25952 constraints/step at depth6, 36386 at depth9; six small proofs, one 270-row stress proof). The new profile extends the public arena with structural records [7+e, source_ctx, ancestor_ctx], e=1..8, for 2^e parent traversals. Host admission independently walks the already validated public parent chain and rejects every invalid record, including targets outside a nonempty context. This is a structural trusted host operation, not an in-circuit proof of pointer construction. All object IDs, tags, metadata and proof rows are bound by domain-separated Poseidon commitments. The new selector checks the jump flag, source context and distance derived from the authenticated tag, then requires a prior RawLookup(target, i-distance, A). All arithmetic is bounded; prior row indices are range-constrained. Unit lookup and all original bulk lifting rules remain.

Proof sketch: a correct jump is an abbreviation for 2^e unit parent lookup steps. Expanding every jump gives an ordinary ZKL-20 derivation, independently replayed by the native checker. With a full admissible set of binary jumps, greedy decomposition takes popcount(i) transitions instead of i, plus the base row; memoization can already share unit suffixes, so savings in a DAG need empirical measurement. The generator rewrites an existing valid bulk DAG and prunes only unused lookup rows, so on that input its row count cannot grow. Adds public metadata and host structural work. The new circuit includes a separate rule and tag/distance constraints; raw costs remain unmeasured until CI. No private arena or semantic compiler claim, no general Lean/kernel or production soundness claim.

## Local native results

576 paired generated exercises. First two cohorts reuse ZKL-20 seeds, third is disjoint public diagnostic (42000/43000/44000 plus 0..63). All old certificates and expanded new certificates replayed; every new local equation checked. 500/576 shorter, 76 equal. 44,495 coherent different-signature prior-row substitutions in six small fixtures plus stress rejected by integer equations; 66 false structural jumps rejected by public admission. Six small certificates 189 ->187 rows. Stress 270 ->240 rows, objects 112->131. Fixed stress is the same already-inspected seed23004. CI runs both depth6 and depth9 profiles.

| cohort | rows bulk->skip | public objects bulk->skip | fit64 | fit128 | fit256 |
|---|---|---|---|---|---|
|22000|22135->19491|9701->11320|62->69|119->137|173->189|
|32000|22424->19722|9835->11498|60->65|120->138|176->183|
|42000 fresh|23127->20244|10066->11784|59->67|115->130|172->184|

All 576 fit 512 slots. Across fresh cohort weakening 4381->3507, dependent application 11975->10874, conversion 6771->5863. Public metadata is selected by the witness generator, then independently validated and committed as part of the public statement. It can expose which context hops the prover uses. No witness privacy, no sealed confirmation or neural training. Native result is not an actual cryptographic timing measurement. Source and rules are pinned by local byte hashes and CI regenerates fixtures/results.
