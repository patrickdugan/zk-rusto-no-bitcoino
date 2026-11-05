# M2 follow-up: independent checks and exact witness length

The first M2 CI run (42031938546) passed all 49 Python tests and reproduced the
local fixture SHA-256. Rust compilation exposed an error-conversion issue in the
harness. Commit a08bc5b fixes it.

The second run (42032381979) compiled successfully and passed all 74 independent
halo2curves comparisons, including 14 expected rejections. Its Script phase
panicked inside upstream OP_PICK at src/lib.rs:800. The pinned interpreter checks
an index against the stack length before popping the index; the following
unchecked lookup can panic on a truncated initial witness. That run is a failure
and establishes no successful complete Script-vector run.

Every M2 leaf now starts with `OP_DEPTH <expected words> OP_EQUALVERIFY`, before
any indexed opening lookup. The new test covers empty, truncated, prepended and
appended witnesses for both predicate directions and both fields. The upstream
interpreter source is unchanged. Panics remain fatal; the harness does not catch
or count them as successful rejection. The Python interpreter gains OP_DEPTH;
existing M1 arithmetic scripts and their byte sizes are unchanged.

Updated exact compiled sizes with the arity guard (superseding M2.md's initial
size table):

| Operation, either field/curve | Leaves | All disproof Script bytes | Largest leaf | Peak reference stack |
| --- | ---: | ---: | ---: | ---: |
| Multiplication | 274 | 1,268,152 | 4,904 | 215 |
| Complete affine point addition | 3,616 | 16,554,753 | 4,904 | 215 |

The regenerated 10,884-vector fixture is 97,846,952 bytes with SHA-256
`5113594145038ed7cb84de0f10e89993c7c9e42ef6039d31e915013828e35eae`.
The 74 curve vectors are unchanged. One new regression test makes 50 total
Python tests. Local fixture generation took 15.2382 seconds and peaked at
160,555,008 bytes RSS. These are fixture-generation measurements, with no
OS-enforced memory ceiling and no full Nova proving run.

The initial `results/m2-local-evidence.json` remains a historical record of the
pre-guard source and measurements. GitHub Actions artifacts record each later
run's exact source revision and outputs. Complete independent Script execution
must be confirmed from the latest successful job, rather than inferred from the
curve comparisons or Python tests.

All production boundaries in M2.md still apply, including dynamic assertions,
on-chain malformed-state dispute coverage, the production Nova transcript and
the Bitcoin transaction graph.
