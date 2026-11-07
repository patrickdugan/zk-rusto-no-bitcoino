# Executed preparation checks

Date: 2026-11-07. Environment: isolated Linux CPU sandbox. Python standard library.

**22 unittest methods passed.** The exhaustive bucket test covered all 256
four-digit schedules over digits 0..3. The tensor identity test covered all
216 triples of nonzero challenges in F_7. Invalid dimensions, canonicality,
missing sources, source drift, malformed graphs and broken joins have checks.

The arithmetic baseline matched a materialized copy of the fetched upstream
`msm_projection.py`. Its Git blob SHA-1 was verified before import:
`ed86b1b20ea37bac1e368e2aa4fbf72631e41852`.
Both role dictionaries and aggregate Script/signature estimates matched exactly.

Commands:

```sh
python -m unittest discover -s compact-skunk -p 'test_*.py' -v
python compact-skunk/lab.py --check-upstream REPO_ROOT --output local-results/report.json
```

In the preparation sandbox, REPO_ROOT pointed to the verified source snapshot.
The CI command uses the actual checkout root. The Git blob hash is a source
identity check, not a cryptographic proof receipt.

## Deterministic cut census

One window over 128 chosen digits. Each exposed point costs an illustrative
19 u32 words at 200 signature bytes per word. Generator constants, selector
checks and internal field constraints are outside this toy graph.

| Window bits | Additions | Adds/chunk | Unique signed point values | Peak live points at a cut | Raw port signature bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 | 102 | 16 | 19 | 3 | 72,200 |
| 2 | 102 | 64 | 4 | 3 | 15,200 |
| 4 | 150 | 16 | 94 | 15 | 357,200 |
| 4 | 150 | 64 | 29 | 15 | 110,200 |
| 6 | 252 | 16 | 141 | 64 | 535,800 |
| 6 | 252 | 64 | 95 | 64 | 361,000 |

These measurements count a specific dependency graph. They expose state that
a constant-width boundary estimate omits. They do not constrain every possible
schedule or authenticated-memory design. The chosen four-bit, 64-addition
chunks require as many as 5,320 raw WOTS witness items under this model, before
other witnesses. That raw format needs redesign before it can satisfy the
1,000-item Tapscript limit.

One test exhibits locally correct transitions `(3 -> 5)` and `(9 -> 11)` under
`x -> x+2`, with an inconsistent join. It is a counterexample to accepting local
relations without shared state identity. No actual signature forgery is tested.

## Execution scope

No new cryptographic proof, Pasta benchmark or Bitcoin Script was executed.
The packet contains no completed compact verifier and makes no new security
claim. Unknown candidate costs remain null. No upstream proof backend was built;
no Bitcoin transaction was created or broadcast. Hosted CI status is external
to this preparation record and must be read from the run for the pushed commit.
