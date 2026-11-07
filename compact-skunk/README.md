# compact-skunk

Research handoff for Mythos: compactify transparent Nova/Spartan/IPA verification
for the existing non-interactive BitVM2 dispute model.

**Start with [MYTHOS.md](MYTHOS.md).** It contains the task, mathematical target,
source map and acceptance tests. [RESEARCH.md](RESEARCH.md) develops the design
lanes and names upstream implementations worth inspecting. [RESULTS.md](RESULTS.md)
records the checks executed while preparing this packet.

The working baseline is commit `55e52156f800f0f39e4bc04ff76103c14633b273`.
[PR #22](https://github.com/patrickdugan/zk-rusto-no-bitcoino/pull/22) remains a
separate sensitivity study. This folder runs independently of that branch.
Existing provers and `integrations/bitvm2-nova` remain unchanged.
Concurrent M24 hash work at `8dcfd2f` is mapped in RESEARCH.md and preserved.

## Run from the repository root

```sh
python -m unittest discover -s compact-skunk -p 'test_*.py' -v
python compact-skunk/lab.py --check-upstream . --output compact-skunk/local-results/report.json
```

Python 3.10+ and the standard library suffice. The upstream check requires the
exact Git blob of `msm_projection.py`; source drift fails before import. Refresh
pins deliberately after reviewing a changed baseline. The dedicated CI job runs
only these checks, with a five-minute limit.

`lab.py` reproduces the cost projection, counts point-valued dependencies across
cuts of a small bucket-addition graph, and exposes the IPA coefficient identity
for toy-field experiments. It leaves Script costs unknown for new designs.
Tests include exhaustive tiny digit schedules and coefficient vectors, plus a
broken-join example. All toy group elements have public discrete logs.

Copy `experiment-template.json` for each measured candidate. Keep local outputs
under `local-results/` until their source, scope and command have been recorded.
Research code and results should stay under this folder; preserve concurrent
work elsewhere in the repository.
