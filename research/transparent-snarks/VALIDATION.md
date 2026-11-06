# Validation record

Date: 2026-11-05.

- Python 3.13.5, Linux sandbox. Standard library only.
- `python3 -m unittest discover -s research/transparent-snarks -p 'test_*.py' -v`: **46 tests passed**.
- Default plan accepted; matrix generated with **12 cases**.
- Canonical plan SHA-256: `d4b39d8000960577fde730d65cdfba5bc82e4d5900078a5316ca1f3c90c8fa37`.

Tests cover ceremony-dependent wrapper rejection, altered curve/backend
labels, missing compression, source-pin drift, wrong network/statement,
explicit checkpoint trust, resource-plan bounds, and malformed JSON.
These tests validate configuration and planning behavior.

No Rust compilation, cryptographic proof generation, restart proof test,
or RAM benchmark was run for this package. The sandbox could not resolve
github.com for a local clone; repository source was inspected through the
GitHub connector. A new feature branch preserves the inspected main tree.
Existing feature-branch performance reports remain historical evidence.

The added CI workflow runs the same offline checks. Its remote outcome
must be read from GitHub Actions; a local pass does not establish CI status.
