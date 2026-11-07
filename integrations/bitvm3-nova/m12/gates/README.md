# M12 gate costs

Non-free (AND/OR-class) gate counts of hash/field primitives for a STARK/FRI verifier, measured by
building each circuit with fresh input wires and checking it against a native reference. Counts come
from ExecuteMode `gate_count.nonfree_gate_count()` and are cross-checked against the number of
ciphertexts GarbleMode emits. Results: `RESULTS.json`.

Reproduce (Windows):

    $env:RUSTUP_TOOLCHAIN='1.90.0-x86_64-pc-windows-msvc'
    $env:CARGO_TARGET_DIR="$env:LOCALAPPDATA\Temp\m12-gates-target"
    & "$env:USERPROFILE\.cargo\bin\cargo.exe" test --release --manifest-path nova-bitvm3/m12/gates/Cargo.toml -- --test-threads=1 --nocapture

`M12 ... nonfree=N` lines are printed; every N is also asserted.
