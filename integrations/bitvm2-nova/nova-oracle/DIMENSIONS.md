# Trusted verifier-key dimensions

The dimension exporter inspects the actual reconstructed, pinned Nova 0.76.0
verifier key. The existing full-key bincode SHA-256 check must succeed first.
It reads the outer arity, both R1CS shapes and IPA commitment-key capacities
through the published release's serde schema. It skips matrices, random-oracle
constants and generator elements rather than building another key-sized JSON
or byte array. Synthetic serializer tests check those skipped paths without
parameter reconstruction.

The hosted native workflow records the descriptor and SHA-256 of its canonical
JSON: sorted object keys, compact separators, ASCII escaping and UTF-8 bytes.
The descriptor is metadata, not a proof or a self-authenticating statement.
A caller must authenticate its exact bytes or expected digest independently.
An editable descriptor containing the correct verifier-key hash does not prove
that its dimensions came from that key.

The parser integration pins the descriptor obtained from successful
hosted reconstruction before admitting inner proof bytes. Provisional profiles
used in isolated tests are caller-owned test inputs, never inferred production
authority. The retained NHT4 fixture gate remains before inner decoding and
before any parameter reconstruction.

Native work stays hosted under the existing 3 GiB address-space and 600-second
verification limits. No proving, local Rust build, secret setup or changes to
the header prover's `k` are required. This exports dimensions only; complete
authenticated Script verification and the Bitcoin transaction graph remain
unfinished.
