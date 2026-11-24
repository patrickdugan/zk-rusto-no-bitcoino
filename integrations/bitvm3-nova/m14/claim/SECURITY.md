# M14 claim artifact format v1

This crate hardens the off-chain boundary around one fixed garbled verifier. It creates a fresh
garbling, retains its artifacts, commits to the statement and circuit, and releases labels for
one proof input. Its CPU tests use a one-gate circuit through the same transport as the M14 CLI.

## Roles and commands

Build the CLI with Rust 1.90.0:

```sh
cargo +1.90.0 build --release --locked \
  --manifest-path integrations/bitvm3-nova/m14/e2e/Cargo.toml --bin m14-claim
```

The following commands describe a full M14 run. Setup writes about 12.7 GB of ciphertexts and
553 MB of input commitments. Each release writes about 138 MB of selected labels. Run setup
only on a machine with sufficient disk and RAM. It performs garbling of the existing fixed
verifier; it does not generate a new Nova/SP1 proof.

```sh
m14-claim setup statement.json claim-public claim-private
# Record manifest_sha256 from this agreed setup in the claim protocol.

m14-claim verify-artifacts claim-public MANIFEST_SHA256
m14-claim release claim-public MANIFEST_SHA256 claim-private proof.bin claim-release
# Record release_sha256 from the agreed release.

# On the evaluator's machine, with only the public directory, proof and release directory:
m14-claim evaluate claim-public MANIFEST_SHA256 proof.bin claim-release RELEASE_SHA256 result.json
```

Supply the manifest hash through an authenticated channel or protocol commitment established
before evaluation. A hash supplied alongside attacker-controlled files has no independent
authority. The CLI requires the pin separately and checks it against the parsed, canonical
manifest before loading artifacts. It also checks the manifest's circuit identity against the
locally supported build. Source files and Cargo.lock contribute to that identity, so all parties
must use the agreed build. The evaluator also requires an independently agreed release hash.
The release command prints it after publishing the selected labels and their header. This pin
authenticates the exact proof-file hash and the selected-label file digest. It must be delivered
through an authenticated channel or protocol commitment, with the same care as the setup pin.

`claim-private` belongs to the garbler. It contains a fresh 32-byte OS-generated seed and, after
the first release attempt, a durable reservation. The evaluator accepts selected 16-byte labels,
public constant labels and a public AES salt. Its input type cannot store paired labels.

Private state creation and release currently require Unix permissions and directory fsync support.
Use Linux or WSL. The directory is created and checked for mode 0700 (non-symlink) and private
files are created and checked for mode 0600 (non-symlink); regular artifact and JSON readers use
`symlink_metadata` plus `O_NOFOLLOW` so symlinks inside artifact directories are rejected. Secret
seed buffers and private JSON reads are zeroized on drop. The CLI does not accept secret seeds in
process arguments. Existing output files/directories are refused.

## What the manifest binds

The v1 manifest contains the protocol version, a fresh instance ID, exact statement pins,
circuit/source/reference identities, input and ciphertext counts, the hasher version and public
salt, active constant labels, file lengths and SHA-256 digests, and SHA-256 commitments to the
accept/reject output labels. The statement uses the existing JSON fields and requires all four
digests to be exactly 32 bytes. Field digests must contain eight canonical KoalaBear limbs;
accepted execution status is exit code 0 and completeness 1.

The manifest hash is SHA-256 of `m14-claim/manifest/v1` followed by a zero byte and compact
`serde_json` serialization of the typed manifest, in declared field order. Byte arrays serialize
as decimal arrays. Unknown and duplicate fields are rejected. Whitespace in the input file does
not change this hash. Hex spelling inside statement strings is preserved and therefore changes
the manifest hash when spelling changes.

Ciphertexts and selected labels use 16-byte little-endian encoding. Artifact SHA-256 is the
ordinary hash of all file bytes. The old CLI's chained BLAKE3 accumulator uses another encoding;
its reports cannot serve as v1 manifests.

Input commitments contain two 32-byte hashes per input wire, ordered false then true. Each hash
binds the domain `m14-claim/input-label/v1` plus a zero byte, the instance ID, the little-endian
u64 wire index, one bit byte (0 or 1), and the 16-byte label. The evaluator derives the choice
from the proof's canonical circuit inputs and checks every selected label against this file.

The input digest binds `m14-claim/input-bits/v1` plus a zero byte, the little-endian u64 bit count,
and packed bits in least-significant-bit-first order, with zero padding in the final byte.
The exact proof file has a separate SHA-256 digest. M14 derives some redundant transcript
values (such as sumcheck claimed sums and evaluation points) instead of taking them as circuit
inputs, while unused trailing public-value slots are rejected if non-zero during shape validation.
Leaving derived transcript values out of shape validation ensures a malformed proof still reaches
garbled evaluation and produces a slashable `reject` verdict, while `accept` attests existence of a
valid wrap proof matching `input_sha256` and `statement`. Output-label commitments use raw
16-byte SHA-256 digests (`SHA256(label_le16)`) for direct `OP_SHA256` Tapscript compatibility.
The release-header hash is SHA-256 of `m14-claim/release/v1` plus a zero byte and compact typed
JSON serialization, using the same conventions as the manifest. The header binds the instance,
manifest hash, proof-file hash, canonical input hash and selected-label artifact. This separate
pin prevents substituting a different proof file that produces the same circuit input bits by
rewriting an otherwise unsigned header. Evaluation reports include both agreed hashes.

## Single-use release and recovery

A fresh garbling is required for every different proof. Revealing opposite labels from one
Free-XOR wire can reveal the global delta. The release operation reserves the instance for both
the proof-file hash and canonical input hash before writing its first selected label. It creates
the reservation with exclusive creation, syncs the file, then syncs the private directory.
Concurrent attempts for different proofs produce at most one successful release.

An identical retry can write to a new release directory. A crash after reservation preserves
the original proof choice. A partial or unreadable reservation locks the instance. Create a
fresh setup when recovery cannot establish the original binding. Keep the reservation with the
seed in backups; restoring old state or copying a seed into another private directory can
bypass a local single-use record. The journal assumes an honest operator and durable local
storage. A malicious garbler can retain or reuse its own secrets.

Files are synchronized before their manifest or release header is published. An interrupted
directory without its final JSON header is incomplete and must not be advertised. These writes
are append-free and never overwrite an existing artifact. Partial directories can be archived
for diagnosis; retry into a new directory.

## Integrity checks and resource bounds

JSON files are capped at 64 KiB. The CLI caps proof files at 8 MiB and validates the pinned proof
shape before constructing circuit inputs. Circuit counts come from the locally supported spec;
untrusted manifest counts cannot increase them. The library additionally caps inputs at ten
million bits and ciphertexts at one billion records.

Each artifact must have its exact committed length. Reads check truncation, trailing bytes,
complete consumption and SHA-256. Ciphertext integrity is checked before circuit execution,
using the same open file that evaluation consumes. Evaluation hashes it again while consuming
it, so an in-place change after preflight produces an error before an output report is returned.
Input commitments and selected labels are fully checked before evaluation. IO errors and
output labels that match neither outcome return errors. A well-formed false circuit input can
still produce the committed reject label.

## Remaining protocol obligations

The manifest commits to a claimed circuit. Establishing that an adversarial garbler constructed
that circuit requires a verified setup protocol, such as cut-and-choose with consistent input
labels or a separately reviewed soldering certificate. Input-label commitments alone cannot
establish that fact. The garbler knows both output labels, which also means the setup protocol
must account for who can submit a reject-label witness.

This change does not create Bitcoin transactions, implement a dispute graph, guarantee artifact
availability, or prove application semantics for Ark/Cashu. The fixed M14 circuit keeps its
existing proof-verification semantics. A future BABE/Nova certificate must define its own
statement and privacy requirements before it can discharge the remaining setup obligation.

## Bounded tests

```sh
cargo +1.90.0 test --locked \
  --manifest-path integrations/bitvm3-nova/m13/statement/Cargo.toml
cargo +1.90.0 test --locked \
  --manifest-path integrations/bitvm3-nova/m14/claim/Cargo.toml
```

The transport tests cover a fresh evaluator process with private state removed, accept/reject
outputs, artifact damage and missing files, manifest and proof binding, crash reservations,
concurrent release attempts, public-path replacement, in-place mutation after preflight, and
private-file permissions. The ignored child test is launched and checked by its parent test.
The existing full M14 circuit/garbling suites remain separate integration gates.
