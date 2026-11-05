"""Bounded native model of Nova 0.76.0's non-EVM Keccak transcript.

This is the production transcript *algorithm*, not a complete Nova verifier or
a Bitcoin Script Keccak implementation. Protocol callers must absorb precisely
the objects and labels required by the production verifier. No extra binding is
invented here. The EVM feature has different encodings and is not supported.

Source: crates.io nova-snark 0.76.0, src/provider/{keccak,traits,pedersen}.rs.
Crate SHA256: c9bb3809a6c70057ea722c1c4fe5097cf29a3479d0b4671f3cddb1d81043bb31
Crate VCS: 98576efa884072bfe69bfad8f275a3a5cd8754e5.
"""
from Cryptodome.Hash import keccak
from script import P, Q

MAX_LABEL = 1024
MAX_BUFFER = 1 << 20
MAX_SCALARS = 4096
MAX_ROUND = (1 << 64) - 1
ENGINES = {"pallas": (P, Q), "vesta": (Q, P)}


def _bytes(value, limit, name):
    if type(value) is not bytes or len(value) > limit:
        raise ValueError(f"invalid {name}")
    return value


def keccak256(data):
    """Keccak-256, deliberately not the standardized SHA3-256 padding."""
    return keccak.new(digest_bits=256, data=data).digest()


def _updated(data):
    return keccak256(data + b"\0") + keccak256(data + b"\1")


class NovaTranscript:
    def __init__(self, engine, label):
        if type(engine) is not str or engine not in ENGINES:
            raise ValueError("unsupported non-EVM Pasta engine")
        _bytes(label, MAX_LABEL, "label")
        self.engine = engine
        self.base_modulus, self.scalar_modulus = ENGINES[engine]
        self._round = 0
        self._state = _updated(b"NoTR" + label)
        self._buffer = b""

    @classmethod
    def from_snapshot(cls, engine, snapshot):
        """Restore Nova's serialized state; engine is external to its encoding.

        Missing transcript_buffer is accepted as in upstream serde. Admission is
        stricter about unknown keys, byte types and memory limits than upstream.
        """
        if type(snapshot) is not dict or set(snapshot) - {
                "round", "state", "transcript_buffer"}:
            raise ValueError("invalid transcript snapshot")
        round_ = snapshot.get("round")
        if type(round_) is not int or not 0 <= round_ <= MAX_ROUND:
            raise ValueError("invalid transcript round")
        def byte_list(name, exact=None):
            data = snapshot.get(name, [] if name == "transcript_buffer" else None)
            if (type(data) is not list or len(data) > MAX_BUFFER
                    or (exact is not None and len(data) != exact)
                    or any(type(x) is not int or not 0 <= x <= 255 for x in data)):
                raise ValueError("invalid transcript " + name)
            return bytes(data)
        state = byte_list("state", 64)
        buffer = byte_list("transcript_buffer")
        out = cls(engine, b"")
        out._round, out._state, out._buffer = round_, state, buffer
        return out

    def snapshot(self):
        return {"round": self._round, "state": list(self._state),
                "transcript_buffer": list(self._buffer)}

    def clone(self):
        return self.from_snapshot(self.engine, self.snapshot())

    def scalar_repr(self, value):
        if type(value) is not int or not 0 <= value < self.scalar_modulus:
            raise ValueError("noncanonical scalar")
        return value.to_bytes(32, "little")

    def scalars_repr(self, values):
        if type(values) not in (list, tuple) or len(values) > MAX_SCALARS:
            raise ValueError("invalid scalar vector")
        return b"".join(self.scalar_repr(x) for x in values)

    def affine_repr(self, point):
        # Upstream's raw affine trait unwraps coordinates. Do not feed it an
        # identity or malformed point and mistake a panic for rejection.
        if (type(point) is not tuple or len(point) != 2
                or any(type(x) is not int or not 0 <= x < self.base_modulus for x in point)
                or (point[1] ** 2 - point[0] ** 3 - 5) % self.base_modulus):
            raise ValueError("expected canonical finite affine point")
        return b"".join(x.to_bytes(32, "little") for x in point)

    def commitment_repr(self, point):
        # Pedersen commitment encoding includes a flag: 1 means infinity.
        return bytes(64) + b"\1" if point is None else self.affine_repr(point) + b"\0"

    def _append(self, data):
        if len(self._buffer) + len(data) > MAX_BUFFER:
            raise ValueError("transcript buffer limit")
        self._buffer += data

    def absorb_bytes(self, label, data):
        """Absorb an already-encoded TranscriptRepr object (no length prefix)."""
        _bytes(label, MAX_LABEL, "label")
        _bytes(data, MAX_BUFFER, "transcript representation")
        self._append(label + data)

    def absorb_scalar(self, label, value):
        self.absorb_bytes(label, self.scalar_repr(value))

    def absorb_scalars(self, label, values):
        self.absorb_bytes(label, self.scalars_repr(values))

    def absorb_affine(self, label, point):
        self.absorb_bytes(label, self.affine_repr(point))

    def absorb_commitment(self, label, point):
        self.absorb_bytes(label, self.commitment_repr(point))

    def dom_sep(self, data):
        _bytes(data, MAX_LABEL, "domain separation")
        self._append(b"NoDS" + data)

    def _squeeze_raw(self, label):
        _bytes(label, MAX_LABEL, "label")
        if self._round == MAX_ROUND:
            raise ValueError("transcript round overflow")
        output = _updated(self._buffer + b"NoDS"
                          + self._round.to_bytes(8, "little") + self._state + label)
        self._round += 1
        self._state, self._buffer = output, b""
        return output

    def squeeze(self, label):
        # Pasta FromUniformBytes<64>: little-endian integer reduced modulo Fr.
        return int.from_bytes(self._squeeze_raw(label), "little") % self.scalar_modulus

    def squeeze_bits(self, label, num_bits, start_with_one=False):
        if (type(num_bits) is not int or not 2 <= num_bits <= 254
                or type(start_with_one) is not bool):
            raise ValueError("invalid squeeze bit parameters")
        value = int.from_bytes(self._squeeze_raw(label), "little") & ((1 << num_bits) - 1)
        return value | (1 << (num_bits - 1)) if start_with_one else value
