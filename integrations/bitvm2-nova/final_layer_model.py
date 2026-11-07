"""M25a: parametric proof-size model for a size-targeted final STARK layer.

Pure arithmetic; nothing is proved or executed. The final layer is a
FRI-based STARK over KoalaBear (4-byte base, degree-4 extension, 16-byte
elements) with 32-byte BLAKE3 Merkle digests. The trace being proved, the
in-circuit verifier of the SP1 compressed proof, has not been built, so its
height and width are swept as assumptions rather than counted.

Per query the proof opens one leaf of each committed matrix (main, auxiliary
and quotient) with its Merkle path, and, per FRI round, 2^arity extension
values with a shrinking path. A Merkle cap of 2^cap digests per tree removes
`cap` levels from every path. Conjectured security is queries x log_blowup +
grinding bits (the ethSTARK toy-problem conjecture); proven bounds need more
queries, which this model reports separately as `proven_queries`.

BitVM2 prices use measured inputs: 76,695 Script bytes per BLAKE3 block (M24)
and 200 WOTS signature bytes per asserted 32-bit word (M23).
"""
from dataclasses import dataclass, asdict
from math import ceil

DIGEST, BASE, EXT = 32, 4, 16
BLAKE3_BLOCK_SCRIPT_BYTES = 76_695
WOTS_BYTES_PER_WORD = 200
STANDARD_TX_WEIGHT = 400_000
PROVER_LDE_BUDGET_BYTES = 16 << 30


@dataclass(frozen=True)
class Shape:
    log_height: int        # trace rows = 2^log_height (assumed)
    main_width: int        # base-field main columns (assumed)
    aux_width: int         # extension-field auxiliary columns
    quotient_width: int    # extension-field quotient chunks
    log_blowup: int
    queries: int
    grinding_bits: int
    log_arity: int         # FRI folding arity 2^log_arity
    log_final: int         # final polynomial length 2^log_final
    cap: int               # Merkle cap height

    def lde_log(self):
        return self.log_height+self.log_blowup

    def fri_rounds(self):
        return ceil(max(0, self.log_height-self.log_final)/self.log_arity)


def _check(s):
    values = asdict(s)
    if any(type(v) is not int or v < 0 for v in values.values()):
        raise ValueError('non-negative integer shape required')
    if s.log_blowup < 1 or s.queries < 1 or s.log_arity < 1 or s.log_height < 1:
        raise ValueError('positive blowup, queries, arity and height required')
    if s.cap > s.lde_log() or s.log_final > s.log_height:
        raise ValueError('cap/final length exceed the domain')


def conjectured_bits(s):
    return s.queries*s.log_blowup+s.grinding_bits


def proven_queries(s, bits):
    """Approximate queries for `bits` in the Johnson-bound regime: about
    log_blowup/2 bits per query. Commit-phase and field-size terms are
    ignored; this is a sizing aid, not a soundness proof."""
    return ceil(max(0, bits-s.grinding_bits)/(s.log_blowup/2))


def proof_bytes(s):
    _check(s)
    trees = 3 if s.aux_width else 2
    leaf = s.main_width*BASE + s.aux_width*EXT + s.quotient_width*EXT
    path = (s.lde_log()-s.cap)*DIGEST
    per_query = leaf + trees*path
    for r in range(s.fri_rounds()):
        depth = max(0, s.lde_log()-s.log_arity*(r+1)-s.cap)
        per_query += (1 << s.log_arity)*EXT + depth*DIGEST
    commitments = (trees+s.fri_rounds())*(1 << s.cap)*DIGEST
    out_of_domain = 2*(s.main_width+s.aux_width+s.quotient_width)*EXT
    final = (1 << s.log_final)*EXT
    return s.queries*per_query + commitments + out_of_domain + final + 8


def hash_blocks(s):
    """BLAKE3 64-byte blocks to check every opening (transcript excluded)."""
    trees = 3 if s.aux_width else 2
    leaves = [s.main_width*BASE, s.aux_width*EXT, s.quotient_width*EXT][:trees]
    per_query = sum(max(1, ceil(b/64)) for b in leaves if b) + trees*(s.lde_log()-s.cap)
    for r in range(s.fri_rounds()):
        per_query += ceil((1 << s.log_arity)*EXT/64) + max(0, s.lde_log()-s.log_arity*(r+1)-s.cap)
    return s.queries*per_query


def prover_lde_bytes(s):
    return (s.main_width*BASE + (s.aux_width+s.quotient_width)*EXT) << s.lde_log()


def evaluate(s):
    size = proof_bytes(s)
    signatures = ceil(size/4)*WOTS_BYTES_PER_WORD
    return dict(shape=asdict(s), proof_bytes=size, conjectured_bits=conjectured_bits(s),
        proven_queries_for_100_bits=proven_queries(s, 100), hash_blocks=hash_blocks(s),
        hash_script_bytes=hash_blocks(s)*BLAKE3_BLOCK_SCRIPT_BYTES,
        assertion_signature_bytes=signatures,
        standard_transactions=ceil(signatures/STANDARD_TX_WEIGHT),
        prover_lde_bytes=prover_lde_bytes(s),
        within_prover_budget=prover_lde_bytes(s) <= PROVER_LDE_BUDGET_BYTES)


def search(log_height, main_width, *, bits=100, aux_width=8, quotient_width=4):
    """Smallest proof meeting `bits` (conjectured) within the prover budget."""
    best = None
    for log_blowup in range(1, 11):
        for grinding in (0, 16, 20, 24):
            queries = ceil(max(1, bits-grinding)/log_blowup)
            for log_arity in range(1, 5):
                for log_final in range(0, 7):
                    for cap in range(0, 7):
                        s = Shape(log_height, main_width, aux_width, quotient_width, log_blowup,
                                  queries, grinding, log_arity, log_final, cap)
                        if s.cap > s.lde_log() or prover_lde_bytes(s) > PROVER_LDE_BUDGET_BYTES:
                            continue
                        size = proof_bytes(s)
                        if best is None or size < best[0]:
                            best = (size, s)
    return None if best is None else evaluate(best[1])


SWEEP_HEIGHTS = (16, 18, 20, 22)
SWEEP_WIDTHS = (64, 128, 256)


def sweep(bits=100):
    return [dict(log_height=h, main_width=w, result=search(h, w, bits=bits))
            for h in SWEEP_HEIGHTS for w in SWEEP_WIDTHS]
