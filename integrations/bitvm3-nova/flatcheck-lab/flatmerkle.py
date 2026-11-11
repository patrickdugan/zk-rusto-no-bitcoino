"""Experimental FlatMerkle SHA-256 stream and indexed openings.

Pure-Python reference for Bitcoin trace-publication research. The digest is
SHA256(exact serialized stream), including ordinary SHA-256 final padding.
This is a laboratory primitive, not an authorization or Bitcoin consensus
verifier. Design follows Sergio Demian Lerner's October 2026 FlatMerkle paper.
"""
from dataclasses import dataclass
from hashlib import sha256
from math import log2
from typing import Tuple

MASK = (1 << 32) - 1
K = (
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
)
IV = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
MID_TAIL = b"\x80" + b"\x00" * 31

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK

def compress(state: bytes, block: bytes) -> bytes:
    """One SHA-256 compression, with caller-controlled chaining state."""
    if len(state) != 32 or len(block) != 64:
        raise ValueError("SHA256 state must be 32 bytes and block 64 bytes")
    h = [int.from_bytes(state[j:j+4], "big") for j in range(0, 32, 4)]
    w = [int.from_bytes(block[j:j+4], "big") for j in range(0, 64, 4)]
    for j in range(16, 64):
        a, b = w[j-15], w[j-2]
        s0 = _rotr(a,7) ^ _rotr(a,18) ^ (a >> 3)
        s1 = _rotr(b,17) ^ _rotr(b,19) ^ (b >> 10)
        w.append((w[j-16] + s0 + w[j-7] + s1) & MASK)
    a,b,c,d,e,f,g,hh = h
    for j in range(64):
        s1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
        ch = (e & f) ^ (~e & g)
        t1 = (hh + s1 + ch + K[j] + w[j]) & MASK
        s0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & MASK
        hh,g,f,e,d,c,b,a = g,f,e,(d+t1)&MASK,c,b,a,(t1+t2)&MASK
    out = [(x + y) & MASK for x,y in zip(h,(a,b,c,d,e,f,g,hh))]
    return b"".join(x.to_bytes(4,"big") for x in out)

def _finalize(state: bytes, byte_length: int) -> bytes:
    if byte_length >= (1 << 61):
        raise ValueError("SHA256 length overflow")
    remainder = byte_length % 64
    padding = b"\x80" + b"\x00" * ((55 - remainder) % 64) + (byte_length * 8).to_bytes(8, "big")
    for j in range(0,len(padding),64):
        state = compress(state,padding[j:j+64])
    return state

def _block(data: bytes) -> bytes:
    if len(data) > 64:
        raise ValueError("item exceeds 64 bytes")
    return data.ljust(64,b"\x00")

def _mid(checkpoint: bytes) -> bytes:
    return checkpoint + MID_TAIL

def _level(n: int) -> int:
    if n < 4 or n & (n - 1):
        raise ValueError("element count must be a power of two >= 4")
    return n.bit_length()-1

@dataclass(frozen=True)
class Opening:
    index: int
    pair: Tuple[bytes,bytes]
    reveals: Tuple[bytes,...]

@dataclass
class Stream:
    items: Tuple[bytes,...]
    payload: bytes
    digest: bytes
    checkpoint: dict
    ending: dict
    prewrap: dict

def build(items) -> Stream:
    items = tuple(_block(x) for x in items)
    level = _level(len(items))
    checkpoint, ending, prewrap = {}, {}, {}
    state = IV
    payload = bytearray()
    def emit(block):
        nonlocal state
        payload.extend(block)
        state = compress(state,block)
    def node(start,k):
        checkpoint[start] = state
        if k == 1:
            emit(items[start]); emit(items[start+1])
        else:
            mid = 1 << (k-1)
            node(start,k-1)
            node(start+mid,k-1)
        prewrap[start,k] = state
        emit(_mid(checkpoint[start]))
        ending[start,k] = state
    half = len(items)//2
    node(0,level-1)
    node(half,level-1)
    digest = _finalize(state,len(payload))
    if digest != sha256(payload).digest():
        raise AssertionError("stream digest disagrees with standard SHA256")
    return Stream(items,bytes(payload),digest,checkpoint,ending,prewrap)

def open_index(stream: Stream, index: int) -> Opening:
    n = len(stream.items); level = _level(n)
    if not 0 <= index < n:
        raise IndexError(index)
    pair_index = index & ~1
    reveals = []
    def visit(start,k):
        if k == 1:
            return
        half = 1 << (k-1)
        if pair_index < start+half:
            visit(start,k-1)
            reveals.append(stream.prewrap[start+half,k-1])
        else:
            reveals.append(stream.ending[start,k-1])
            visit(start+half,k-1)
    half = n//2
    if pair_index < half:
        visit(0,level-1)
        reveals.append(stream.prewrap[half,level-1])
    else:
        reveals.append(stream.ending[0,level-1])
        visit(half,level-1)
    return Opening(index,(stream.items[pair_index],stream.items[pair_index+1]),tuple(reveals))

def verify(n: int, digest: bytes, index: int, item: bytes, proof: Opening) -> bool:
    try:
        level = _level(n)
        if len(digest)!=32 or not 0 <= index < n or index!=proof.index:
            return False
        if len(proof.pair)!=2 or any(len(v)!=64 for v in proof.pair):
            return False
        if _block(item)!=proof.pair[index & 1]:
            return False
        if len(proof.reveals)!=level-1 or any(len(v)!=32 for v in proof.reveals):
            return False
        it = iter(proof.reveals)
        pair_index = index & ~1
        def visit(start,k,ck):
            if k==1:
                x=compress(compress(ck,proof.pair[0]),proof.pair[1])
                return compress(x,_mid(ck))
            half=1 << (k-1)
            if pair_index < start+half:
                left=visit(start,k-1,ck)
                right=compress(next(it),_mid(left))
                return compress(right,_mid(ck))
            left=next(it)
            right=visit(start+half,k-1,left)
            return compress(right,_mid(ck))
        half=n//2
        if pair_index < half:
            left=visit(0,level-1,IV)
            state=compress(next(it),_mid(left))
        else:
            left=next(it)
            state=visit(half,level-1,left)
        if next(it,None) is not None:
            return False
        return _finalize(state,(2*n-2)*64)==digest
    except (ValueError,TypeError,IndexError,StopIteration,OverflowError):
        return False
