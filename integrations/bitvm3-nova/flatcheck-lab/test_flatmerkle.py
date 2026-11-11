"""Bounded reference tests; no prover, Bitcoin node, or external dependencies."""
import dataclasses
import hashlib
import os
import unittest

from flatmerkle import IV, Opening, build, compress, open_index, verify


class FlatMerkleTests(unittest.TestCase):
    def test_sha256_compression_known_digest(self):
        # A single-block message after SHA256 length padding.
        message = b"abc"
        block = message + b"\x80" + b"\x00" * 52 + (24).to_bytes(8, "big")
        self.assertEqual(compress(IV, block), hashlib.sha256(message).digest())

    def test_upstream_sizes_and_all_indices(self):
        for n in (4, 8, 16, 32, 64):
            items = tuple(hashlib.sha256(i.to_bytes(4, "little")).digest() for i in range(n))
            stream = build(items)
            self.assertEqual(len(stream.payload), (2*n-2)*64)
            self.assertEqual(stream.digest, hashlib.sha256(stream.payload).digest())
            for i, item in enumerate(items):
                opening = open_index(stream,i)
                self.assertEqual(len(opening.reveals), n.bit_length()-2)
                self.assertTrue(verify(n,stream.digest,i,item,opening))
                corrupted = bytes([item[0] ^ 1])+item[1:]
                self.assertFalse(verify(n,stream.digest,i,corrupted,opening))
                for j in range(len(opening.reveals)):
                    changed = list(opening.reveals)
                    changed[j] = bytes([changed[j][0] ^ 1]) + changed[j][1:]
                    self.assertFalse(verify(n,stream.digest,i,item,dataclasses.replace(opening,reveals=tuple(changed))))

    def test_index_substitution_and_wrong_digest(self):
        items=[bytes([i])*64 for i in range(16)]
        stream=build(items)
        for i in range(16):
            opening=open_index(stream,i)
            other=i ^ 1
            self.assertFalse(verify(16,stream.digest,other,items[other],opening))
            self.assertFalse(verify(16,stream.digest,other,items[i],opening))
            wrong=bytes([stream.digest[0] ^ 1])+stream.digest[1:]
            self.assertFalse(verify(16,wrong,i,items[i],opening))

    def test_length_and_unsupported_count(self):
        with self.assertRaises(ValueError):
            build([b"x"] * 3)
        with self.assertRaises(ValueError):
            build([b"x"] * 5)
        with self.assertRaises(ValueError):
            build([b"x" * 65] * 4)
        self.assertFalse(verify(4,b"\x00"*32,0,b"x",Opening(0,(b"",b""),())))

if __name__=="__main__":
    unittest.main()
