"""Tiny CSR differential/adversarial checks; never load actual matrix payloads.

The actual fixture test authenticates lengths only. Every payload in this file
is a deliberately synthetic test-owned profile with a separate replacement
dimension/profile/collection pin. It is not production proof evidence.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import unittest

from nht4 import load_expected_json
from proof_codec import SCALAR_MODULI, VerifierDimensions, load_dimensions_json
from matrix_reference import (COLLECTION_SCHEMA, ENCODING, MAX_COLLECTION_BYTES,
    MAX_FILE_BYTES, MAX_JSON_BYTES, MAX_TABLE_BYTES, MatrixCollection,
    MatrixEvaluation, MatrixFile, MatrixProfile, MatrixRole, MatrixSegment,
    MatrixShape, check_inner_terminal, evaluate_matrix, evaluate_role,
    load_collection_json, load_profile_json)

FIXTURES = Path(__file__).resolve().parents[1]/'fixtures'
DIMENSION_PIN = bytes.fromhex('de6333df2e41b5f5bae1c103fab862f8d6022fd54abeb80ba61920bc9f360edc')
PROFILE_PIN = bytes.fromhex('7a69cdd0c39601c988c39719bbfc67386762d516eea8a3fcfc0e23c7938ac921')


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('ascii')


def pin(data):
    return sha256(canonical(data)).digest()


def u64(value):
    return value.to_bytes(8, 'little')


def encode_csr(data, indices, indptr, cols):
    """Independent straightforward source serde field order, not codec reuse."""
    return (u64(len(data))+b''.join(x.to_bytes(32, 'little') for x in data)
        +u64(len(indices))+b''.join(u64(x) for x in indices)
        +u64(len(indptr))+b''.join(u64(x) for x in indptr)+u64(cols))


def sparse_toy(engine, name):
    p = SCALAR_MODULI[engine]
    # A has leading/middle empty rows; B has no stored rows or columns.
    # C includes the high column-bit domain and the final stored row.
    return {'A': ([2, p-1, 7, 0], [0, 3, 9, 10], [0, 0, 2, 2, 4], 11),
            'B': ([], [], [0], 0),
            'C': ([1, p-2, 19], [1, 8, 10], [0, 1, 1, 2, 3], 11)}[name]


def dense_evaluate(csr, rows, cols, r_x, r_y, modulus):
    """Explicit dense padded array and direct bit products, no packed table."""
    data, indices, pointers, stored_cols = csr
    dense = [[0]*cols for _ in range(rows)]
    for row in range(len(pointers)-1):
        for offset in range(pointers[row], pointers[row+1]):
            dense[row][indices[offset]] = (dense[row][indices[offset]]+data[offset]) % modulus
    def weight(point, index):
        product = 1
        for bit, value in zip(f'{index:0{len(point)}b}', point, strict=True):
            product = product*(value if bit == '1' else 1-value) % modulus
        return product
    return sum(weight(r_x, row)*weight(r_y, col)*dense[row][col]
        for row in range(rows) for col in range(cols)) % modulus


class MatrixReference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = load_expected_json((FIXTURES/'nht4-genesis-0-2020-k5.expected.json').read_bytes())
        cls.actual_dimensions = load_dimensions_json(
            (FIXTURES/'nht4-genesis-0-2020-k5.dimensions.json').read_bytes(), cls.expected,
            expected_descriptor_sha256=DIMENSION_PIN)
        cls.actual_profile_data = json.loads((FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json').read_bytes())
        # TEST ONLY: coherent tiny dimensions with independently owned test pin.
        descriptor = cls.actual_dimensions.json()
        for role, nc, nv in (('primary', 8, 8), ('secondary', 16, 8)):
            mc, mv = nc.bit_length()-1, nv.bit_length()-1
            descriptor[role].update(num_cons=nc, num_vars=nv, outer_rounds=mc,
                inner_rounds=mv+1, batch_rounds=max(mc, mv), ipa_rounds=max(mc, mv),
                ipa_dimension=max(nc, nv), ck_v_generators=max(nc, nv))
        cls.dimensions = VerifierDimensions.from_json(descriptor, cls.expected,
                                                      expected_descriptor_sha256=pin(descriptor))
        cls.profile_data = deepcopy(cls.actual_profile_data)
        cls.profile_data['verifier_dimensions_sha256'] = cls.dimensions.descriptor_sha256.hex()
        cls.payloads, cls.csrs = {}, {}
        for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
            dim = getattr(cls.dimensions, role)
            value = cls.profile_data[role]
            value.update(num_cons=dim.num_cons, num_vars=dim.num_vars,
                         evaluation_rows=dim.num_cons, evaluation_cols=2*dim.num_vars)
            for name in ('A', 'B', 'C'):
                csr = sparse_toy(engine, name)
                data, indices, indptr, cols = csr
                value['matrices'][name] = dict(data_len=len(data), indices_len=len(indices),
                    indptr_len=len(indptr), csr_rows=len(indptr)-1, cols=cols)
                filename = f'{role}-{name}.csr.bin'
                cls.csrs[filename] = csr
                cls.payloads[filename] = encode_csr(*csr)
        cls.profile = MatrixProfile.from_json(cls.profile_data, cls.expected, cls.dimensions,
                                             expected_profile_sha256=pin(cls.profile_data))
        cls.collection_data = cls.make_collection(cls.payloads)
        cls.collection = cls.admit(cls.collection_data)

    @classmethod
    def make_collection(cls, payloads):
        data = {key: value for key, value in cls.profile_data.items()
                if key not in ('scope', 'primary', 'secondary')}
        data.update(schema=COLLECTION_SCHEMA, encoding=ENCODING,
                    matrix_profile_sha256=cls.profile.profile_sha256.hex())
        files = []
        for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
            meta = cls.profile_data[role]
            for name in ('A', 'B', 'C'):
                shape = meta['matrices'][name]
                filename, offset, segments = f'{role}-{name}.csr.bin', 0, []
                lengths = [8+32*shape['data_len'], 8+8*shape['indices_len'],
                           8+8*shape['indptr_len'], 8]
                payload = payloads[filename]
                for segment, size in zip(('data', 'indices', 'indptr', 'cols'), lengths, strict=True):
                    segments.append(dict(name=segment, offset=offset, bytes=size,
                        sha256=sha256(payload[offset:offset+size]).hexdigest()))
                    offset += size
                files.append(dict(role=role, engine=engine, field_role=engine+'_scalar',
                    matrix=name, filename=filename, **{k: meta[k]
                    for k in ('num_cons', 'num_vars', 'num_io')}, **shape,
                    bytes=offset, sha256=sha256(payload).hexdigest(), segments=segments))
        data.update(files=files, total_bytes=sum(x['bytes'] for x in files))
        return data

    @classmethod
    def admit(cls, data):
        # Explicit diagnostic replacement pin, only for tests reaching internals.
        return MatrixCollection.from_json(data, cls.expected, cls.profile,
                                           expected_collection_sha256=pin(data))

    def evaluate(self, payloads=None, collection=None, role='primary', name='A',
                 x=None, y=None, opener=None, **kwargs):
        payloads = self.payloads if payloads is None else payloads
        collection = self.collection if collection is None else collection
        nc = collection.profile.role(role).num_cons
        x = [2, 3, 5, 7][:nc.bit_length()-1] if x is None else x
        y = [11, 13, 17, 19] if y is None else y
        return evaluate_matrix(collection, role, name, x, y,
            opener=(lambda filename: BytesIO(payloads[filename])) if opener is None else opener,
            **kwargs)

    def test_actual_authenticated_length_profile_without_bulk_or_large_tables(self):
        raw = (FIXTURES/'nht4-genesis-0-2020-k5.matrix-profile.json').read_bytes()
        profile = load_profile_json(raw, self.expected, self.actual_dimensions,
                                    expected_profile_sha256=PROFILE_PIN)
        self.assertEqual(profile.profile_sha256, PROFILE_PIN)
        self.assertEqual(profile.role('primary').matrix('A').data_len, 1153172)
        self.assertEqual(profile.role('secondary').matrix('C').data_len, 9812)
        self.assertEqual(profile.role('primary').evaluation_cols, 1048576)
        # Reuse toy hashes ONLY to build shape-valid metadata, then demonstrate
        # that the default guard rejects real equality-table allocation before IO.
        data = deepcopy(self.collection_data)
        data['matrix_profile_sha256'] = PROFILE_PIN.hex()
        data['verifier_dimensions_sha256'] = self.actual_dimensions.descriptor_sha256.hex()
        for entry in data['files']:
            role = profile.role(entry['role'])
            shape = role.matrix(entry['matrix'])
            entry.update(num_cons=role.num_cons, num_vars=role.num_vars, num_io=role.num_io,
                **{k: getattr(shape, k) for k in MatrixShape.__dataclass_fields__})
            offset = 0
            for segment, length in zip(entry['segments'], (8+32*shape.data_len,
                    8+8*shape.indices_len, 8+8*shape.indptr_len, 8), strict=True):
                segment.update(offset=offset, bytes=length)
                offset += length
            entry['bytes'] = offset
        data['total_bytes'] = sum(item['bytes'] for item in data['files'])
        collection = MatrixCollection.from_json(data, self.expected, profile,
                                               expected_collection_sha256=pin(data))
        self.assertEqual(collection.total_bytes, 119674848)
        calls = []
        with self.assertRaisesRegex(ValueError, 'memory budget'):
            evaluate_matrix(collection, 'primary', 'A', [0]*19, [0]*20,
                            opener=lambda filename: calls.append(filename))
        self.assertEqual(calls, [])

    def test_tiny_dense_differential_both_fields_full_domain_and_implicit_zeros(self):
        for role, engine in (('primary', 'pallas'), ('secondary', 'vesta')):
            metadata = self.profile.role(role)
            p = SCALAR_MODULI[engine]
            count = metadata.num_cons.bit_length()-1
            for x, y in (([0]*count, [0]*4), ([1]*count, [1]*4),
                         ([2, 3, 5, 7][:count], [11, 13, 17, 19]),
                         ([p-1]*count, [p-2, 0, 1, 3])):
                for name in ('A', 'B', 'C'):
                    result = self.evaluate(role=role, name=name, x=x, y=y)
                    expected = dense_evaluate(self.csrs[f'{role}-{name}.csr.bin'],
                        metadata.evaluation_rows, metadata.evaluation_cols, x, y, p)
                    self.assertEqual(result.value, expected)
                    self.assertTrue(result.arithmetic_segments_authenticated)
                    self.assertEqual(result.r_x, tuple(x))
                    self.assertEqual(result.r_y, tuple(y))
        # A's entry at row3,col9 distinguishes the high r_y bit (full Nv*2 domain).
        self.assertEqual(self.evaluate(x=[0, 1, 1], y=[1, 0, 0, 1]).value, 7)
        self.assertEqual(self.evaluate(x=[1, 1, 1], y=[0, 0, 0, 0]).value, 0)

    def test_all_truncations_and_surplus_reject_without_replacement_pins(self):
        payloads = dict(self.payloads)
        filename = 'primary-A.csr.bin'
        original = payloads[filename]
        for length in range(len(original)):
            payloads[filename] = original[:length]
            with self.subTest(length=length), self.assertRaises(ValueError):
                self.evaluate(payloads)
        for raw in (original+b'\0', b'\0'+original, b'', original+b'\0'*8):
            payloads[filename] = raw
            with self.assertRaises(ValueError):
                self.evaluate(payloads)

    def test_semantic_csr_attacks_after_explicit_diagnostic_repin(self):
        filename = 'primary-A.csr.bin'
        original = self.payloads[filename]
        entry = self.collection.file('primary', 'A')
        offsets = {segment.name: segment.offset for segment in entry.segments}
        attacks = []
        # Huge lengths for all three Vec prefixes and wrong cols footer.
        for name in ('data', 'indices', 'indptr', 'cols'):
            attacks.append((offsets[name], u64((1 << 64)-1)))
        attacks.extend([
            (offsets['data']+8, SCALAR_MODULI['pallas'].to_bytes(32, 'little')),
            (offsets['indices']+8, u64(11)),
            (offsets['indices']+8, u64((1 << 64)-1)),
            (offsets['indptr']+8, u64(1)),  # initial pointer
            (offsets['indptr']+8+2*8, u64(5)),  # >nnz
            (offsets['indptr']+8+3*8, u64(1)),  # decreasing
            (offsets['indptr']+8+4*8, u64(3)),  # final !=nnz
        ])
        for offset, replacement in attacks:
            raw = original[:offset]+replacement+original[offset+len(replacement):]
            payloads = dict(self.payloads, **{filename: raw})
            collection = self.admit(self.make_collection(payloads))
            with self.subTest(offset=offset, replacement=replacement.hex()), self.assertRaises(ValueError):
                self.evaluate(payloads, collection)

    def test_unordered_and_duplicate_entries_follow_actual_frontend_sum_semantics(self):
        # SparseMatrix::new's constructor assertion does not constrain the
        # actual frontend, which builds fields directly (inputs before aux).
        filename = 'primary-A.csr.bin'
        for indices in ([3, 0, 10, 9], [0, 0, 9, 9]):
            data, _, indptr, cols = self.csrs[filename]
            csr = (data, indices, indptr, cols)
            payloads = dict(self.payloads, **{filename: encode_csr(*csr)})
            collection = self.admit(self.make_collection(payloads))
            x, y = [2, 3, 5], [11, 13, 17, 19]
            result = self.evaluate(payloads, collection, x=x, y=y)
            expected = dense_evaluate(csr, 8, 16, x, y, SCALAR_MODULI['pallas'])
            self.assertEqual(result.value, expected)

    def test_exact_arithmetic_reads_defeat_hash_then_reread_mutation(self):
        filename = 'primary-A.csr.bin'
        original = self.payloads[filename]
        changed = bytearray(original)
        changed[8] ^= 1  # still canonical, dimension-valid; arithmetic would change
        class ChangesAfterWholeHash(BytesIO):
            def __init__(self):
                super().__init__(original)
                self.initial_hash_read_done = False
            def read(self, count=-1):
                result = super().read(count)
                if count == 1 and self.tell() == len(original) and not result:
                    self.initial_hash_read_done = True
                return result
            def seek(self, offset, whence=0):
                if self.initial_hash_read_done and offset == 0:
                    self.initial_hash_read_done = False
                    super().seek(0)
                    super().write(bytes(changed))
                return super().seek(offset, whence)
        with self.assertRaisesRegex(ValueError, 'arithmetic matrix segment digest'):
            self.evaluate(opener=lambda _: ChangesAfterWholeHash())

    def test_every_segment_digest_is_an_independent_arithmetic_authority(self):
        for index in range(4):
            data = deepcopy(self.collection_data)
            data['files'][0]['segments'][index]['sha256'] = '00'*32
            with self.subTest(index=index), self.assertRaisesRegex(ValueError, 'segment digest'):
                self.evaluate(collection=self.admit(data))
        data = deepcopy(self.collection_data)
        data['files'][0]['sha256'] = '00'*32
        with self.assertRaisesRegex(ValueError, 'file digest'):
            self.evaluate(collection=self.admit(data))

    def test_pin_identity_schema_bounds_and_role_swaps_fail_closed(self):
        for path, replacement in (
            (('files', 0, 'engine'), 'vesta'), (('files', 0, 'field_role'), 'pallas_base'),
            (('files', 0, 'role'), 'secondary'), (('files', 0, 'filename'), '../primary-A.csr.bin'),
            (('files', 0, 'matrix'), 'B'), (('files', 0, 'data_len'), True),
            (('files', 0, 'segments', 0, 'offset'), True),
            (('files', 0, 'segments', 0, 'bytes'), 1),
            (('files', 0, 'sha256'), 'AA'*32), (('total_bytes',), MAX_COLLECTION_BYTES+1),
            (('files', 0, 'bytes'), MAX_FILE_BYTES+1),
            (('matrix_profile_sha256',), '00'*32), (('network',), 'mainnet'),
            (('k',), True), (('verifier_key_sha256',), '00'*32)):
            data = deepcopy(self.collection_data)
            parent = data
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.admit(data)
        for value in (None, b'', b'0'*31, '00'*32):
            with self.assertRaises(ValueError):
                MatrixCollection.from_json(self.collection_data, self.expected, self.profile,
                                           expected_collection_sha256=value)
        data = deepcopy(self.collection_data)
        data['files'][0]['sha256'] = '01'*32
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            MatrixCollection.from_json(data, self.expected, self.profile,
                                       expected_collection_sha256=self.collection.collection_sha256)
        data = deepcopy(self.collection_data)
        data['files'][0], data['files'][1] = data['files'][1], data['files'][0]
        with self.assertRaises(ValueError):
            self.admit(data)

    def test_profile_authentication_and_malformed_shapes(self):
        for path, replacement in (
            (('primary', 'engine'), 'vesta'), (('primary', 'evaluation_cols'), 8),
            (('primary', 'num_cons'), True), (('primary', 'num_vars'), 16),
            (('primary', 'matrices', 'A', 'indptr_len'), 0),
            (('primary', 'matrices', 'A', 'csr_rows'), 9),
            (('primary', 'matrices', 'A', 'cols'), 17),
            (('primary', 'matrices', 'A', 'data_len'), 100),
            (('primary', 'matrices', 'A', 'indices_len'), 3),
            (('primary', 'matrices', 'A', 'cols'), 0),
            (('verifier_dimensions_sha256',), '00'*32)):
            data = deepcopy(self.profile_data)
            parent = data
            for key in path[:-1]:
                parent = parent[key]
            parent[path[-1]] = replacement
            with self.subTest(path=path), self.assertRaises(ValueError):
                MatrixProfile.from_json(data, self.expected, self.dimensions,
                                        expected_profile_sha256=pin(data))
        data = deepcopy(self.profile_data)
        data['primary']['matrices']['A']['cols'] = 12  # valid shape, unauthorized profile
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            MatrixProfile.from_json(data, self.expected, self.dimensions,
                                    expected_profile_sha256=self.profile.profile_sha256)

    def test_json_transport_duplicates_depth_constants_and_type_budgets(self):
        raw = canonical(self.collection_data)
        valid = load_collection_json(raw, self.expected, self.profile,
                                      expected_collection_sha256=self.collection.collection_sha256)
        self.assertEqual(valid.json(), self.collection_data)
        for bad in (raw[:-1]+b',"total_bytes":'+str(self.collection.total_bytes).encode()+b'}',
                    b'{"x":NaN}', b'['*13+b'0'+b']'*13, b'\xff',
                    b' '* (MAX_JSON_BYTES+1), bytearray(raw), b''):
            with self.assertRaises(ValueError):
                load_collection_json(bad, self.expected, self.profile,
                                     expected_collection_sha256=self.collection.collection_sha256)
        duplicate = canonical(self.profile_data)[:-1]+b',"k":5}'
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            load_profile_json(duplicate, self.expected, self.dimensions,
                              expected_profile_sha256=self.profile.profile_sha256)

    def test_dimension_point_scalar_types_memory_and_public_constructors(self):
        for x, y in (([1, 2], [1, 2, 3, 4]), ([1, 2, 3], [1, 2, 3]),
                     ([1, 2, 3], [1, 2, 3, 4, 5]), ([True, 2, 3], [1, 2, 3, 4]),
                     ([1, 2, SCALAR_MODULI['pallas']], [1, 2, 3, 4]),
                     ([1, 2, 3], [1, -1, 3, 4])):
            with self.subTest(x=x, y=y), self.assertRaises(ValueError):
                self.evaluate(x=x, y=y)
        for budget in (True, 31, MAX_TABLE_BYTES+1, 767):
            with self.assertRaises(ValueError):
                self.evaluate(max_table_bytes=budget)
        for role, matrix in (([], 'A'), ('primary', []), ('PRIMARY', 'A'), ('primary', 'D')):
            with self.assertRaises(ValueError):
                evaluate_matrix(self.collection, role, matrix, [0]*3, [0]*4)
        for cls in (MatrixProfile, MatrixRole, MatrixShape, MatrixCollection,
                    MatrixSegment, MatrixFile, MatrixEvaluation):
            with self.assertRaises(TypeError):
                cls()
        with self.assertRaises(FrozenInstanceError):
            self.profile.profile_sha256 = b'\0'*32
        copy = self.collection.json()
        copy['files'][0]['filename'] = 'other'
        self.assertEqual(self.collection.file('primary', 'A').filename, 'primary-A.csr.bin')

    def test_role_evaluation_and_terminal_comparison_including_zero_eval_z(self):
        for role in ('primary', 'secondary'):
            count = self.profile.role(role).num_cons.bit_length()-1
            x, y = [2, 3, 5, 7][:count], [11, 13, 17, 19]
            values = evaluate_role(self.collection, role, x, y,
                opener=lambda filename: BytesIO(self.payloads[filename]))
            p = SCALAR_MODULI[self.profile.role(role).engine]
            rho, z = 23, 29
            combination = (values[0].value+rho*values[1].value+rho*rho*values[2].value) % p
            self.assertEqual(check_inner_terminal(values, rho, z, z*combination % p), combination)
            self.assertEqual(check_inner_terminal(values, rho, 0, 0), combination)
            with self.assertRaisesRegex(ValueError, 'terminal mismatch'):
                check_inner_terminal(values, rho, 0, 1)
            with self.assertRaisesRegex(ValueError, 'terminal mismatch'):
                check_inner_terminal(values, rho, z, (z*combination+1) % p)
            changed = list(values)
            changed[1] = self.evaluate(role=role, name='B', x=[0]*count, y=y)
            with self.assertRaisesRegex(ValueError, 'role/collection mismatch'):
                check_inner_terminal(changed, rho, z, z*combination % p)
            changed = list(values)
            changed[1] = self.evaluate(role='secondary' if role == 'primary' else 'primary', name='B')
            with self.assertRaises(ValueError):
                check_inner_terminal(changed, rho, z, z*combination % p)


if __name__ == '__main__':
    unittest.main()
