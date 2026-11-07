"""SYNTHETIC schema tests, not Script, signature or cryptographic evidence.

No Program/GraphSpec, source factory, compiler, key generation or native worker
is invoked. Complete-cost rows below are handcrafted to exercise transport.
"""
from collections import Counter, defaultdict
from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bench_grouped_convolution as bench


def synthetic_observation(point_delta=0):
    digest = '12'*32
    descriptors, census, rows = [], [], []
    normal_fold = {key: 0 for key in bench.METRIC_SUM_FIELDS+bench.METRIC_MAX_FIELDS}
    all_fold = dict(normal_fold)
    for case_index, (name, role, fixture, profile, full) in enumerate(bench._requests()):
        words, old_leaves, new_leaves, fields, products = bench.COUNTS[fixture]
        descriptor = dict(name=name, role=role, fixture=fixture, profile=profile,
            source_sha256=digest, source_maps_sha256=digest,
            word_catalogue_sha256=digest, assignment_sha256=digest)
        headers, counts, adapters = [], [], []
        for adapter, leaves in enumerate((old_leaves, new_leaves)):
            selected = list(range(leaves)) if full else [0, 1]
            false = [] if full else [0]
            evidence = []
            if profile in ('row-middle-0', 'subtotal-max'):
                evidence = [dict(ordinal=0, semantic_word=3, forged_word=0,
                    semantic_unique_position=2, forged_unique_position=0,
                    forged_group_row=3 if adapter == 1 and profile == 'row-middle-0' else None)]
            source = dict(index=adapter, label=bench.ADAPTERS[adapter],
                filename=f'case-{case_index:02d}-{adapter}.json', file_sha256=digest, file_bytes=100,
                program_sha256=digest, catalogue_id=digest, words=words,
                arithmetic_constraints=leaves-fields, canonical_fields=fields, leaves=leaves,
                execution_mode='all' if full else 'selected', selected_ordinals=None if full else selected,
                expected_false=false, expected_abort_ordinals=[])
            count = dict(selected=selected, unique_slots=[1]*leaves,
                selected_false=len(false), selected_abort=0,
                actual_opening_occurrences=len(selected), actual_opened_words=len(selected),
                shared_opening_links=0, alias_formal_reuses=0,
                input_lexical_nodes=100, late_auth_evidence=evidence)
            if full and fixture == 'point' and adapter == 0:
                total = bench.LEGACY_POINT_BYTES[role]+point_delta
                amount, extra = divmod(total, leaves)
                costs = [[amount+int(i < extra), 10, 200] for i in selected]
            else:
                costs = [[100+adapter, 10, 200] for _ in selected]
                total = sum(cost[0] for cost in costs)
            maximum = max(cost[0] for cost in costs)
            normal = dict(vectors=2*len(selected), expected_rejections=len(selected),
                max_script_bytes=maximum, max_witness_items=10,
                max_witness_payload_bytes=200, max_stack_items=12)
            guards, extras = 14*len(selected), 2*len(evidence)
            overall = dict(normal, vectors=normal['vectors']+guards+extras,
                expected_rejections=normal['expected_rejections']+guards+extras,
                max_stack_items=15)
            part = {key: value for key, value in source.items() if key in (
                'index', 'label', 'program_sha256', 'catalogue_id', 'words',
                'arithmetic_constraints', 'canonical_fields', 'leaves', 'execution_mode')}
            part.update(false_predicates=false, abort_predicates=[],
                measured_ordinals=None if full else selected,
                registry_id=('ab' if adapter == 0 else 'cd')*32,
                compiled_stream_sha256=digest, compiled_script_bytes=total,
                largest_disproof_leaf_bytes=maximum, normal_vectors=normal['vectors'],
                normal_metrics=normal, metrics=overall, guarded_leaves=len(selected),
                standard_guard_vectors=guards, late_auth_vectors=extras,
                late_auth_evidence=evidence, proper_disproof_vectors=len(false), abort_leaf_checks=0,
                actual_opening_occurrences=len(selected), actual_opened_words=len(selected),
                shared_opening_links=0, alias_formal_reuses=0, native_rejections=9,
                input_lexical_nodes=100, lexical_node_limit=550000, leaf_costs=costs)
            headers.append(source)
            counts.append(count)
            adapters.append(part)
            bench._fold(normal_fold, normal)
            bench._fold(all_fold, overall)
        descriptor['adapters'] = headers
        row = {key: value for key, value in descriptor.items() if key != 'adapters'}
        row.update(signature_entries_created=words, full_signature_signing_calls=words,
            cross_adapter_hash_links=10*words, old_ab_rows=280*products,
            grouped_ab_leaves=72*products, unchanged_leaf_projections=old_leaves-280*products,
            canonical_guard_projections=fields, subtotal_opening_links=280*products,
            carry_opening_links=63*products, opening_link_pass_all_leaves=False,
            opening_link_pass_all_mapped_coordinates=True,
            paired_word_opening_pass_all_words=True,
            legacy_equivalence_leaves=len(counts[0]['selected']), adapters=adapters)
        row['curve_verdict'] = (dict(applicable=True, left_valid=True, right_valid=True,
            result_valid=True, addition_holds=True) if fixture in ('point', 'point-inactive')
            else dict(applicable=False))
        descriptors.append(descriptor)
        census.append(counts)
        rows.append(row)
    manifest = dict(schema=bench.SCHEMA, context=bench.CONTEXT.hex(),
        operation_id=bench.OPERATION, cases=descriptors)
    native = dict(schema='bitvm2-nova-grouped-convolution-execution/v1', passed=True,
        input_manifest_sha256=digest, leaf_cost_columns=bench.LEAF_COST_COLUMNS,
        cases=rows, normal_metrics=normal_fold, metrics=all_fold,
        compact_execution_records_bytes=1000, compact_execution_records_sha256=digest,
        wall_seconds=1.0, full_statement_cases=8, targeted_statement_cases=32,
        signature_entries_created=52508, full_signature_signing_calls=52508,
        cross_adapter_hash_links=525080)
    native.update({key: True for key in bench.TRUE_FLAGS})
    native.update({key: False for key in bench.FALSE_FLAGS})
    native.update({key: 0 for key in bench.ZERO_FIELDS})
    # Parsed worker JSON cannot alias the independently held source census.
    return deepcopy(native), deepcopy(manifest), dict(file_sha256=digest), deepcopy(census)


class GroupedConvolutionBenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = synthetic_observation()

    def reject(self, mutation):
        data = deepcopy(self.fixture)
        mutation(data)
        with self.assertRaises(ValueError):
            bench._validate(*data)

    def test_synthetic_closed_transport(self):
        measured = bench._validate(*self.fixture)
        self.assertEqual(len(measured), 40)
        self.assertEqual(sum(row['complete_source_measured'] for row in measured), 8)
        self.assertTrue(all(row['grouped_to_baseline_ratio'] is None
            for row in measured if not row['complete_source_measured']))
        self.assertTrue(all(row['grouped_minus_baseline_bytes'] is None
            for row in measured if not row['complete_source_measured']))

    def test_pure_group_census_and_closed_budgets(self):
        patterns, aliases = Counter(), defaultdict(set)
        old_count = 0
        for square in (False, True):
            for block in range(8):
                rows = []
                for column in range(64):
                    pairs = [(i, column-i) for i in range(32) if 0 <= column-i < 32][4*block:4*block+4]
                    if not pairs:
                        continue
                    wires = [word for a, b in pairs
                        for word in (('a', a), ('a' if square else 'b', b))]+[('out', column, block)]
                    rows.append((len(pairs), wires))
                if not square:
                    old_count += len(rows)
                for start in range(0, len(rows), 4):
                    group = rows[start:start+4]
                    argument = tuple(row[0] for row in group)
                    wires = [word for _, row in group for word in row]
                    unique = list(dict.fromkeys(wires))
                    partition = tuple(unique.index(word) for word in wires)
                    bounds = tuple((1 << 18) if word[0] == 'out' else 256 for word in unique)
                    aliases[argument].add((bounds, partition))
                    if not square:
                        patterns[argument] += 1
        self.assertEqual(old_count, 280)
        self.assertEqual(patterns, {(1, 2, 3, 4): 8, (4, 4, 4, 4): 56, (3, 2, 1): 8})
        self.assertEqual(sum(len(value) for value in aliases.values()), 10)
        self.assertEqual(6151-13*(280-72), 3447)
        budget = bench._record_budget()
        self.assertEqual((budget['measured_rows_upper'], budget['engine_calls_upper'],
            budget['record_bytes_upper'], budget['combined_upper_bytes']),
            (27844, 447552, 218, 97566336))
        self.assertEqual(bench._summary_budget()['combined_upper_bytes'], 884724)
        self.assertEqual(sum(bench.COUNTS[fixture][0] for _, _, fixture, _, _ in bench._requests()), 52508)

    def test_lexical_bound_and_hosted_guard(self):
        self.assertEqual(8*7476+6151*(16+48+7)+7*6151+7476+4*256+1024, 549110)
        exact = b'['+b','.join([b'0']*bench.MAX_JSON_NODES)+b']'
        self.assertEqual(bench._lexical_nodes(exact), 550000)
        with self.assertRaises(ValueError):
            bench._lexical_nodes(exact[:-1]+b',0]')
        with patch.dict(os.environ, {}, clear=True):
            for invoke in (lambda: bench.run(None, None), lambda: bench._generate(None),
                    lambda: bench._source_snapshot(None), lambda: bench._worker(None),
                    lambda: bench._verify_inputs(None, None, None)):
                with self.assertRaisesRegex(ValueError, 'hosted GitHub Linux'):
                    invoke()

    def test_conjunction_rejects_balanced_row_errors_without_reduction(self):
        words, values, wires = [], {}, []
        for row, count in enumerate((1, 2, 3, 4)):
            for product in range(count):
                for side in ('a', 'b'):
                    name = f'{row}/{product}/{side}'
                    wires.append(len(words));words.append((name, 256));values[name] = 1
            name = f'row/{row}'
            wires.append(len(words));words.append((name, 1 << 18));values[name] = count
        spec = SimpleNamespace(words=words, leaves=(SimpleNamespace(
            kind='conv_ab_all', argument=(1, 2, 3, 4), wires=tuple(wires)),))
        program = SimpleNamespace(p=17)
        self.assertEqual(bench._truths(spec, program, values), (True,))
        values['row/0'] += 1;values['row/1'] -= 1
        self.assertEqual(bench._truths(spec, program, values), (False,))
        values['row/3'] = 0xffffffff
        self.assertEqual(bench._truths(spec, program, values), (False,))
        self.assertEqual(257*257-255, 65794)

    def test_scope_aliases_and_typed_counts(self):
        for key in ('proof_verified', 'production_assertion_binding', 'complete_verifier',
                'nova_transcript_bound', 'taproot_coverage_verified', 'source_authority'):
            with self.subTest(key=key):
                self.reject(lambda a, key=key: a[0]['cases'][0].__setitem__('metadata', {key: True}))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('cross_adapter_hash_links', True))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('paired_word_opening_pass_all_words', 1))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('opening_link_pass_all_leaves', True))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('opening_link_pass_all_mapped_coordinates', False))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('subtotal_opening_links', 279))
        self.reject(lambda a: a[0]['cases'][0].__setitem__('legacy_equivalence_leaves', 1))
        self.reject(lambda a: a[0]['cases'][3]['curve_verdict'].__setitem__('addition_holds', 1))
        self.reject(lambda a: a[0]['cases'][0]['curve_verdict'].__setitem__('unclaimed_authority', True))

    def test_cost_rows_normal_all_folds_and_exact_old_regression(self):
        mutations = (
            lambda a: a[0]['cases'][0]['adapters'][0]['leaf_costs'][0].__setitem__(1, 20),
            lambda a: a[0]['cases'][0]['adapters'][1]['leaf_costs'][0].__setitem__(2, 199),
            lambda a: a[0]['cases'][0]['adapters'][0]['normal_metrics'].__setitem__('vectors', True),
            lambda a: a[0]['cases'][0]['adapters'][0]['metrics'].__setitem__('max_stack_items', 9),
            lambda a: a[0]['normal_metrics'].__setitem__('max_witness_items', 11),
            lambda a: a[0]['cases'][0]['adapters'][0]['leaf_costs'].pop(),
            lambda a: a[0].__setitem__('correctness_bytes_equal_disproof_minus_one_checked', False),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.reject(mutation)
        with self.assertRaisesRegex(ValueError, 'historical complete legacy point'):
            bench._validate(*synthetic_observation(point_delta=1))

    def test_target_evidence_false_abort_and_limits(self):
        self.reject(lambda a: a[0]['cases'][8]['adapters'][1].__setitem__('late_auth_vectors', 0))
        self.reject(lambda a: a[0]['cases'][8]['adapters'][1]['late_auth_evidence'][0].__setitem__('forged_group_row', True))
        self.reject(lambda a: a[0]['cases'][8]['adapters'][1]['late_auth_evidence'][0].__setitem__('ordinal', 1))
        self.reject(lambda a: a[0]['cases'][4]['adapters'][0].__setitem__('false_predicates', []))
        self.reject(lambda a: a[0]['cases'][4]['adapters'][0].__setitem__('abort_predicates', [0]))
        self.reject(lambda a: a[0]['cases'][4]['adapters'][0].__setitem__('input_lexical_nodes', True))
        self.reject(lambda a: a[0]['cases'][4]['adapters'][0].__setitem__('lexical_node_limit', 550001))
        self.reject(lambda a: a[0].__setitem__('compact_execution_records_bytes', 128 << 20))
        self.reject(lambda a: a[0].__setitem__('wall_seconds', float('inf')))

    def test_owned_input_seal_and_dependency_inventory(self):
        owner = Path(__file__).resolve().parents[1]/'results'
        owner.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=owner, prefix='grouping-transport-test-') as name:
            root = Path(name).resolve()
            self.assertTrue(root.is_relative_to(owner.resolve()))
            for crate in bench.SNAPSHOT_CRATES:
                (root/crate/'src').mkdir(parents=True)
                (root/crate/'src'/'main.rs').write_text('// synthetic\n', encoding='utf-8')
                for filename in ('Cargo.toml', 'Cargo.lock'):
                    (root/crate/filename).write_text('# synthetic\n', encoding='utf-8')
            required = root/'transcript-requirements.txt'
            required.write_text('synthetic==1\n', encoding='utf-8')
            paths, _ = bench._dependency_inventory(root)
            self.assertNotIn(root/'requirements.txt', paths)
            self.assertEqual(sum(path.name == 'Cargo.lock' for path in paths), 6)
            required.unlink()
            with self.assertRaisesRegex(ValueError, 'required transcript'):
                bench._dependency_inventory(root)
            corpus = root/'cases'
            corpus.mkdir()
            case_info = bench._write_json(corpus/'case-00-0.json', {'synthetic': True}, 1024)
            manifest = {'cases': [{'adapters': [dict(filename='case-00-0.json', **case_info)]}]}
            info = bench._write_json(corpus/'manifest.json', manifest, 1024)
            with patch.object(bench, '_guard'):
                bench._verify_inputs(corpus, manifest, info)
                (corpus/'case-00-0.json').write_text('{"synthetic":false}', encoding='utf-8')
                with self.assertRaises(ValueError):
                    bench._verify_inputs(corpus, manifest, info)


if __name__ == '__main__':
    unittest.main()
