"""Hosted direct-process boundary for the trusted configured Nova IPA helper.

GITHUB_ACTIONS is a resource guard, not authentication or proof authority. The
caller must select a trusted compiled helper and trusted configuration paths.
Neither the proof nor its request chooses an executable. Result JSON supplied
by a caller is never accepted: an execution object is created only after this
function runs the configured helper successfully and checks its bounded output.

This establishes a native mathematical terminal relation for a sealed request.
It does not independently compute the large MSM in Python or accept a proof.
"""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

from ipa_statement import (MAX_METADATA_BYTES, REQUEST_SCHEMA, IpaGeneratorCollection,
                           IpaStatement)
from production_replay import CURVES, ipa_factors
from proof_codec import SCALAR_MODULI, decode_point

RESULT_SCHEMA = 'bitvm2-nova-ipa-msm-result/v1'
NATIVE_SCOPE = 'mathematical IPA terminal relation for exact supplied request, not proof acceptance'
PRLIMIT = Path('/usr/bin/prlimit')
ADDRESS_SPACE_BYTES = 512 << 20
CPU_SECONDS = 300
WALL_SECONDS = 360
OUTPUT_BYTES = 1 << 15


class IpaRuntimeError(ValueError):
    pass


def _hosted_guard():
    if (os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_OS') != 'Linux' or sys.platform != 'linux'):
        raise IpaRuntimeError('native IPA execution is hosted GitHub Linux only')


def _keys(value, keys, description):
    if type(value) is not dict or len(value) != len(keys) or set(value) != set(keys):
        raise IpaRuntimeError(f'unexpected native IPA {description} fields')


def _integer(value, low, high, description):
    if type(value) is not int or not low <= value <= high:
        raise IpaRuntimeError(f'invalid native IPA {description}')
    return value


def _hex32(value):
    if (type(value) is not str or len(value) != 64
            or any(c not in '0123456789abcdef' for c in value)):
        raise IpaRuntimeError('canonical native IPA32-byte lowercase hex required')
    return bytes.fromhex(value)


def _json(raw, limit):
    if type(raw) is not bytes or not 1 <= len(raw) <= limit:
        raise IpaRuntimeError('native IPA JSON byte budget/type')
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 8:
                raise IpaRuntimeError('native IPA JSON nesting budget')
        elif byte in (93, 125):
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IpaRuntimeError('duplicate native IPA JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise IpaRuntimeError('non-JSON native IPA constant')
    try:
        return json.loads(raw.decode('ascii'), object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise IpaRuntimeError('invalid native IPA JSON') from error


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _regular_file(value, description):
    if type(value) is not str and not isinstance(value, Path):
        raise IpaRuntimeError(f'trusted {description} path required')
    try:
        path = Path(value).resolve(strict=True)
        if not stat.S_ISREG(path.stat().st_mode):
            raise IpaRuntimeError(f'{description} must be a regular file')
    except OSError as error:
        raise IpaRuntimeError(f'{description} file unavailable') from error
    return path


def _trusted_executable(value):
    path = _regular_file(value, 'compiled IPA helper')
    if path.name != 'ipa_msm' or not os.access(path, os.X_OK):
        raise IpaRuntimeError('trusted executable named ipa_msm required')
    limiter = _regular_file(PRLIMIT, 'system prlimit')
    if limiter != PRLIMIT or not os.access(limiter, os.X_OK):
        raise IpaRuntimeError('fixed /usr/bin/prlimit executable required')
    return path


def _owned_results(value):
    cwd = Path.cwd().resolve()
    root = (cwd/'results').resolve(strict=False)
    if root.parent != cwd:
        raise IpaRuntimeError('results directory must remain under the owned cwd')
    if value is not None and type(value) is not str and not isinstance(value, Path):
        raise IpaRuntimeError('owned results path required')
    selected = root if value is None else Path(value).resolve(strict=False)
    if not selected.is_relative_to(root):
        raise IpaRuntimeError('IPA temporary directory must remain under cwd/results')
    selected.mkdir(parents=True, exist_ok=True)
    return selected


def _metadata_snapshot(source, target, expected_digest):
    path = _regular_file(source, 'IPA metadata')
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise IpaRuntimeError('IPA metadata file byte budget')
    with path.open('rb') as stream:
        raw = stream.read(MAX_METADATA_BYTES+1)
    encoded = _canonical(_json(raw, MAX_METADATA_BYTES))
    if not compare_digest(sha256(encoded).digest(), expected_digest):
        raise IpaRuntimeError('IPA configuration metadata digest mismatch')
    # The native child reads this same immutable-by-convention owned snapshot,
    # not a source path which could change after the wrapper authenticated it.
    with target.open('xb') as stream:
        stream.write(encoded)


def _checked_result(raw, statement, collection):
    """Private process-output checker; never constructs an execution object."""
    result, request = _json(raw, OUTPUT_BYTES), statement.json()
    _keys(result, {'schema', 'request_sha256', 'generator_collection_sha256',
        'key_bindings_sha256', 'role', 'engine', 'ipa_dimension', 'terminal',
        'generator_bytes_authenticated', 'cpu_only', 'wall_seconds',
        'native_proofs_verified', 'proving_jobs', 'proof_verified',
        'bitvm2_script_verified', 'scope'}, 'result')
    identities = dict(schema=RESULT_SCHEMA, request_sha256=statement.request_sha256.hex(),
        generator_collection_sha256=collection.collection_sha256.hex(),
        key_bindings_sha256=request['key_bindings_sha256'], role=statement.role,
        engine=statement.engine, ipa_dimension=request['ipa_dimension'],
        generator_bytes_authenticated=True, cpu_only=True,
        native_proofs_verified=0, proving_jobs=0, proof_verified=False,
        bitvm2_script_verified=False, scope=NATIVE_SCOPE)
    if any(type(result[key]) is not type(value) or result[key] != value
           for key, value in identities.items()):
        raise IpaRuntimeError('native IPA result identity/flag mismatch')
    terminal = result['terminal']
    _keys(terminal, {'relation_holds', 'residual_matches_python', 'generators_consumed',
        'weights_computed', 'ipa_rounds', 'weights_sha256', 'factorized_b_hat_le',
        'generator_sum', 'scaled_generator_sum', 'required_generator_residual',
        'msm_seconds'}, 'terminal')
    n, engine = request['ipa_dimension'], statement.engine
    expected = dict(relation_holds=True, residual_matches_python=True,
        generators_consumed=request['generator_count'], weights_computed=n,
        ipa_rounds=n.bit_length()-1)
    if any(type(terminal[key]) is not type(value) or terminal[key] != value
           for key, value in expected.items()):
        raise IpaRuntimeError('native IPA terminal relation/count mismatch')
    _hex32(terminal['weights_sha256'])
    q = SCALAR_MODULI[engine]
    b_hat = int.from_bytes(_hex32(terminal['factorized_b_hat_le']), 'little')
    if b_hat >= q:
        raise IpaRuntimeError('noncanonical native IPA factorized scalar')
    point = tuple(int.from_bytes(bytes.fromhex(x), 'little') for x in request['batch_point_le'])
    challenges = tuple(int.from_bytes(bytes.fromhex(x), 'little') for x in request['challenges_le'])
    if b_hat != ipa_factors(point, challenges, q)['b_hat']:
        raise IpaRuntimeError('native IPA factorized scalar differs from sealed statement')
    points = {}
    for key in ('generator_sum', 'scaled_generator_sum', 'required_generator_residual'):
        try:
            points[key] = decode_point(_hex32(terminal[key]), engine)
        except ValueError as error:
            raise IpaRuntimeError('noncanonical native IPA result point') from error
    for key in ('scaled_generator_sum', 'required_generator_residual'):
        if terminal[key] != request['generator_residual']:
            raise IpaRuntimeError('native IPA point differs from sealed required residual')
    a_hat = int.from_bytes(bytes.fromhex(request['a_hat_le']), 'little')
    if CURVES[engine].mul(points['generator_sum'], a_hat) != points['scaled_generator_sum']:
        raise IpaRuntimeError('native IPA unscaled/scaled generator sums disagree')
    for key, value in (('wall_seconds', result['wall_seconds']),
                       ('msm_seconds', terminal['msm_seconds'])):
        if type(value) is not float or not math.isfinite(value) or not 0 <= value <= WALL_SECONDS+1:
            raise IpaRuntimeError(f'invalid native IPA {key}')
    if terminal['msm_seconds'] > result['wall_seconds']:
        raise IpaRuntimeError('native IPA timing fields disagree')
    return result


@dataclass(frozen=True, init=False)
class IpaExecution:
    role: str
    engine: str
    request_sha256: bytes
    collection_sha256: bytes
    helper_path: str
    stdout_bytes: int
    stderr_bytes: int
    elapsed_seconds: float
    _result: bytes

    def __init__(self, *args, **kwargs):
        raise TypeError('execute a sealed IPA statement directly to obtain an execution')

    def native_result(self):
        return json.loads(self._result)

    def summary(self):
        return dict(role=self.role, engine=self.engine,
            request_sha256=self.request_sha256.hex(),
            generator_collection_sha256=self.collection_sha256.hex(),
            helper_path=self.helper_path, stdout_bytes=self.stdout_bytes,
            stderr_bytes=self.stderr_bytes, elapsed_seconds=self.elapsed_seconds,
            ipa_native_msm_executed=True, ipa_native_relation_checked=True,
            ipa_python_msm_independently_computed=False, ipa_generator_msm_verified=False,
            ipa_complete_verification=False, proof_verified=False,
            bitvm2_script_verified=False,
            scope='native mathematical IPA terminal from direct trusted helper execution')


def execute_ipa_statement(statement, collection, *, executable, key_bindings_file,
                          collection_file, generators_directory, results_directory=None):
    """Run one trusted configured helper, under fixed hosted-only resource caps.

    Two roles must be orchestrated sequentially by the caller. Configuration
    paths and the compiled helper are trusted caller inputs, never proof-owned
    fields. The GitHub environment guard is not a security/authentication claim.
    No caller-supplied result JSON can create IpaExecution or enable flags.
    """
    _hosted_guard()  # Must remain before any file/directory/process operation.
    if type(statement) is not IpaStatement or type(collection) is not IpaGeneratorCollection:
        raise IpaRuntimeError('sealed IpaStatement and pinned generator collection required')
    request, encoded = statement.json(), statement.to_bytes()
    if (request['schema'] != REQUEST_SCHEMA or request['role'] != statement.role
            or request['engine'] != statement.engine
            or request['generator_collection_sha256'] != collection.collection_sha256.hex()
            or request['verifier_dimensions_sha256'] != collection.dimensions.descriptor_sha256.hex()
            or sha256(encoded).digest() != statement.request_sha256 or encoded != _canonical(request)):
        raise IpaRuntimeError('sealed IPA request identity/digest mismatch')
    descriptor = collection.file(statement.role)
    if descriptor.count != request['generator_count'] or descriptor.count != request['ipa_dimension']:
        raise IpaRuntimeError('sealed IPA request generator dimension mismatch')
    helper = _trusted_executable(executable)
    if type(generators_directory) is not str and not isinstance(generators_directory, Path):
        raise IpaRuntimeError('trusted generator directory path required')
    generators = _regular_file(Path(generators_directory)/descriptor.filename, 'ordered IPA generators')
    if generators.stat().st_size != descriptor.bytes:
        raise IpaRuntimeError('ordered IPA generator file size mismatch')
    results = _owned_results(results_directory)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='ipa-msm-', dir=results) as task:
        directory = Path(task)
        request_file = directory/'request.json'
        with request_file.open('xb') as stream:
            stream.write(encoded)
        key_snapshot, collection_snapshot = directory/'keys.json', directory/'collection.json'
        _metadata_snapshot(key_bindings_file, key_snapshot, _hex32(request['key_bindings_sha256']))
        _metadata_snapshot(collection_file, collection_snapshot, collection.collection_sha256)
        command = [str(PRLIMIT), f'--as={ADDRESS_SPACE_BYTES}', f'--cpu={CPU_SECONDS}',
            f'--fsize={OUTPUT_BYTES}', '--', str(helper), str(request_file),
            str(key_snapshot), str(collection_snapshot), str(generators),
            statement.request_sha256.hex()]
        with (directory/'stdout.json').open('w+b') as stdout, (directory/'stderr.txt').open('w+b') as stderr:
            try:
                completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout,
                    stderr=stderr, cwd=directory, timeout=WALL_SECONDS, check=False,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                         'RUST_BACKTRACE': '0', 'RAYON_NUM_THREADS': '2'})
            except subprocess.TimeoutExpired as error:
                raise IpaRuntimeError('native IPA helper exceeded360-second timeout') from error
            except OSError as error:
                raise IpaRuntimeError('native IPA helper failed to execute') from error
            stdout.seek(0)
            stderr.seek(0)
            raw, diagnostic = stdout.read(OUTPUT_BYTES+1), stderr.read(OUTPUT_BYTES+1)
        if len(raw) > OUTPUT_BYTES or len(diagnostic) > OUTPUT_BYTES:
            raise IpaRuntimeError('native IPA stdout/stderr exceeded32KiB file budget')
        if type(completed.returncode) is not int or completed.returncode != 0:
            detail = diagnostic.decode('utf-8', 'replace')[:1024]
            raise IpaRuntimeError(f'native IPA helper failed (exit{completed.returncode}): {detail}')
        result = _checked_result(raw, statement, collection)
        execution = object.__new__(IpaExecution)
        fields = dict(role=statement.role, engine=statement.engine,
            request_sha256=statement.request_sha256, collection_sha256=collection.collection_sha256,
            helper_path=str(helper), stdout_bytes=len(raw), stderr_bytes=len(diagnostic),
            elapsed_seconds=time.monotonic()-started, _result=_canonical(result))
        for key, value in fields.items():
            object.__setattr__(execution, key, value)
        return execution
