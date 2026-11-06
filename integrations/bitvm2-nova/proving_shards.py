"""Real, bounded Nova header proving using the existing k-aligned shard protocol.

The configured source and executables are trusted. Only this invocation's fresh
artifacts enter native deserialization; this is not arbitrary-proof admission.
The output is a verified multiproof set, never a merged SNARK or Script verifier.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import sys
import threading
import time

from proving_process import run_bounded
from proving_policy import (plan_shards, verify_source_package,
                            validate_native_receipt, validate_shard_continuity)

SOURCE_REV = 'de607d3db17d400dd6c2923d357f1d4a7bf233c7'
NETWORK = 'testnet4'
GENESIS_SHA = '9c82dffe8b6005378775c8f2028b7644039defadb0fcc1d77820b7aaced6de9c'
PINS = {5:'1ae88a7bcfdc5f14d030d0baafa06ec17fe904a5ebed42f9bd6fa6105fdc8c24',
        10:'2495da9bf5965030e45fa2cef1a43ade78e099ca844b5d3a9abf56400447eabe'}


def file_sha(path):
    digest = sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def read_json(path, limit=1 << 20):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate native output key')
            result[key] = value
        return result
    with Path(path).open('rb') as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError('native JSON output exceeds explicit byte budget')
    return json.loads(raw, object_pairs_hook=unique)


def _fresh_output(path):
    owner = (Path(__file__).resolve().parent/'results').resolve()
    package = Path(__file__).resolve().parent
    target = Path(path).resolve()
    if owner.parent != package or target == owner or not target.is_relative_to(owner):
        raise ValueError('new proof output must stay beneath integration/results')
    owner.mkdir(exist_ok=True)
    target.mkdir(parents=True, exist_ok=False)
    (target/'logs').mkdir()
    return target


def _available_memory():
    if os.name != 'nt':
        raise ValueError('this resource-enforced proving coordinator currently requires Windows')
    import ctypes as C
    class State(C.Structure):
        _fields_ = [('length',C.c_uint32),('load',C.c_uint32)]+[(name,C.c_uint64) for name in
            ('total','available','pagefile','available_pagefile','virtual','available_virtual','extended')]
    state = State()
    state.length = C.sizeof(state)
    if not C.windll.kernel32.GlobalMemoryStatusEx(C.byref(state)):
        raise ValueError('cannot establish available proving memory')
    return state.total, state.available


def admit_memory_budget(*,memory_mib,parallel,export_parallel,total_memory_mib,
                        reserve_memory_mib,available_bytes):
    """Pure scheduler admission; the child Job Objects enforce the ceilings."""
    for name,value in (('child memory',memory_mib),('fold concurrency',parallel),
                       ('export concurrency',export_parallel),('total memory',total_memory_mib)):
        if type(value) is not int or value <= 0:
            raise ValueError('positive integer '+name+' required')
    if (type(reserve_memory_mib) is not int or reserve_memory_mib < 0
            or type(available_bytes) is not int or available_bytes < 0):
        raise ValueError('invalid memory reserve or available-byte observation')
    aggregate = max(parallel,export_parallel)*memory_mib*(1 << 20)
    budget = total_memory_mib*(1 << 20)
    reserve = reserve_memory_mib*(1 << 20)
    if aggregate > budget:
        raise ValueError('concurrent child Job ceilings exceed the explicit total proving budget')
    if aggregate+reserve > available_bytes:
        raise ValueError('available RAM cannot cover admitted Job ceilings plus the host reserve')
    return dict(total_proving_memory_mib=total_memory_mib,host_reserve_memory_mib=reserve_memory_mib,
                maximum_concurrent_job_limit_bytes=aggregate,observed_available_bytes=available_bytes)


def prove(args):
    started = time.perf_counter()
    if any((Path(args.source_root)/name).exists() for name in
           ('.source-preparation-incomplete','source-preparation-incomplete.json','source-preparation-failed.json')):
        raise ValueError('source preparation did not finish successfully')
    source = verify_source_package(args.source_root)
    crate = Path(args.source_root).resolve()/'integrations/nova-header-chain'
    headers = crate/'fixtures/testnet4/headers_0_4100.bin'
    if headers.stat().st_size % 80:
        raise ValueError('height-indexed source header file has trailing data')
    header_sha = file_sha(headers)
    plan = plan_shards(k=args.k, to_height=args.to, header_count=headers.stat().st_size//80,
        shards=args.shards, parallel=args.parallel, threads=args.threads, memory_mib=args.memory_mib)
    if type(args.export_parallel) is not int or not 1 <= args.export_parallel <= args.parallel:
        raise ValueError('export parallelism must be within the admitted proving concurrency')
    if not math.isfinite(args.wall_seconds) or args.wall_seconds <= 0:
        raise ValueError('positive child wall-time budget required')
    total_ram, free_ram = _available_memory()
    memory_budget = admit_memory_budget(memory_mib=args.memory_mib,parallel=args.parallel,
        export_parallel=args.export_parallel,total_memory_mib=args.total_memory_mib,
        reserve_memory_mib=args.reserve_memory_mib,available_bytes=free_ram)
    if args.plan_only:
        report = dict(schema='bitvm2-nova-proving-plan/v1',k=args.k,
            ranges=[shard.json() for shard in plan.ranges],memory_budget=memory_budget,
            real_proving_executed=False,source=source.summary())
        print(json.dumps(report))
        return report
    binaries = Path(args.bin_dir).resolve()
    chain, verifier = binaries/'nova-chain.exe', binaries/'btc-header-fold.exe'
    for exe in (chain, verifier):
        if not exe.is_file():
            raise ValueError('build both trusted pinned prover/verifier executables first')
    binary_hashes = {exe.name:file_sha(exe) for exe in (chain, verifier)}
    out = _fresh_output(args.out)
    cancel = threading.Event()
    processes, reports_lock = [], threading.Lock()

    def execute(label, executable, arguments):
        try:
            if cancel.is_set():
                raise ValueError('proving task cancelled before launch')
            result = run_bounded(executable, arguments, cwd=crate, owned_root=out,
                stdout_path=out/'logs'/f'{label}.json', stderr_path=out/'logs'/f'{label}.err',
                memory_mib=args.memory_mib, wall_seconds=args.wall_seconds,
                threads=args.threads, cancel_event=cancel)
            with reports_lock:
                processes.append(dict(label=label, **result.summary()))
            if not result.succeeded:
                raise ValueError(f'bounded proving phase {label} failed: {result.termination_reason}')
            response = read_json(result.stdout_path)
            if type(response) is not dict:
                raise ValueError('native command must emit one typed JSON object')
            return response
        except BaseException:
            cancel.set()
            raise

    def guarded(task, shard):
        try:
            if cancel.is_set():
                raise ValueError('queued proving task cancelled')
            return task(shard)
        except BaseException:
            cancel.set()
            raise

    def fold(shard):
        index, start, end = shard.index, shard.start_height, shard.end_height
        directory = out/f'shard-{index:03d}'
        common = ['--network',NETWORK,'--k',str(args.k),'--headers',str(headers),
            '--start',str(start),'--to',str(end),'--every','1','--out',str(directory)]
        result = execute(f'shard-{index:03d}-run', chain,
                         ['run',*common,'--max-steps','1'])
        if result.get('ok') is not True:
            raise ValueError('fresh recursive proving failed')
        if (end-start)//args.k > 1:
            result = execute(f'shard-{index:03d}-resume', chain,
                ['resume','--dir',str(directory),'--headers',str(headers),
                 '--to',str(end),'--every','1'])
            if result.get('ok') is not True:
                raise ValueError('verified continuation resume failed')
        state = result.get('chain', {})
        if (state.get('network') != NETWORK or state.get('k') != args.k
                or state.get('start',{}).get('height') != start
                or state.get('end',{}).get('height') != end
                or state.get('completed_steps') != (end-start)//args.k):
            raise ValueError('prover stopped short of the requested shard or changed its identity')
        return shard

    def export(shard):
        index = shard.index
        directory = out/f'shard-{index:03d}'
        bundle, vk = out/f'shard-{index:03d}.bundle', out/f'shard-{index:03d}.vk'
        result = execute(f'shard-{index:03d}-export', chain,
            ['export','--dir',str(directory),'--bundle',str(bundle),'--vk-out',str(vk)])
        if result.get('ok') is not True or result.get('bundle_sha256') != file_sha(bundle):
            raise ValueError('self-verified export did not bind the actual fresh bundle')
        if result.get('vk_sha256') != file_sha(vk):
            raise ValueError('fresh verifier key differs from the trusted export')
        known = PINS.get(args.k)
        if known is not None and result['vk_sha256'] != known:
            raise ValueError('generated verifier key differs from the existing network/k pin')
        latest = (directory/'LATEST').read_text(encoding='ascii').strip()
        if not latest.startswith('gen-') or len(latest) != 10 or not latest[4:].isdigit():
            raise ValueError('noncanonical continuation generation pointer')
        manifest = read_json(directory/'generations'/latest/'manifest.json')
        if (manifest['network'] != NETWORK or manifest['k'] != args.k
                or manifest['initial_height'] != shard.start_height or manifest['end_height'] != shard.end_height
                or manifest['completed_steps'] != shard.steps
                or manifest['source_commit'] != SOURCE_REV
                or manifest['binary_sha256'] != binary_hashes[chain.name]):
            raise ValueError('continuation fallback is not the requested complete shard')
        initial, terminal = bytes.fromhex(manifest['initial_state_hex']), bytes.fromhex(manifest['end_state_hex'])
        if len(initial) != 544 or len(terminal) != 544:
            raise ValueError('complete seventeen-scalar states required')
        with bundle.open('rb') as stream:
            prefix = stream.read(556)
        if (len(prefix) != 556 or prefix[:4] != b'NHT4'
                or int.from_bytes(prefix[4:8],'little') != shard.steps
                or int.from_bytes(prefix[8:12],'little') != args.k or prefix[12:] != initial):
            raise ValueError('fresh NHT4 framing disagrees with the requested shard')
        if (result['chain']['initial_state_sha256'] != sha256(initial).hexdigest()
                or result['chain']['end_state_sha256'] != sha256(terminal).hexdigest()):
            raise ValueError('verified export differs from full continuation states')
        proof_hash = file_sha(bundle)  # Bind the complete container separately below.
        with bundle.open('rb') as stream:
            stream.read(556)
            raw = stream.read((1 << 20)+1)
        if len(raw) > 1 << 20:
            raise ValueError('fresh compressed proof exceeds its bounded runner profile')
        if sha256(raw).hexdigest() != result['proof_sha256']:
            raise ValueError('fresh proof bytes differ from self-verified export')
        arguments = ['verify-bundle',str(bundle)]
        # Known keys are independently pinned. Unknown k cold-reconstructs the
        # verifier-owned key from the trusted circuit rather than loading a key.
        if known is not None:
            arguments += ['--vk',str(vk)]
        receipt = execute(f'shard-{index:03d}-cold-verify', verifier, arguments)
        with headers.open('rb') as stream:
            stream.seek(shard.end_height*80)
            header = stream.read(80)
        if (len(header) != 80 or receipt.get('end',{}).get('tip_hash')
                != sha256(sha256(header).digest()).digest()[::-1].hex()):
            raise ValueError('proven shard tip differs from its requested header fixture')
        checked = validate_native_receipt(receipt, shard=shard,k=args.k,network=NETWORK,
            verifier_key_sha256=bytes.fromhex(result['vk_sha256']),proof_sha256=bytes.fromhex(result['proof_sha256']),
            initial_state=initial,end_state=terminal,headers_sha256=bytes.fromhex(header_sha),
            cold_reconstructed_vk_sha256=bytes.fromhex(receipt['vk_sha256']) if known is None else None)
        return checked, dict(index=index,bundle=str(bundle),bundle_sha256=proof_hash,
            proof_sha256=result['proof_sha256'],vk_sha256=result['vk_sha256'],
            proof_bytes=len(raw),bundle_bytes=bundle.stat().st_size,initial_state_hex=initial.hex(),
            end_state_hex=terminal.hex(),native_receipt=receipt)

    try:
        anchor = execute('genesis-anchor', chain, ['anchor','--network',NETWORK])
        if anchor.get('initial_state_sha256') != GENESIS_SHA:
            raise ValueError('configured prover does not reproduce the pinned testnet4 genesis state')
        differential = execute('core-fixture-differential',chain,
            ['native-check','--network',NETWORK,'--headers',str(headers),
             '--core-ref',str(crate/'fixtures/testnet4/core_ref_0_4100.tsv'),'--to',str(args.to)])
        if differential.get('ok') is not True or differential.get('checked_heights') != f'0..={args.to}':
            raise ValueError('native rules failed the independently recorded Core header fixture')
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            try:
                list(pool.map(lambda shard: guarded(fold,shard), plan.ranges))
            except BaseException:
                cancel.set()
                raise
        with ThreadPoolExecutor(max_workers=args.export_parallel) as pool:
            try:
                exported = list(pool.map(lambda shard: guarded(export,shard), plan.ranges))
            except BaseException:
                cancel.set()
                raise
        checked, artifacts = zip(*exported)
        keys = {a['vk_sha256'] for a in artifacts}
        if len(keys) != 1:
            raise ValueError('shards were produced against different verifier keys')
        continuity = validate_shard_continuity(plan, checked, network=NETWORK,
            verifier_key_sha256=bytes.fromhex(keys.pop()),expected_headers_sha256=bytes.fromhex(header_sha))
        for exe in (chain,verifier):
            if file_sha(exe) != binary_hashes[exe.name]:
                raise ValueError('configured native executable changed during the proving run')
        if file_sha(headers) != header_sha:
            raise ValueError('source header fixture changed during the proving run')
        report = dict(schema='bitvm2-nova-actual-sharded-proving/v1',passed=True,
            source_revision=SOURCE_REV,source_package=source.summary(),k=args.k,
            to_height=args.to,shards=args.shards,parallel=args.parallel,threads=args.threads,
            export_parallel=args.export_parallel,process_memory_mib=args.memory_mib,
            memory_budget=memory_budget,
            initial_total_physical_bytes=total_ram,initial_available_physical_bytes=free_ram,
            headers_sha256=header_sha,binary_sha256=binary_hashes,artifacts=list(artifacts),
            continuity=continuity.summary(),processes=processes,real_proving_executed=True,
            core_fixture_differential=differential,
            compression='Nova 0.76.0 transparent Spartan with IPA',trusted_setup_used=False,
            native_compressed_proofs_verified=len(checked),recursively_merged_snark=False,
            complete_bitvm2_verifier=False,bitvm2_script_verified=False,
            production_assertion_binding=False,bitcoin_transaction_graph=False,
            transactions_broadcast=0,active_chain_at_lookup=False,
            wall_seconds=time.perf_counter()-started)
        (out/'verified.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(dict(passed=True,report=str(out/'verified.json'),k=args.k,
            shards=args.shards,headers=args.to,wall_seconds=report['wall_seconds'])))
        return report
    except BaseException as error:
        cancel.set()
        failure = dict(schema='bitvm2-nova-actual-sharded-proving-failure/v1',passed=False,
            k=args.k,to_height=args.to,shards=args.shards,processes=processes,
            error_type=type(error).__name__,error=str(error),
            wall_seconds=time.perf_counter()-started,shard_set_accepted=False)
        (out/'failed.json').write_text(json.dumps(failure,indent=2)+'\n',encoding='utf-8')
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    parser.add_argument('--bin-dir',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--k',type=int,default=10)
    parser.add_argument('--to',type=int,default=40)
    parser.add_argument('--shards',type=int,default=2)
    parser.add_argument('--parallel',type=int,default=2)
    parser.add_argument('--export-parallel',type=int,default=2)
    parser.add_argument('--threads',type=int,default=2)
    parser.add_argument('--memory-mib',type=int,default=6144)
    parser.add_argument('--total-memory-mib',type=int,default=16384)
    parser.add_argument('--reserve-memory-mib',type=int,default=2048)
    parser.add_argument('--plan-only',action='store_true')
    parser.add_argument('--wall-seconds',type=float,default=1800)
    prove(parser.parse_args())


if __name__=='__main__':
    main()
