#!/usr/bin/env python3
"""Execute the bounded BABE transaction graph with valueless coins on isolated Core regtest.

Requires two real protocol public fixtures and the durable release adapter. The adapter is
invoked after Core confirms the selected challenge and can independently query this node.
The harness pre-signs every connector before broadcasting funding, then chooses an index.
Its receipt distinguishes native graph checks, mempool policy checks and mined spends.
"""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import secrets
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


CORE_VERSION = "v31.1.0"
CORE_ARCHIVE_SHA256 = "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
CORE_SOURCE_COMMIT = "9be056a8a72b624dae9623b2f7bded92c2a21c91"
CORE_SOURCE_URL = "https://github.com/bitcoin/bitcoin.git"
CORE_BUILD_SCHEMA = "babe-core-source-build/v1"
CORE_BUILD_PROFILE = {
    # Core preserves assertions and builds secp using the RelWithDebInfo C flags.
    "CMAKE_BUILD_TYPE": "Release", "CMAKE_CXX_FLAGS_RELEASE": "-O2",
    "CMAKE_C_FLAGS_RELEASE": "-O2", "CMAKE_C_FLAGS_RELWITHDEBINFO": "-O2",
    "BUILD_DAEMON": "ON", "BUILD_CLI": "ON", "ENABLE_WALLET": "ON",
    "BUILD_TESTS": "OFF", "BUILD_GUI": "OFF", "BUILD_BENCH": "OFF",
    "BUILD_FUZZ_BINARY": "OFF", "BUILD_BITCOIN_BIN": "OFF", "BUILD_TX": "OFF",
    "BUILD_UTIL": "OFF", "BUILD_WALLET_TOOL": "OFF", "ENABLE_IPC": "OFF",
    "WITH_CCACHE": "OFF",
}
PUBLIC_FIELDS = (
    "session_id", "commit1", "catalog_hash", "rows", "base_hashlocks",
    "retained_refute_hashes",
)
MAX_JSON_BYTES = 4 * 1024 * 1024


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git_metadata(source_root):
    try:
        head = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                              capture_output=True, timeout=10)
    except FileNotFoundError:
        return None
    if head.returncode:
        return None
    status = subprocess.run(["git", "-C", str(source_root), "status", "--porcelain=v1",
                             "--untracked-files=normal", "--", "."],
                            capture_output=True, check=True, timeout=10)
    return {"commit":head.stdout.decode().strip(), "crate_working_tree_dirty":bool(status.stdout)}


def source_snapshot(source_root):
    paths = sorted((source_root / "src").rglob("*.rs"))
    paths.extend([source_root / "Cargo.toml", source_root / "Cargo.lock", Path(__file__).resolve()])
    return {str(path.relative_to(source_root)):digest(path) for path in paths}


def json_file(path):
    raw = Path(path).read_bytes()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("fixture exceeds bounded JSON profile")
    return json.loads(raw)


def run_json(command, request):
    raw = json.dumps(request, separators=(",", ":")).encode()
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("adapter request exceeds bound")
    process = subprocess.run(command, input=raw, capture_output=True, timeout=120)
    if process.returncode:
        # Adapters must keep role secrets out of error output.
        raise RuntimeError(f"adapter {Path(command[0]).name} failed: {process.stderr.decode()[-2000:]}")
    if len(process.stdout) > MAX_JSON_BYTES:
        raise ValueError("adapter output exceeds bound")
    return json.loads(process.stdout)


class RpcError(RuntimeError):
    def __init__(self, error):
        self.error = error
        super().__init__(str(error))


class Core:
    def __init__(self, binaries, datadir):
        self.binaries = Path(binaries).resolve()
        self.datadir = Path(datadir).resolve()
        self.datadir.mkdir(parents=True, exist_ok=True)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.log = open(self.datadir / "process.log", "wb")
        self.process = subprocess.Popen([
            str(self.binaries / "bitcoind"), f"-datadir={self.datadir}", "-regtest=1",
            "-server=1", f"-rpcport={self.port}", "-rpcbind=127.0.0.1",
            "-listen=0", "-discover=0", "-dnsseed=0", "-connect=0", "-networkactive=0",
            "-txindex=1", "-fallbackfee=0.0002", "-dbcache=64", "-printtoconsole=0",
        ], stdout=self.log, stderr=subprocess.STDOUT)
        # The release process invokes bitcoin-cli and reads the same isolated settings.
        (self.datadir / "bitcoin.conf").write_text(f"regtest=1\n[regtest]\nrpcport={self.port}\n")
        for _ in range(200):
            try:
                info = self.rpc("getblockchaininfo")
                if info["chain"] != "regtest":
                    raise RuntimeError("refusing a non-regtest chain")
                self.rpc("createwallet", "babe-regtest")
                self.mine_address = self.rpc("getnewaddress", "mining", "bech32")
                self.mine(101)
                return
            except (OSError, RpcError):
                if self.process.poll() is not None:
                    raise RuntimeError((self.datadir / "process.log").read_text()[-4000:])
                time.sleep(0.1)
        raise TimeoutError("Core RPC did not become ready")

    def rpc(self, method, *params):
        cookie = (self.datadir / "regtest" / ".cookie").read_text().strip()
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/", data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Basic " + base64.b64encode(cookie.encode()).decode()},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            result = json.loads(error.read())
        if result.get("error"):
            raise RpcError(result["error"])
        return result["result"]

    def mine(self, count):
        return self.rpc("generatetoaddress", count, self.mine_address) if count else []

    def close(self):
        if self.process.poll() is None:
            try:
                self.rpc("stop")
            except (OSError, RpcError):
                self.process.terminate()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


class Harness:
    def __init__(self, args, node):
        self.args, self.node = args, node
        self.events, self.transactions, self.scenarios = [], {}, []
        self.operator_secret, self.challenger_secret = secrets.token_hex(32), secrets.token_hex(32)
        operator = node.rpc("getnewaddress", "operator", "bech32")
        challenger = node.rpc("getnewaddress", "challenger", "bech32")
        self.operator_destination = node.rpc("getaddressinfo", operator)["scriptPubKey"]
        self.challenger_destination = node.rpc("getaddressinfo", challenger)["scriptPubKey"]

    def event(self, kind, **fields):
        self.events.append({"event": kind, "height": self.node.rpc("getblockcount"), **fields})

    def adapter(self, request):
        return run_json([str(self.args.graph_bin)], request)

    def reject_release(self, name, request):
        process = subprocess.run([str(self.args.release_bin), "release"],
                                 input=json.dumps(request).encode(), capture_output=True,
                                 timeout=120)
        if process.returncode == 0:
            raise AssertionError(f"{name}: release adapter accepted an unauthorized challenge")
        if process.stdout.strip():
            raise AssertionError(f"{name}: rejected release produced an output payload")
        self.event("durable_release_rejected", check=name,
                   reason=process.stderr.decode()[-1200:])

    def base(self, fixture):
        return {
            "fixture": {key: fixture[key] for key in PUBLIC_FIELDS},
            "operator_secret": self.operator_secret, "challenger_secret": self.challenger_secret,
            "operator_destination": self.operator_destination,
            "challenger_destination": self.challenger_destination,
            "funding_sats": 1_000_000, "challenge_fee_sats": 2_000,
            "response_fee_sats": 5_000, "terminal_fee_sats": 2_000,
            "assertion_csv": 12, "labels_csv": 4, "payout_csv": 5,
        }

    def accept(self, name, transaction, expected, reason=None):
        result = self.node.rpc("testmempoolaccept", [transaction["hex"]])[0]
        allowed = result.get("allowed", False)
        if allowed != expected:
            raise AssertionError(f"{name}: expected allowed={expected}, received {result}")
        rejection = result.get("reject-reason", "")
        if reason is not None and reason not in rejection:
            raise AssertionError(f"{name}: expected reason containing {reason!r}, received {result}")
        self.event("mempool_acceptance", check=name, expected=expected, result=result)
        self.transactions[name] = transaction
        return result

    def broadcast_confirm(self, name, transaction):
        self.accept(name, transaction, True)
        txid = self.node.rpc("sendrawtransaction", transaction["hex"])
        if txid != transaction["txid"]:
            raise AssertionError("Core changed transaction identity")
        block_hash = self.node.mine(1)[0]
        observed = self.node.rpc("getrawtransaction", txid, True, block_hash)
        if observed["confirmations"] < 1:
            raise AssertionError("transaction was not confirmed")
        self.event("confirmed_spend", check=name, txid=txid, block_hash=block_hash,
                   vsize=observed["vsize"], weight_wu=observed["weight"])
        return observed

    def csv_boundary(self, name, transaction, parent_height, delay):
        height = self.node.rpc("getblockcount")
        target = parent_height + delay - 2
        if height > target:
            raise AssertionError("scenario advanced past the pre-maturity boundary")
        self.node.mine(target - height)
        self.accept(name + "_one_block_early", transaction, False, "non-BIP68-final")
        self.node.mine(1)
        if self.node.rpc("getblockcount") != parent_height + delay - 1:
            raise AssertionError("wrong relative-locktime boundary")
        result = self.broadcast_confirm(name + "_first_valid_block", transaction)
        if self.node.rpc("getblockcount") != parent_height + delay:
            raise AssertionError("spend confirmed at the wrong CSV height")
        return result

    def prepare_funding(self, name, fixture, fixture_path, state_path, reserve):
        base = self.base(fixture)
        address = self.adapter({**base, "mode": "address"})
        psbt = self.node.rpc("walletcreatefundedpsbt", [], {address["address"]: base["funding_sats"] / 100_000_000}, 0, {"fee_rate": 2})
        signed = self.node.rpc("walletprocesspsbt", psbt["psbt"])
        final = self.node.rpc("finalizepsbt", signed["psbt"])
        if not final["complete"]:
            raise AssertionError("wallet did not finish the test funding transaction")
        decoded = self.node.rpc("decoderawtransaction", final["hex"])
        matches = [v for v in decoded["vout"] if v["scriptPubKey"]["hex"] == address["script_pubkey"] and round(v["value"] * 100_000_000) == base["funding_sats"]]
        if len(matches) != 1:
            raise AssertionError("funding output is ambiguous")
        funding_outpoint = f"{decoded['txid']}:{matches[0]['n']}"
        funded = {**base, "funding_outpoint": funding_outpoint}
        prepared = self.adapter({**funded, "mode": "prepare", "funding_transaction_hex": final["hex"]})
        if prepared["graph_digest"] != address["graph_digest"]:
            raise AssertionError("pre-signature graph differs from funding destination")
        if len(prepared["branches"]) != len(fixture["rows"]):
            raise AssertionError("some alternatives were not pre-signed")
        if self.node.rpc("gettxout", decoded["txid"], matches[0]["n"]) is not None:
            raise AssertionError("funding already reached the chain before pre-signatures")
        self.event("all_connectors_verified_before_funding", scenario=name, graph_digest=prepared["graph_digest"], funding_outpoint=funding_outpoint, choices=len(prepared["branches"]))
        if reserve:
            reservation = run_json([str(self.args.release_bin), "bind-graph"], {
                "state_path":str(Path(state_path).resolve()),
                "public_fixture_path":str(Path(fixture_path).resolve()),
                "graph_config":prepared["graph_config"],
                "graph_digest":prepared["graph_digest"],
                "funding_outpoint":funding_outpoint,
            })
            if "selected_active_labels" in reservation:
                raise AssertionError("pre-funding graph reservation released labels")
            self.event("graph_reserved_in_trusted_authority_before_funding", scenario=name,
                       graph_digest=prepared["graph_digest"], funding_outpoint=funding_outpoint,
                       receipt=reservation)
        funding = {"hex":final["hex"], "txid":decoded["txid"], "wtxid":decoded["hash"], "vsize":decoded["vsize"], "weight_wu":decoded["weight"]}
        observed = self.broadcast_confirm(name + "_funding", funding)
        funding_height = self.node.rpc("getblockcount")
        self.event("funding_confirmed_before_selection", scenario=name, funding_outpoint=funding_outpoint, block_hash=observed["blockhash"])
        return funded, prepared, funding_height

    def scenario(self, name, fixture_path, state_path, selected, terminal):
        fixture = json_file(fixture_path)
        funded, prepared, funding_height = self.prepare_funding(
            name, fixture, fixture_path, state_path,
            terminal in ("operator_payout", "disprove"),
        )
        if terminal == "assertion_timeout":
            self.csv_boundary(name, prepared["assertion_timeout"], funding_height, funded["assertion_csv"])
            self.scenarios.append({"name":name, "terminal":terminal, "confirmed":True, "choices":len(fixture["rows"])})
            return
        presigned = {**funded, "operator_presignatures":prepared["operator_presignatures"], "challenger_presignatures":prepared["challenger_presignatures"]}
        chosen = self.adapter({**presigned, "mode":"select", "selected_index":selected})
        self.event("challenge_selected_after_funding", scenario=name, selected_index=selected, choices=len(prepared["branches"]), funding_height=funding_height)
        observed = self.broadcast_confirm(name + "_challenge", chosen["challenge"])
        challenge_height = self.node.rpc("getblockcount")
        if chosen["alternate_challenge"]:
            self.accept(name + "_competing_challenge_spent_input", chosen["alternate_challenge"], False, "missing-inputs")
        if terminal == "withholding":
            self.csv_boundary(name, chosen["withholding"], challenge_height, funded["labels_csv"])
            self.scenarios.append({"name":name, "terminal":terminal, "selected_index":selected, "confirmed":True})
            return
        hook = {
            "state_path":str(Path(state_path).resolve()), "public_fixture_path":str(Path(fixture_path).resolve()),
            "graph_config":prepared["graph_config"], "graph_digest":prepared["graph_digest"],
            "funding_outpoint":funded["funding_outpoint"], "selected_index":selected,
            "challenge_transaction_hex":observed["hex"], "challenge_txid":observed["txid"],
            "block_hash":observed["blockhash"], "confirmation_height":challenge_height,
            "confirmations":observed["confirmations"], "current_height":challenge_height,
            "bitcoin_cli_path":str(self.node.binaries / "bitcoin-cli"),
            "bitcoin_datadir":str(self.node.datadir),
        }
        if chosen["alternate_challenge"]:
            other = chosen["alternate_challenge"]
            unauthorized = {**hook, "selected_index":(selected + 1) % len(prepared["branches"]),
                            "challenge_transaction_hex":other["hex"], "challenge_txid":other["txid"]}
            self.reject_release(name + "_unconfirmed_alternative", unauthorized)
        changed_catalogue = copy.deepcopy(hook)
        changed_catalogue["graph_config"]["choices"][0]["input_bits"][0] ^= True
        self.reject_release(name + "_changed_catalogue", changed_catalogue)
        delivery = run_json([str(self.args.release_bin), "release"], hook)
        if not isinstance(delivery.get("selected_active_labels"), list):
            raise AssertionError("release adapter did not return active labels")
        self.event("durable_labels_released_after_confirmed_challenge", scenario=name, selected_index=selected, challenge_txid=observed["txid"], label_count=len(delivery["selected_active_labels"]))
        retry = run_json([str(self.args.release_bin), "release"], hook)
        if retry.get("release_was_exact_retry") is not True:
            raise AssertionError("release retry did not recover its prior durable authorization")
        if retry.get("selected_active_labels") != delivery["selected_active_labels"] or retry.get("refute") != delivery.get("refute"):
            raise AssertionError("release retry changed its exact delivery")
        self.event("exact_release_retry_after_process_restart", scenario=name,
                   selected_index=selected, identical_delivery=True)
        response_request = {**presigned, "mode":"respond", "selected_index":selected,
                            "observed_challenge_hex":observed["hex"], "selected_active_labels":delivery["selected_active_labels"],
                            "refute":delivery.get("refute")}
        responses = self.adapter(response_request)
        self.accept(name + "_wrong_input_label", responses["wrong_label_response"], False, "script-verify-flag-failed")
        self.accept(name + "_operator_redirect", responses["redirected_response"], False, "script-verify-flag-failed")
        self.broadcast_confirm(name + "_response", responses["response"])
        response_height = self.node.rpc("getblockcount")
        self.accept(name + "_withholding_after_response", responses["withholding"], False, "missing-inputs")
        if terminal == "operator_payout":
            if responses["disprove"] is not None:
                raise AssertionError("honest setup unexpectedly supplied a refutation label")
            self.csv_boundary(name + "_payout", responses["operator_payout"], response_height, funded["payout_csv"])
        elif terminal == "disprove":
            if responses["disprove"] is None:
                raise AssertionError("invalid committed claim did not yield a real refutation label")
            self.accept(name + "_wrong_refutation_label", responses["wrong_refute"], False, "script-verify-flag-failed")
            self.broadcast_confirm(name + "_disprove", responses["disprove"])
            self.accept(name + "_payout_after_disprove", responses["operator_payout"], False, "missing-inputs")
        else:
            raise ValueError("unknown terminal scenario")
        self.accept(name + "_replayed_response", responses["response"], False)
        self.scenarios.append({"name":name, "terminal":terminal, "selected_index":selected, "confirmed":True,
                               "response_vsize":responses["response"]["vsize"], "response_witness_items":responses["response"]["witness_items"]})


def verify_core_archive(args):
    archive = Path(args.core_archive)
    if digest(archive) != CORE_ARCHIVE_SHA256:
        raise AssertionError("Core archive differs from the official 31.1 SHA256SUMS pin")
    binary = Path(args.bitcoin_bin) / "bitcoind"
    with tarfile.open(archive, "r:gz") as tar:
        for name in ("bitcoind", "bitcoin-cli"):
            member = tar.extractfile("bitcoin-31.1/bin/" + name)
            expected = hashlib.sha256(member.read()).hexdigest()
            if digest(Path(args.bitcoin_bin) / name) != expected:
                raise AssertionError("Core executable differs from the verified release archive")
    version = subprocess.run([str(binary), "--version"], capture_output=True, check=True).stdout.decode().splitlines()[0]
    if CORE_VERSION not in version:
        raise AssertionError("unexpected Core version")
    return {"evidence_kind":"official-release-archive", "version":version,
            "archive_sha256":CORE_ARCHIVE_SHA256, "bitcoind_sha256":digest(binary),
            "bitcoin_cli_sha256":digest(Path(args.bitcoin_bin) / "bitcoin-cli"),
            "official_archive":"https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz",
            "official_checksums":"https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS"}


def core_git(source, *arguments):
    # The source-build mode uses a fresh checkout controlled by the CI workflow.
    # Ignore ambient Git repository overrides and disable executable fsmonitor hooks.
    environment = {key:value for key,value in os.environ.items()
                   if not key.startswith("GIT_")}
    environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
    process = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(source), *arguments],
        capture_output=True, check=True, timeout=60, env=environment,
    )
    return process.stdout


def core_regular_file(path, limit=None):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise AssertionError(f"Core provenance requires a regular file: {path.name}")
    if limit is not None and metadata.st_size > limit:
        raise AssertionError("Core build metadata exceeds size limit")
    return metadata


def core_source_snapshot(source):
    if Path(core_git(source, "rev-parse", "--show-toplevel").decode().strip()).resolve() != source:
        raise AssertionError("Core source path must be the checkout root")
    commit = core_git(source, "rev-parse", "HEAD").decode().strip()
    if commit != CORE_SOURCE_COMMIT:
        raise AssertionError("Core source commit differs from the pinned official commit")
    origin = core_git(source, "remote", "get-url", "--all", "origin").decode().splitlines()
    if origin != [CORE_SOURCE_URL]:
        raise AssertionError("Core source origin must be the exact official Git URL")
    if core_git(source, "status", "--porcelain=v1", "--untracked-files=no"):
        raise AssertionError("Core tracked source tree or index is dirty")
    tree = core_git(source, "rev-parse", "HEAD^{tree}").decode().strip()
    tracked = set()
    manifest = hashlib.sha256()
    for entry in core_git(source, "ls-tree", "-rz", "--full-tree", "HEAD").split(b"\0"):
        if not entry:
            continue
        descriptor, raw_name = entry.split(b"\t", 1)
        mode, kind, object_id = descriptor.split()
        name = raw_name.decode("utf-8")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] in (".git", "build"):
            raise AssertionError("unexpected path in pinned Core tree")
        tracked.add(name)
        path = source / relative
        for parent in relative.parents:
            if (source / parent).is_symlink():
                raise AssertionError("Core source ancestor became a symlink")
        metadata = path.lstat()
        if kind != b"blob":
            raise AssertionError("unsupported Git entry in Core source tree")
        if mode == b"120000" and stat.S_ISLNK(metadata.st_mode):
            content = os.fsencode(os.readlink(path))
        elif mode in (b"100644", b"100755") and stat.S_ISREG(metadata.st_mode):
            if bool(metadata.st_mode & 0o111) != (mode == b"100755"):
                raise AssertionError("Core tracked executable mode changed")
            content = path.read_bytes()
        else:
            raise AssertionError("Core tracked file type changed")
        # Direct contents checks also catch index assume-unchanged/skip-worktree flags.
        blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if blob.encode() != object_id:
            raise AssertionError("Core tracked file contents differ from the pinned tree")
        manifest.update(descriptor + b"\t" + raw_name + b"\0")
        manifest.update(hashlib.sha256(content).digest())
    for directory, names, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source)
        if relative == Path("."):
            names[:] = [name for name in names if name not in (".git", "build")]
            files = [name for name in files if name != ".git"]
        for name in files + [name for name in names if (Path(directory) / name).is_symlink()]:
            if (relative / name).as_posix() not in tracked:
                raise AssertionError("untracked Core source file outside the build directory")
    return {"source_commit":commit, "source_tree":tree, "source_git_url":origin[0],
            "tracked_source_sha256":manifest.hexdigest(), "tracked_source_files":len(tracked)}


def core_build_metadata(source):
    build = source / "build"
    cache_path, info_path = build / "CMakeCache.txt", build / "build-info.json"
    core_regular_file(cache_path, MAX_JSON_BYTES)
    core_regular_file(info_path, 256 * 1024)
    cache = {}
    for line in cache_path.read_text().splitlines():
        if not line or line.startswith(("#", "//")):
            continue
        key_type, separator, value = line.partition("=")
        key, colon, _ = key_type.partition(":")
        if not separator or not colon or not key or key in cache:
            raise AssertionError("malformed or duplicate CMake cache entry")
        cache[key] = value
    if cache.get("CMAKE_HOME_DIRECTORY") != str(source) or cache.get("CMAKE_CACHEFILE_DIR") != str(build):
        raise AssertionError("CMake cache belongs to another source or build directory")
    for key, expected in CORE_BUILD_PROFILE.items():
        if cache.get(key) != expected:
            raise AssertionError(f"unexpected Core build profile: {key}={cache.get(key)!r}; expected {expected!r}")
    for key in ("CMAKE_C_FLAGS", "CMAKE_C_FLAGS_RELEASE", "CMAKE_CXX_FLAGS", "CMAKE_CXX_FLAGS_RELEASE"):
        if any(flag.startswith("-g") for flag in shlex.split(cache.get(key, ""))):
            raise AssertionError("Core release build enables debug information")
    if not cache.get("CMAKE_CXX_COMPILER"):
        raise AssertionError("CMake cache omits the C++ compiler")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError("duplicate Core build metadata key")
            result[key] = value
        return result

    info = json.loads(info_path.read_text(), object_pairs_hook=unique_object)
    if not isinstance(info, dict) or info.get("schema") != CORE_BUILD_SCHEMA:
        raise AssertionError("unexpected Core build metadata schema")
    configure, command = info.get("configure_argv"), info.get("build_argv")
    for argv in (configure, command):
        if (not isinstance(argv, list) or len(argv) > 128 or
                not all(isinstance(arg, str) and 0 < len(arg) <= 4096 and "\0" not in arg for arg in argv)):
            raise AssertionError("invalid Core build command metadata")
    if configure[:5] != ["cmake", "-S", str(source), "-B", str(build)]:
        raise AssertionError("Core configure command uses unexpected paths")
    definitions = {}
    for flag in configure[5:]:
        if not flag.startswith("-D") or "=" not in flag:
            raise AssertionError("unexpected Core configure argument")
        key, value = flag[2:].split("=", 1)
        if key in definitions:
            raise AssertionError("duplicate Core configure definition")
        definitions[key] = value
    if definitions != CORE_BUILD_PROFILE:
        raise AssertionError("Core configure command differs from required profile")
    if (command[:6] != ["cmake", "--build", str(build), "--target", "bitcoind", "bitcoin-cli"] or
            len(command) != 8 or command[6] != "--parallel" or not command[7].isdigit() or
            not 1 <= int(command[7]) <= 64):
        raise AssertionError("Core build command must select only bitcoind and bitcoin-cli")
    if not isinstance(info.get("compiler_version"), str) or not info["compiler_version"].strip():
        raise AssertionError("Core build metadata omits compiler version")
    return {"cmake_cache_sha256":digest(cache_path), "build_info_sha256":digest(info_path),
            "configure_argv":configure, "build_argv":command,
            "compiler_path":cache["CMAKE_CXX_COMPILER"], "compiler_version":info["compiler_version"]}


def verify_core_source(args):
    source = Path(args.core_source).resolve(strict=True)
    binaries = source / "build" / "bin"
    if (source / "build").is_symlink() or binaries.is_symlink() or Path(args.bitcoin_bin).resolve(strict=True) != binaries:
        raise AssertionError("Core binaries must be in the pinned source/build/bin directory")
    provenance = {"evidence_kind":"trusted-ci-source-build", **core_source_snapshot(source),
                  **core_build_metadata(source)}
    for name, field in (("bitcoind", "bitcoind_sha256"), ("bitcoin-cli", "bitcoin_cli_sha256")):
        metadata = core_regular_file(binaries / name)
        if not metadata.st_mode & 0o111:
            raise AssertionError("Core binary is not executable")
        provenance[field] = digest(binaries / name)
    provenance["trust_basis"] = (
        "Pinned official source and measured local build artifacts from the trusted CI workflow; "
        "these hashes do not prove that a compiler used the recorded source or commands."
    )
    return provenance


def verify_core(args, expected=None):
    archive, source = getattr(args, "core_archive", None), getattr(args, "core_source", None)
    if bool(archive) == bool(source):
        raise AssertionError("select exactly one Core archive or source provenance mode")
    if expected is not None:
        for name, field in (("bitcoind", "bitcoind_sha256"), ("bitcoin-cli", "bitcoin_cli_sha256")):
            if digest(Path(args.bitcoin_bin) / name) != expected[field]:
                raise AssertionError("Core executable changed while the harness ran")
    if archive:
        result = verify_core_archive(args)
    else:
        result = verify_core_source(args)
        if expected is not None:
            if result != {key:value for key,value in expected.items() if key != "version"}:
                raise AssertionError("Core source/build provenance changed while the harness ran")
            result["version"] = expected["version"]
        else:
            version = subprocess.run([str(Path(args.bitcoin_bin) / "bitcoind"), "--version"],
                                     capture_output=True, check=True, timeout=30).stdout.decode().splitlines()[0]
            if CORE_VERSION not in version:
                raise AssertionError("unexpected Core version")
            result["version"] = version
    if expected is not None and result != expected:
        raise AssertionError("Core provenance changed while the harness ran")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-bin", type=Path, required=True)
    provenance = parser.add_mutually_exclusive_group(required=True)
    provenance.add_argument("--core-archive", type=Path)
    provenance.add_argument("--core-source", type=Path)
    parser.add_argument("--graph-bin", type=Path, required=True)
    parser.add_argument("--release-bin", type=Path, required=True)
    parser.add_argument("--honest-fixture", type=Path, required=True)
    parser.add_argument("--bad-fixture", type=Path, required=True)
    parser.add_argument("--honest-state", type=Path, required=True)
    parser.add_argument("--bad-state", type=Path, required=True)
    parser.add_argument("--honest-index", type=int, default=3)
    parser.add_argument("--bad-index", type=int, default=5)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    core = verify_core(args)
    source_root = Path(__file__).resolve().parent.parent
    before = source_snapshot(source_root)
    git_before = git_metadata(source_root)
    binaries_before = {"graph":digest(args.graph_bin), "release":digest(args.release_bin)}
    node = None
    try:
        with tempfile.TemporaryDirectory(prefix="babe-core-regtest-") as datadir:
            node = Core(args.bitcoin_bin, datadir)
            harness = Harness(args, node)
            harness.scenario("assertion_timeout", args.honest_fixture, args.honest_state, args.honest_index, "assertion_timeout")
            harness.scenario("withheld_labels", args.honest_fixture, args.honest_state, args.honest_index, "withholding")
            harness.scenario("honest_claim", args.honest_fixture, args.honest_state, args.honest_index, "operator_payout")
            harness.scenario("invalid_committed_claim", args.bad_fixture, args.bad_state, args.bad_index, "disprove")
            after = source_snapshot(source_root)
            if before != after:
                raise AssertionError("crate sources changed while the Core test ran")
            git_after = git_metadata(source_root)
            if (git_before or {}).get("commit") != (git_after or {}).get("commit"):
                raise AssertionError("source commit changed while the Core test ran")
            binaries_after = {"graph":digest(args.graph_bin), "release":digest(args.release_bin)}
            if binaries_before != binaries_after:
                raise AssertionError("adapter binaries changed while the Core test ran")
            verify_core(args, expected=core)
            receipt = {
                "schema":"babe-pilot/funded-regtest/v1", "status":"passed", "network":"regtest",
                "core":core, "source_sha256":before, "source_git":git_before,
                "graph_binary_sha256":binaries_before["graph"],
                "release_binary_sha256":binaries_before["release"],
                "public_fixture_sha256":{"honest":digest(args.honest_fixture), "invalid":digest(args.bad_fixture)},
                "scenarios":harness.scenarios, "events":harness.events,
                "scope":{"real_protocol_labels":True, "all_connectors_verified_before_funding":True,
                         "dynamic_choice_after_funding":True, "durable_release_after_core_confirmation":True,
                         "mempool_policy_executed":True, "valid_spends_mined":True,
                         "full_application_withdrawal":False, "reorg_rollback_exercised":False,
                         "independent_operator_challenger_processes":False},
            }
            (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            (args.out / "transactions.json").write_text(json.dumps(harness.transactions, indent=2) + "\n")
            node.close()
            node = None
    finally:
        if node is not None:
            node.close()
    print(json.dumps({"status":"passed", "receipt":str(args.out / "receipt.json"), "scenarios":len(receipt["scenarios"]), "checks":len(receipt["events"])}))


if __name__ == "__main__":
    main()
