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
import secrets
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


CORE_VERSION = "v31.1.0"
CORE_ARCHIVE_SHA256 = "b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
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


def verify_core(args):
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
    return {"version":version, "archive_sha256":CORE_ARCHIVE_SHA256, "bitcoind_sha256":digest(binary),
            "official_archive":"https://bitcoincore.org/bin/bitcoin-core-31.1/bitcoin-31.1-x86_64-linux-gnu.tar.gz",
            "official_checksums":"https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-bin", type=Path, required=True)
    parser.add_argument("--core-archive", type=Path, required=True)
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
