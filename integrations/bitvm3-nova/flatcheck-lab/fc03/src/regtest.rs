//! One bounded FC03 dispute on Bitcoin Core regtest, enforced by tapscript.
//!
//! Per claim, a Taproot output (NUMS internal key, script path only):
//!   claim output   C:  [unchallenged]  <D1> CSV DROP <op> CHECKSIG
//!                      [challenge i]   <i> DROP <op> CHECKSIGVERIFY <ch> CHECKSIG     (one leaf per row)
//!   challenge tx   spends C via leaf i; outputs X_i and OP_RETURN(challenge_id_i). The operator
//!                  pre-signs it (SIGHASH_DEFAULT), so outputs and the challenge id are fixed.
//!   challenge out  X_i:[respond]     DROP*k <ch> CHECKSIGVERIFY <op> CHECKSIG  (payload: k pushes)
//!                      [withheld]    <D2> CSV DROP <ch> CHECKSIG
//!   response tx    spends X_i via [respond]; the challenger pre-signs it; the witness carries the
//!                  response bytes the garbled row circuit evaluates.
//!   response out   R_i:[disprove]    SHA256 <H(refute label of circuit instance i)> EQUALVERIFY <ch> CHECKSIG
//!                      [operator]    <D3> CSV DROP <op> CHECKSIG
//! Bitcoin enforces: who may challenge (pre-signature), which row (the leaf), the response
//! deadline (D2), that only the holder of the circuit's refute label can disprove, and the
//! operator's payout after D3. It does not check the garbling or the label delivery: see
//! `trust` in the output.
use crate::{
    cases::{challenge_for, locate_fault},
    circuit::{inputs, row::RowKnown, run},
    enc,
    fixture::{self, Committed, Toy},
    flatmerkle, merkle,
    protocol::*,
    sha,
};
use bitcoin::{
    absolute::LockTime,
    consensus::encode::{deserialize, serialize_hex},
    hashes::Hash,
    key::{Keypair, Secp256k1},
    opcodes::all::{OP_2DROP, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_RETURN, OP_SHA256},
    script::{Builder, PushBytesBuf},
    secp256k1::{All, Message, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use ff::Field;
use nova_snark::provider::PallasEngine;
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};

type E = PallasEngine;
pub const D1: u16 = 6;
pub const D2: u16 = 6;
pub const D3: u16 = 6;
const BOND: u64 = 200_000;
const FEE_RATE: u64 = 2; // sat/vB

const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47,
    0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

struct Node {
    cli: String,
    datadir: String,
    rpcport: u16,
    child: Child,
}

impl Node {
    fn base(&self) -> Vec<String> {
        vec!["-regtest".into(), format!("-datadir={}", self.datadir), format!("-rpcport={}", self.rpcport)]
    }
    fn call(&self, wallet: bool, args: &[&str]) -> Result<String, String> {
        let mut a = self.base();
        if wallet {
            a.push("-rpcwallet=fc03".into());
        }
        a.extend(args.iter().map(|s| s.to_string()));
        let o = Command::new(&self.cli).args(&a).output().map_err(|e| format!("bitcoin-cli: {e}"))?;
        if o.status.success() {
            Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else {
            Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
        }
    }
    fn rpc(&self, args: &[&str]) -> Result<String, String> {
        self.call(false, args)
    }
    fn w(&self, args: &[&str]) -> Result<String, String> {
        self.call(true, args)
    }
    fn json(&self, args: &[&str]) -> Result<Value, String> {
        serde_json::from_str(&self.rpc(args)?).map_err(|e| e.to_string())
    }
    fn mine(&self, n: u32, addr: &str) -> Result<(), String> {
        self.rpc(&["generatetoaddress", &n.to_string(), addr]).map(|_| ())
    }
    fn height(&self) -> Result<u64, String> {
        self.rpc(&["getblockcount"]).and_then(|s| s.parse().map_err(|e| format!("{e}")))
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.rpc(&["stop"]);
        let _ = self.child.wait();
    }
}

fn start(bitcoind: &str, cli: &str, root: &str) -> Result<Node, String> {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let datadir = format!("{root}/fc03-regtest-{stamp}");
    std::fs::create_dir_all(&datadir).map_err(|e| e.to_string())?;
    let rpcport = 18000 + (stamp % 1000) as u16 * 2;
    let child = Command::new(bitcoind)
        .args([
            "-regtest",
            &format!("-datadir={datadir}"),
            &format!("-rpcport={rpcport}"),
            &format!("-port={}", rpcport + 1),
            "-listen=0",
            "-server=1",
            "-txindex=1",
            "-fallbackfee=0.0001",
            "-printtoconsole=0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("bitcoind: {e}"))?;
    let node = Node { cli: cli.into(), datadir, rpcport, child };
    for _ in 0..120 {
        if let Ok(info) = node.json(&["getblockchaininfo"]) {
            if info["chain"] != "regtest" {
                return Err(format!("refusing to run: node chain is {}", info["chain"]));
            }
            return Ok(node);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err("bitcoind RPC did not come up".into())
}

fn key(label: &str, secp: &Secp256k1<All>) -> Keypair {
    let mut e = enc::Enc::new("regtest-key");
    e.field("label", label.as_bytes());
    Keypair::from_secret_key(secp, &SecretKey::from_slice(&e.digest()).unwrap())
}

fn push(b: &[u8]) -> PushBytesBuf {
    PushBytesBuf::try_from(b.to_vec()).unwrap()
}

fn timeout_leaf(d: u16, pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new().push_int(d as i64).push_opcode(OP_CSV).push_opcode(OP_DROP).push_x_only_key(pk).push_opcode(OP_CHECKSIG).into_script()
}

fn two_sig_leaf(tag: i64, drops: usize, first: &XOnlyPublicKey, second: &XOnlyPublicKey) -> ScriptBuf {
    let mut b = Builder::new();
    if tag >= 0 {
        b = b.push_int(tag).push_opcode(OP_DROP);
    }
    b = self::drops(b, drops);
    b.push_x_only_key(first).push_opcode(OP_CHECKSIGVERIFY).push_x_only_key(second).push_opcode(OP_CHECKSIG).into_script()
}

fn hashlock_leaf(h: &[u8; 32], pk: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new().push_opcode(OP_SHA256).push_slice(push(h)).push_opcode(OP_EQUALVERIFY).push_x_only_key(pk).push_opcode(OP_CHECKSIG).into_script()
}

fn tree(secp: &Secp256k1<All>, leaves: &[ScriptBuf]) -> TaprootSpendInfo {
    // Balanced-enough: place leaves with depths from a Huffman build of equal weights.
    let weighted: Vec<(u32, ScriptBuf)> = leaves.iter().map(|l| (1u32, l.clone())).collect();
    TaprootBuilder::with_huffman_tree(weighted).unwrap().finalize(secp, XOnlyPublicKey::from_slice(&NUMS).unwrap()).unwrap()
}

fn spk(info: &TaprootSpendInfo) -> ScriptBuf {
    ScriptBuf::new_p2tr_tweaked(info.output_key())
}

fn sign(secp: &Secp256k1<All>, tx: &Transaction, prev: &TxOut, leaf: &ScriptBuf, k: &Keypair) -> Vec<u8> {
    let h = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev.clone()]), TapLeafHash::from_script(leaf, LeafVersion::TapScript), TapSighashType::Default)
        .unwrap();
    secp.sign_schnorr_no_aux_rand(&Message::from_digest(h.to_byte_array()), k).as_ref().to_vec()
}

fn witness(items: &[Vec<u8>], leaf: &ScriptBuf, info: &TaprootSpendInfo) -> Witness {
    let mut w = Witness::new();
    for i in items {
        w.push(i);
    }
    w.push(leaf.as_bytes());
    w.push(info.control_block(&(leaf.clone(), LeafVersion::TapScript)).unwrap().serialize());
    w
}

/// One-input transaction; the fee is set from the exact vsize, computed with placeholder
/// signatures of the final length.
fn spend(prev: OutPoint, prev_value: u64, seq: Sequence, outs: Vec<TxOut>, dummy_items: &[Vec<u8>], leaf: &ScriptBuf, info: &TaprootSpendInfo) -> Transaction {
    let mut tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: vec![TxIn { previous_output: prev, script_sig: ScriptBuf::new(), sequence: seq, witness: Witness::new() }], output: outs };
    tx.input[0].witness = witness(dummy_items, leaf, info);
    let fee = tx.vsize() as u64 * FEE_RATE;
    tx.output[0].value = Amount::from_sat(prev_value - fee - tx.output.iter().skip(1).map(|o| o.value.to_sat()).sum::<u64>());
    tx.input[0].witness = Witness::new();
    tx
}

fn op_return(data: &[u8; 32]) -> TxOut {
    TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new_op_return(push(data)) }
}

fn measure(tx: &Transaction, prev_value: u64) -> Value {
    let out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    json!({"txid": tx.compute_txid().to_string(), "vsize": tx.vsize(), "weight": tx.weight().to_wu(), "fee_sats": prev_value - out, "witness_items": tx.input[0].witness.len()})
}

struct Claimed {
    claim: FlatCheckClaim,
    committed: Committed,
    info: TaprootSpendInfo,
    leaves_challenge: Vec<ScriptBuf>,
    leaf_unchallenged: ScriptBuf,
    outpoint: OutPoint,
    funding: Value,
    /// Per row: (challenge, output labels (accept, refute), challenge-output tree, response-output tree, leaves).
    rows: Vec<RowGraph>,
}

struct RowGraph {
    challenge: FlatCheckChallenge,
    accept: u128,
    refute: u128,
    x_info: TaprootSpendInfo,
    leaf_respond: ScriptBuf,
    leaf_withheld: ScriptBuf,
    r_info: TaprootSpendInfo,
    leaf_disprove: ScriptBuf,
    leaf_operator: ScriptBuf,
    seed: u64,
}

/// Bitcoin Core relay policy caps each initial tapscript stack item at 80 bytes
/// (MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE in policy.h). This is separate from the OP_RETURN
/// data-carrier limit, which Core 30 raised (-datacarriersize defaults to 100,000 bytes in 31.1).
/// Response payloads therefore travel in the witness as 80-byte pushes.
pub const CHUNK: usize = 80;

fn payload_chunks(b: &[u8]) -> Vec<Vec<u8>> {
    b.chunks(CHUNK).map(|c| c.to_vec()).collect()
}

fn drops(mut b: Builder, k: usize) -> Builder {
    for _ in 0..k / 2 {
        b = b.push_opcode(OP_2DROP);
    }
    if k % 2 == 1 {
        b = b.push_opcode(OP_DROP);
    }
    b
}

fn seed_for(claim_id: &[u8; 32], row: u32) -> u64 {
    let mut e = enc::Enc::new("regtest-garbling-seed");
    e.field("claim", claim_id).u32("row", row);
    u64::from_le_bytes(e.digest()[..8].try_into().unwrap())
}

fn response_payload(toy: &Toy<E>, claim: &FlatCheckClaim, c: &Committed, ch: &FlatCheckChallenge) -> Vec<u8> {
    let tc = &toy.pinned.tc;
    let r = toy.respond(c, ch);
    let all = inputs::row_input(tc, claim, ch, r.as_ref()).unwrap();
    all[inputs::common_len(tc)..].to_vec()
}

#[allow(clippy::too_many_arguments)]
fn setup_claim(node: &Node, secp: &Secp256k1<All>, toy: &Toy<E>, op: &Keypair, ch: &Keypair, committed: Committed, label: &str) -> Result<Claimed, String> {
    let tc = &toy.pinned.tc;
    let replay = ReplayDomain { network: "regtest".into(), contract_id: {
        let mut e = enc::Enc::new("regtest-contract");
        e.field("operator", &op.x_only_public_key().0.serialize()).field("challenger", &ch.x_only_public_key().0.serialize()).field("label", label.as_bytes());
        e.digest()
    } };
    let claim = Toy::<E>::claim_for(&toy.nova, tc, &committed, replay);
    let (opk, chk) = (op.x_only_public_key().0, ch.x_only_public_key().0);
    let n_in = inputs::row_input_len(tc) * 8;
    let k = RowKnown::new(tc);
    let which = run::Which::Row(k);
    let mut rows = Vec::new();
    let mut leaves_challenge = Vec::new();
    for row in 0..tc.num_cons {
        let mut chal = challenge_for(&claim, ChallengeKind::Row { row }, "regtest");
        chal.challenger = chk.serialize();
        let seed = seed_for(&claim.id(), row);
        let (accept, refute) = run::output_labels(&which, n_in, seed);
        let k_chunks = payload_chunks(&response_payload(toy, &claim, &committed, &chal)).len();
        let leaf_respond = two_sig_leaf(-1, k_chunks, &chk, &opk);
        let leaf_withheld = timeout_leaf(D2, &chk);
        let x_info = tree(secp, &[leaf_respond.clone(), leaf_withheld.clone()]);
        let leaf_disprove = hashlock_leaf(&sha::sha256(&refute.to_le_bytes()), &chk);
        let leaf_operator = timeout_leaf(D3, &opk);
        let r_info = tree(secp, &[leaf_disprove.clone(), leaf_operator.clone()]);
        leaves_challenge.push(two_sig_leaf(row as i64, 0, &opk, &chk));
        rows.push(RowGraph { challenge: chal, accept, refute, x_info, leaf_respond, leaf_withheld, r_info, leaf_disprove, leaf_operator, seed });
    }
    let leaf_unchallenged = timeout_leaf(D1, &opk);
    let mut all = vec![leaf_unchallenged.clone()];
    all.extend(leaves_challenge.iter().cloned());
    let info = tree(secp, &all);
    // The claim transaction: bond to the dispute output + OP_RETURN(claim id), wallet-funded.
    let addr = bitcoin::Address::p2tr_tweaked(info.output_key(), bitcoin::Network::Regtest).to_string();
    let outs = format!("[{{\"{addr}\": {:.8}}}, {{\"data\": \"{}\"}}]", BOND as f64 / 1e8, hex::encode(claim.id()));
    let raw = node.w(&["createrawtransaction", "[]", &outs])?;
    let funded: Value = serde_json::from_str(&node.w(&["fundrawtransaction", &raw, "{\"fee_rate\": 2}"])?).map_err(|e| e.to_string())?;
    let signed: Value = serde_json::from_str(&node.w(&["signrawtransactionwithwallet", funded["hex"].as_str().unwrap()])?).map_err(|e| e.to_string())?;
    let hex_tx = signed["hex"].as_str().unwrap().to_string();
    let txid = node.rpc(&["sendrawtransaction", &hex_tx])?;
    let tx: Transaction = deserialize(&hex::decode(&hex_tx).unwrap()).unwrap();
    let vout = tx.output.iter().position(|o| o.script_pubkey == spk(&info)).unwrap() as u32;
    let funding = json!({"txid": txid, "vsize": tx.vsize(), "weight": tx.weight().to_wu(), "fee_sats": (funded["fee"].as_f64().unwrap() * 1e8).round() as u64, "op_return_claim_id": hex::encode(claim.id()), "taptree_leaves": all.len()});
    Ok(Claimed { claim, committed, info, leaves_challenge, leaf_unchallenged, outpoint: OutPoint { txid: txid.parse::<Txid>().unwrap(), vout }, funding, rows })
}

fn send(node: &Node, tx: &Transaction) -> Result<String, String> {
    node.rpc(&["sendrawtransaction", &serialize_hex(tx)])
}

fn challenge_tx(secp: &Secp256k1<All>, c: &Claimed, row: usize, op: &Keypair, ch: &Keypair, corrupt_ch_sig: bool) -> (Transaction, TxOut) {
    let prev = TxOut { value: Amount::from_sat(BOND), script_pubkey: spk(&c.info) };
    let g = &c.rows[row];
    let leaf = &c.leaves_challenge[row];
    let outs = vec![TxOut { value: Amount::ZERO, script_pubkey: spk(&g.x_info) }, op_return(&g.challenge.id())];
    let mut tx = spend(c.outpoint, BOND, Sequence::ENABLE_RBF_NO_LOCKTIME, outs, &[vec![0; 64], vec![0; 64]], leaf, &c.info);
    let op_presig = sign(secp, &tx, &prev, leaf, op);
    let mut ch_sig = sign(secp, &tx, &prev, leaf, ch);
    if corrupt_ch_sig {
        ch_sig[5] ^= 1;
    }
    // stack: [ch_sig, op_sig] with op_sig on top (consumed first by <op> CHECKSIGVERIFY).
    tx.input[0].witness = witness(&[ch_sig, op_presig], leaf, &c.info);
    (tx, prev)
}

fn response_tx(secp: &Secp256k1<All>, c: &Claimed, row: usize, chal_tx: &Transaction, payload: &[u8], op: &Keypair, ch: &Keypair) -> (Transaction, TxOut) {
    let g = &c.rows[row];
    let prev = chal_tx.output[0].clone();
    let chunks = payload_chunks(payload);
    let mut dummy = vec![vec![0u8; 64], vec![0u8; 64]];
    dummy.extend(chunks.iter().cloned());
    let outs = vec![TxOut { value: Amount::ZERO, script_pubkey: spk(&g.r_info) }];
    let mut tx = spend(OutPoint { txid: chal_tx.compute_txid(), vout: 0 }, prev.value.to_sat(), Sequence::ENABLE_RBF_NO_LOCKTIME, outs, &dummy, &g.leaf_respond, &g.x_info);
    let ch_presig = sign(secp, &tx, &prev, &g.leaf_respond, ch);
    let op_sig = sign(secp, &tx, &prev, &g.leaf_respond, op);
    // stack bottom->top: op_sig, ch_sig, chunk_0 .. chunk_{k-1}; DROP*k, then <ch> CSV, <op> CS.
    let mut items = vec![op_sig, ch_presig];
    items.extend(chunks);
    tx.input[0].witness = witness(&items, &g.leaf_respond, &g.x_info);
    (tx, prev)
}

/// Spend a single-signature (optionally preimage-gated) leaf to a fresh wallet address.
#[allow(clippy::too_many_arguments)]
fn simple_spend(secp: &Secp256k1<All>, prev_tx: &Transaction, vout: u32, info: &TaprootSpendInfo, leaf: &ScriptBuf, seq: Sequence, key: &Keypair, preimage: Option<&[u8]>, dest: &ScriptBuf) -> (Transaction, TxOut) {
    let prev = prev_tx.output[vout as usize].clone();
    let mut dummy = vec![vec![0u8; 64]];
    if let Some(p) = preimage {
        dummy.push(p.to_vec());
    }
    let outs = vec![TxOut { value: Amount::ZERO, script_pubkey: dest.clone() }];
    let mut tx = spend(OutPoint { txid: prev_tx.compute_txid(), vout }, prev.value.to_sat(), seq, outs, &dummy, leaf, info);
    let sig = sign(secp, &tx, &prev, leaf, key);
    let mut items = vec![sig];
    if let Some(p) = preimage {
        items.push(p.to_vec());
    }
    tx.input[0].witness = witness(&items, leaf, info);
    (tx, prev)
}

/// Read a transaction back from the chain (mempool or one of the last 12 blocks), without
/// relying on the asynchronously built txindex.
fn tx_of(node: &Node, txid: &str) -> Transaction {
    let mut h = node.rpc(&["getrawtransaction", txid]).ok();
    if h.is_none() {
        let tip = node.height().unwrap();
        for ht in (tip.saturating_sub(12)..=tip).rev() {
            let bh = node.rpc(&["getblockhash", &ht.to_string()]).unwrap();
            if let Ok(x) = node.rpc(&["getrawtransaction", txid, "0", &bh]) {
                h = Some(x);
                break;
            }
        }
    }
    deserialize(&hex::decode(h.expect("transaction on chain")).unwrap()).unwrap()
}

/// The challenger's evaluation: rebuild the circuit input from the claim it holds, the on-chain
/// challenge and the response bytes read back from the confirmed response witness.
fn evaluate(toy: &Toy<E>, c: &Claimed, row: usize, resp_onchain: &Transaction) -> (run::GarbleReport, bool) {
    let tc = &toy.pinned.tc;
    let wit = &resp_onchain.input[0].witness;
    let n = wit.len();
    // witness: op_sig, ch_sig, chunks..., script, control block
    let payload: Vec<u8> = (2..n - 2).flat_map(|i| wit.nth(i).unwrap().to_vec()).collect();
    let g = &c.rows[row];
    let mut bytes = inputs::common(tc, &c.claim, &g.challenge).unwrap();
    bytes.extend_from_slice(&payload);
    let rep = run::garble_and_evaluate(&run::Which::Row(RowKnown::new(tc)), inputs::bits(&bytes), g.seed);
    let matches_labels = rep.accept_label == g.accept && rep.refute_label == g.refute;
    (rep, matches_labels)
}

pub fn run(bitcoind: &str, cli: &str, root: &str) -> Result<Value, String> {
    let secp = Secp256k1::new();
    let node = start(bitcoind, cli, root)?;
    let chain = node.json(&["getblockchaininfo"])?;
    node.rpc(&["createwallet", "fc03"])?;
    let addr = node.w(&["getnewaddress", "", "bech32m"])?;
    node.mine(101, &addr)?;
    let dest = addr
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| e.to_string())?
        .require_network(bitcoin::Network::Regtest)
        .map_err(|e| e.to_string())?;
    let op = key("operator", &secp);
    let ch = key("challenger", &secp);
    let toy = Toy::<E>::new(0xFC03_0001);
    let mut log: Vec<Value> = Vec::new();
    let mut checks: Vec<Value> = Vec::new();
    let mut ok = true;
    let mut expect = |name: &str, want_ok: bool, res: Result<String, String>, detail: Value| {
        let pass = res.is_ok() == want_ok;
        eprintln!("[{}] {name}: {:?}", if pass { "pass" } else { "FAIL" }, res);
        ok &= pass;
        checks.push(json!({"check": name, "expected": if want_ok {"accepted"} else {"rejected"}, "actual": match &res { Ok(_) => "accepted".to_string(), Err(e) => format!("rejected: {e}") }, "pass": pass, "detail": detail}));
    };

    // ---------------- honest claim, challenged on row 2: operator wins after D3.
    let honest = setup_claim(&node, &secp, &toy, &op, &ch, toy.committed.clone(), "honest")?;
    // The dishonest claim commits W with W2 + 1: row 3 is violated.
    let mut wbad: Vec<_> = toy.committed.w.iter().map(|b| crate::field::fe_from_bytes::<<E as nova_snark::traits::Engine>::Scalar>(b).unwrap()).collect();
    wbad[2] += <E as nova_snark::traits::Engine>::Scalar::ONE;
    let ebytes: Vec<_> = toy.committed.e.iter().map(|b| crate::field::fe_from_bytes::<<E as nova_snark::traits::Engine>::Scalar>(b).unwrap()).collect();
    let (_, r_w, r_e) = toy.nova.w.derandomize();
    let bad_c = fixture::commit::<E>(&toy.gens, toy.pinned.tc.ck_len as usize, &wbad, r_w, &ebytes, r_e);
    let dishonest = setup_claim(&node, &secp, &toy, &op, &ch, bad_c, "dishonest")?;
    let silent = setup_claim(&node, &secp, &toy, &op, &ch, toy.committed.clone(), "withheld")?;
    let idle = setup_claim(&node, &secp, &toy, &op, &ch, toy.committed.clone(), "unchallenged")?;
    node.mine(1, &addr)?;
    for (n, c) in [("honest", &honest), ("dishonest", &dishonest), ("withheld", &silent), ("unchallenged", &idle)] {
        log.push(json!({"tx": format!("claim/{n}"), "measure": c.funding}));
    }

    // ---------------- A. unchallenged claim: operator reclaims after D1.
    let (t, _) = simple_spend(&secp, &tx_of(&node, &idle.outpoint.txid.to_string()), idle.outpoint.vout, &idle.info, &idle.leaf_unchallenged, Sequence::from_height(D1), &op, None, &dest.script_pubkey());
    expect("unchallenged payout before D1", false, send(&node, &t), json!({"blocks_since_claim": 1, "csv": D1}));
    node.mine(D1 as u32 - 1, &addr)?;
    expect("unchallenged payout at D1", true, send(&node, &t), json!({"csv": D1}));
    log.push(json!({"tx": "unchallenged-payout", "measure": measure(&t, BOND)}));

    // ---------------- B. honest claim, row 2.
    let row = 2usize;
    let (ctx, prev) = challenge_tx(&secp, &honest, row, &op, &ch, false);
    expect("challenge (row 2, honest claim)", true, send(&node, &ctx), json!({}));
    log.push(json!({"tx": "challenge/honest-row2", "measure": measure(&ctx, prev.value.to_sat())}));
    node.mine(1, &addr)?;
    let payload = response_payload(&toy, &honest.claim, &honest.committed, &honest.rows[row].challenge);
    let (rtx, rprev) = response_tx(&secp, &honest, row, &ctx, &payload, &op, &ch);
    expect("response (honest, row 2)", true, send(&node, &rtx), json!({"payload_bytes": payload.len()}));
    log.push(json!({"tx": "response/honest-row2", "payload_bytes": payload.len(), "measure": measure(&rtx, rprev.value.to_sat())}));
    node.mine(1, &addr)?;
    let (rep, labels_ok) = evaluate(&toy, &honest, row, &tx_of(&node, &rtx.compute_txid().to_string()));
    let g = &honest.rows[row];
    let got = rep.evaluated_label;
    let (dtx, _) = simple_spend(&secp, &rtx, 0, &g.r_info, &g.leaf_disprove, Sequence::ENABLE_RBF_NO_LOCKTIME, &ch, Some(&got.to_le_bytes()), &dest.script_pubkey());
    expect("disprove with the label an honest response yields", false, send(&node, &dtx), json!({"evaluator_got": if got == g.accept {"accept label"} else if got == g.refute {"refute label"} else {"other"}, "labels_match_committed": labels_ok, "ciphertexts": rep.ciphertexts, "garble_and_evaluate_seconds": rep.garble_and_evaluate_seconds}));
    let (otx, oprev) = simple_spend(&secp, &rtx, 0, &g.r_info, &g.leaf_operator, Sequence::from_height(D3), &op, None, &dest.script_pubkey());
    expect("operator payout before D3", false, send(&node, &otx), json!({}));
    node.mine(D3 as u32 - 1, &addr)?;
    expect("operator payout at D3", true, send(&node, &otx), json!({"csv": D3}));
    log.push(json!({"tx": "operator-payout/honest", "measure": measure(&otx, oprev.value.to_sat())}));

    // ---------------- C. dishonest claim: the challenger locates row 3 and disproves.
    let fault = locate_fault(&toy, &dishonest.claim, &dishonest.committed);
    let frow = match fault {
        Some(ChallengeKind::Row { row }) => row as usize,
        other => return Err(format!("expected a row fault, found {other:?}")),
    };
    let (ctx2, prev2) = challenge_tx(&secp, &dishonest, frow, &op, &ch, false);
    expect("challenge (dishonest claim, located row)", true, send(&node, &ctx2), json!({"located": format!("{fault:?}")}));
    log.push(json!({"tx": "challenge/dishonest", "measure": measure(&ctx2, prev2.value.to_sat())}));
    node.mine(1, &addr)?;
    let payload2 = response_payload(&toy, &dishonest.claim, &dishonest.committed, &dishonest.rows[frow].challenge);
    let (rtx2, rprev2) = response_tx(&secp, &dishonest, frow, &ctx2, &payload2, &op, &ch);
    expect("response (dishonest claim)", true, send(&node, &rtx2), json!({"payload_bytes": payload2.len()}));
    log.push(json!({"tx": "response/dishonest", "measure": measure(&rtx2, rprev2.value.to_sat())}));
    node.mine(1, &addr)?;
    let (rep2, labels_ok2) = evaluate(&toy, &dishonest, frow, &tx_of(&node, &rtx2.compute_txid().to_string()));
    let g2 = &dishonest.rows[frow];
    let (wrong_key, _) = simple_spend(&secp, &rtx2, 0, &g2.r_info, &g2.leaf_disprove, Sequence::ENABLE_RBF_NO_LOCKTIME, &op, Some(&rep2.evaluated_label.to_le_bytes()), &dest.script_pubkey());
    expect("disprove signed by the operator's key", false, send(&node, &wrong_key), json!({}));
    let (dtx2, dprev2) = simple_spend(&secp, &rtx2, 0, &g2.r_info, &g2.leaf_disprove, Sequence::ENABLE_RBF_NO_LOCKTIME, &ch, Some(&rep2.evaluated_label.to_le_bytes()), &dest.script_pubkey());
    expect("disprove with the refute label", true, send(&node, &dtx2), json!({"evaluator_got": if rep2.evaluated_label == g2.refute {"refute label"} else {"other"}, "labels_match_committed": labels_ok2}));
    log.push(json!({"tx": "disprove/dishonest", "measure": measure(&dtx2, dprev2.value.to_sat())}));
    let (late_op, _) = simple_spend(&secp, &rtx2, 0, &g2.r_info, &g2.leaf_operator, Sequence::from_height(D3), &op, None, &dest.script_pubkey());
    node.mine(D3 as u32, &addr)?;
    expect("operator payout after a confirmed disprove (output already spent)", false, send(&node, &late_op), json!({}));

    // ---------------- D. withheld response; E. invalid signatures; F. replay.
    let (bad_sig, _) = challenge_tx(&secp, &silent, 1, &op, &ch, true);
    expect("challenge with a corrupted challenger signature", false, send(&node, &bad_sig), json!({}));
    let (mut swapped, prevs) = challenge_tx(&secp, &silent, 1, &op, &ch, false);
    {
        // The operator's pre-signature for row 0's leaf replayed on row 1's leaf.
        let (t0, _) = challenge_tx(&secp, &silent, 0, &op, &ch, false);
        let op0 = t0.input[0].witness.nth(1).unwrap().to_vec();
        let chs = sign(&secp, &swapped, &prevs, &silent.leaves_challenge[1], &ch);
        swapped.input[0].witness = witness(&[chs, op0], &silent.leaves_challenge[1], &silent.info);
    }
    expect("operator pre-signature of another row's leaf", false, send(&node, &swapped), json!({}));
    let (mut replay, _) = challenge_tx(&secp, &dishonest, 1, &op, &ch, false);
    replay.input[0].previous_output = silent.outpoint;
    expect("challenge pre-signed for another claim replayed on this claim's output", false, send(&node, &replay), json!({}));
    let (ctx3, prev3) = challenge_tx(&secp, &silent, 1, &op, &ch, false);
    expect("challenge (row 1, operator will stay silent)", true, send(&node, &ctx3), json!({}));
    node.mine(1, &addr)?;
    let g3 = &silent.rows[1];
    let (wtx, wprev) = simple_spend(&secp, &ctx3, 0, &g3.x_info, &g3.leaf_withheld, Sequence::from_height(D2), &ch, None, &dest.script_pubkey());
    expect("withheld-response claim before D2", false, send(&node, &wtx), json!({"csv": D2}));
    let h0 = node.height()?;
    node.mine(D2 as u32 - 1, &addr)?;
    expect("withheld-response claim at D2", true, send(&node, &wtx), json!({"csv": D2, "challenge_confirmed_height": h0, "spend_height": node.height()? + 1}));
    log.push(json!({"tx": "withheld-payout", "measure": measure(&wtx, wprev.value.to_sat())}));
    let _ = prev3;
    node.mine(1, &addr)?;

    // ---------------- Publication cost of the same row response: FlatMerkle vs Merkle openings,
    // and a whole FlatMerkle commitment checked by OP_SHA256 in tapscript.
    let pub_cost = publication(&node, &secp, &toy, &op, &addr, &dest.script_pubkey())?;

    Ok(json!({
        "chain": chain["chain"], "bitcoind": node.rpc(&["-version"]).unwrap_or_default().lines().next().unwrap_or("").to_string(),
        "network_note": "regtest only: the harness refuses any node whose getblockchaininfo.chain is not regtest; keys are derived from fixed test labels",
        "deadlines_blocks": {"unchallenged_D1": D1, "response_D2": D2, "operator_payout_after_response_D3": D3},
        "fee_rate_sat_per_vb": FEE_RATE, "bond_sats": BOND,
        "transactions": log, "checks": checks, "all_checks_pass": ok, "publication": pub_cost,
        "enforced_by_bitcoin": [
            "only the pinned challenger, with the operator's pre-signature, can open a challenge, and only through the leaf of the challenged row",
            "the challenge id is fixed by the pre-signed OP_RETURN output",
            "a missing response lets the challenger take the bond after D2 blocks (BIP68 relative locktime)",
            "only the preimage of SHA256(refute label) of that row's garbled circuit, plus the challenger's signature, spends the disprove leaf",
            "an unrefuted response pays the operator after D3 blocks",
        ],
        "trust": [
            "T1 garbling: the operator garbles the row circuit; nothing here checks the tables were generated for the pinned circuit (BitVM3 needs cut-and-choose or a proof of correct garbling)",
            "T2 labels: the operator hands the challenger the input labels of the on-chain claim, challenge and response bits off-chain; Bitcoin does not verify them. Any label set that yields 'accept' must encode an authenticated response (openings are binding), but withheld or garbage labels after a confirmed response leave the challenger without a refute label and the operator paid after D3",
            "T3 pre-signed graph: the operator's pre-signatures stand in for a covenant; an operator that refuses to pre-sign cannot be challenged, so the graph must be signed before the bond is locked",
            "the challenger's off-chain search (locate_fault) uses the published claim data, which the operator must make available (data availability is not enforced)",
        ],
    }))
}

fn publication(node: &Node, secp: &Secp256k1<All>, toy: &Toy<E>, op: &Keypair, addr: &str, dest: &ScriptBuf) -> Result<Value, String> {
    let tc = &toy.pinned.tc;
    let c = &toy.committed;
    let ch = challenge_for(&toy.claim, ChallengeKind::Row { row: 3 }, "publication");
    let flat = response_payload(toy, &toy.claim, c, &ch);
    // The same response with Merkle openings over the same records.
    let mt_rows = merkle::build(&toy.pinned.matrix.items).unwrap();
    let mt_w = merkle::build(&c.w_stream.items).unwrap();
    let mt_e = merkle::build(&c.e_stream.items).unwrap();
    let rec = toy.row_record(3);
    let mut mk = Vec::new();
    mk.extend_from_slice(&ch.id());
    mk.extend_from_slice(&rec);
    let put = |out: &mut Vec<u8>, t: &merkle::Tree, items: &[[u8; 64]], i: usize| {
        let o = merkle::open(t, i);
        out.extend_from_slice(&o.index.to_be_bytes());
        out.extend_from_slice(&items[i]);
        for s in &o.siblings {
            out.extend_from_slice(s);
        }
    };
    put(&mut mk, &mt_rows, &toy.pinned.matrix.items, 3);
    let k = [tc.k[0] as usize, tc.k[1] as usize, tc.k[2] as usize];
    for (col, active) in fixture::row_cols(&rec, k) {
        put(&mut mk, &mt_w, &c.w_stream.items, if active && col < tc.num_vars { col as usize } else { 0 });
    }
    put(&mut mk, &mt_e, &c.e_stream.items, 3);
    let mut out = json!({"row": 3, "flatmerkle_payload_bytes": flat.len(), "merkle_payload_bytes": mk.len()});
    let stream = flatmerkle::payload(&toy.pinned.matrix.items).unwrap();
    let full_leaf = hashlock_leaf(&toy.pinned.matrix.digest, &op.x_only_public_key().0);
    // Carriers: tapscript witness pushes of 80 bytes (the per-item policy limit) or 520 bytes
    // (the consensus element limit), one witness item (needed for OP_SHA256 over a whole stream),
    // or an OP_RETURN output (Core 30+ relays up to -datacarriersize = 100,000 bytes, but output
    // bytes weigh 4 WU each and Script cannot read them).
    #[derive(PartialEq)]
    enum Carrier {
        Witness(usize),
        WholeItem,
        OpReturn,
    }
    for (name, payload, carrier) in [
        ("flatmerkle-row-response", flat.clone(), Carrier::Witness(CHUNK)),
        ("merkle-row-response", mk.clone(), Carrier::Witness(CHUNK)),
        ("flatmerkle-row-response-520-byte-pushes", flat.clone(), Carrier::Witness(520)),
        ("flatmerkle-row-response-op_return", flat.clone(), Carrier::OpReturn),
        ("flatmerkle-full-matrix-stream-OP_SHA256", stream.clone(), Carrier::WholeItem),
    ] {
        let opk = op.x_only_public_key().0;
        let chunks: Vec<Vec<u8>> = match carrier {
            Carrier::Witness(n) => payload.chunks(n).map(|c| c.to_vec()).collect(),
            Carrier::WholeItem => vec![payload.clone()],
            Carrier::OpReturn => Vec::new(),
        };
        let leaf = match carrier {
            Carrier::WholeItem => full_leaf.clone(),
            _ => drops(Builder::new(), chunks.len()).push_x_only_key(&opk).push_opcode(OP_CHECKSIG).into_script(),
        };
        let info = tree(secp, &[leaf.clone()]);
        let a = bitcoin::Address::p2tr_tweaked(info.output_key(), bitcoin::Network::Regtest).to_string();
        let txid = node.w(&["sendtoaddress", &a, "0.0005"])?;
        node.mine(1, addr)?;
        let ftx = tx_of(node, &txid);
        let vout = ftx.output.iter().position(|o| o.script_pubkey == spk(&info)).unwrap() as u32;
        let prev = ftx.output[vout as usize].clone();
        let mut outs = vec![TxOut { value: Amount::ZERO, script_pubkey: dest.clone() }];
        if carrier == Carrier::OpReturn {
            let mut b = Builder::new().push_opcode(OP_RETURN);
            for c in payload.chunks(520) {
                b = b.push_slice(push(c));
            }
            outs.push(TxOut { value: Amount::ZERO, script_pubkey: b.into_script() });
        }
        let mut dummy = vec![vec![0u8; 64]];
        dummy.extend(chunks.iter().cloned());
        let mut tx = spend(OutPoint { txid: ftx.compute_txid(), vout }, prev.value.to_sat(), Sequence::ENABLE_RBF_NO_LOCKTIME, outs, &dummy, &leaf, &info);
        let sig = sign(secp, &tx, &prev, &leaf, op);
        let mut items = vec![sig];
        // WholeItem stack: sig, stream (top): SHA256(stream) == matrix root, then the signature.
        items.extend(chunks.iter().cloned());
        tx.input[0].witness = witness(&items, &leaf, &info);
        let full = carrier == Carrier::WholeItem;
        let n_items = chunks.len();
        let policy = send(node, &tx);
        let mined = if policy.is_err() {
            // Consensus check without mempool policy: mine it directly.
            node.rpc(&["generateblock", addr, &format!("[\"{}\"]", serialize_hex(&tx))]).map(|_| "mined by generateblock (consensus-valid)".to_string())
        } else {
            Ok("relayed".into())
        };
        out[name] = json!({"policy": match &policy { Ok(_) => "standard".to_string(), Err(e) => e.replace(['\r', '\n'], " ") }, "consensus": match &mined { Ok(m) => m.clone(), Err(e) => format!("rejected: {e}") }, "payload_bytes": payload.len(), "payload_witness_items": n_items, "whole_item": full, "measure": measure(&tx, prev.value.to_sat())});
    }
    node.mine(1, addr)?;
    Ok(out)
}
