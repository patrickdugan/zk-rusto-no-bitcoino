#!/usr/bin/env python3
"""PRAXIS-10: proof-context and isolated Bitcoin regtest transaction plumbing.
No real witness encryption, proof-authorized spending, or security claim.
Without --regtest only canonical context and digest self-tests execute.
"""
import argparse, hashlib, json, socket, struct, subprocess, tempfile, time
from dataclasses import dataclass, replace, fields
from decimal import Decimal

def sha(x): return hashlib.sha256(x).digest()
def tag(t,x): h=sha(t.encode()); return sha(h+h+x)
def u32(x): return struct.pack("<I",x)
def u64(x): return struct.pack("<Q",x)
def compact(x):
    if x<253: return bytes([x])
    if x<=65535: return b"\xfd"+struct.pack("<H",x)
    raise ValueError("fixture length")
def script(s): return compact(len(s))+s
def h32(v):
    if not isinstance(v,bytes) or len(v)!=32: raise ValueError("32-byte field")
    return v

@dataclass(frozen=True)
class Context:
    network_genesis: bytes
    funding_txid: bytes  # display order, unlike Bitcoin wire outpoint
    funding_vout: int
    contract_id: bytes
    epoch: int
    predecessor: bytes
    successor: bytes
    chain_checkpoint: bytes
    nullifier: bytes
    payout_script_hash: bytes
    payout_sats: int
    fee_sats: int
    sighash: bytes
    verifier_id: bytes

    def encode(self):
        return (b"PRAXIS-SETTLEMENT-CONTEXT/v1\x00"+h32(self.network_genesis)
            +h32(self.funding_txid)+u32(self.funding_vout)+h32(self.contract_id)
            +u64(self.epoch)+h32(self.predecessor)+h32(self.successor)
            +h32(self.chain_checkpoint)+h32(self.nullifier)+h32(self.payout_script_hash)
            +u64(self.payout_sats)+u64(self.fee_sats)+h32(self.sighash)+h32(self.verifier_id))

    def digest(self): return sha(self.encode())
    def public_limbs(self):
        h=self.digest(); return int.from_bytes(h[:16],"big"),int.from_bytes(h[16:],"big")

def tap_sighash(tx,prev_sats,prev_script):
    # BIP341 key-path, one input, SIGHASH_DEFAULT, no annex, all outputs.
    assert len(tx["vin"])==1 and tx["version"]==2
    v=tx["vin"][0]
    outpoint=bytes.fromhex(v["txid"])[::-1]+u32(v["vout"])
    outs=b"".join(u64(int(x["value"]*100000000))+script(bytes.fromhex(x["scriptPubKey"]["hex"]))
                   for x in tx["vout"])
    sigmsg=(b"\x00"+u32(tx["version"])+u32(tx["locktime"])+sha(outpoint)
            +sha(u64(prev_sats))+sha(script(prev_script))+sha(u32(v["sequence"]))
            +sha(outs)+b"\x00"+u32(0))
    return tag("TapSighash",b"\x00"+sigmsg)

# Minimal independent BIP340 verifier for fixture cross-checks only. Public data;
# never use this variable-time code for signing or handling secret scalars.
P=2**256-2**32-977
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
   0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(a,b):
    if a is None:return b
    if b is None:return a
    x,y=a; X,Y=b
    if x==X and (y+Y)%P==0:return None
    m=((3*x*x)*pow(2*y,-1,P) if a==b else (Y-y)*pow(X-x,-1,P))%P
    z=(m*m-x-X)%P;return z,(m*(x-z)-y)%P
def mul(k,a):
    z=None
    while k:
        if k&1:z=add(z,a)
        a=add(a,a);k>>=1
    return z
def schnorr_verify(pub,msg,sig):
    if len(pub)!=32 or len(sig)!=64 or len(msg)!=32:return False
    x=int.from_bytes(pub,"big");r=int.from_bytes(sig[:32],"big");s=int.from_bytes(sig[32:],"big")
    if x>=P or r>=P or s>=N:return False
    y=pow((x*x*x+7)%P,(P+1)//4,P)
    if (y*y-x*x*x-7)%P:return False
    if y&1:y=P-y
    e=int.from_bytes(tag("BIP0340/challenge",sig[:32]+pub+msg),"big")%N
    R=add(mul(s,G),mul((N-e)%N,(x,y)))
    return R is not None and R[0]==r and R[1]%2==0

def selftest():
    h=lambda x:sha(x.encode())
    c=Context(h("genesis"),h("txid"),0,h("contract"),1,h("before"),h("after"),
        h("checkpoint"),h("nullifier"),h("recipient"),100000,500,h("sigmsg"),h("vk"))
    v=c.digest();a,b=c.public_limbs()
    assert a.to_bytes(16,"big")+b.to_bytes(16,"big")==v
    count=0
    for t in fields(c):
        val=getattr(c,t.name)
        other=val+1 if isinstance(val,int) else bytes([val[0]^1])+val[1:]
        assert replace(c,**{t.name:other}).digest()!=v;count+=1
    assert mul(N,G) is None
    print(json.dumps({"context_mutations":count,"digest":v.hex(),"limbs":[str(a),str(b)],
        "scope":"context serialization only, no circuit or release authorization"}))

def regtest():
    # Never connect to an existing Bitcoin node. Use a new datadir and private
    # loopback RPC port; the process and all regtest coins are discarded.
    with tempfile.TemporaryDirectory(prefix="praxis-regtest-") as datadir:
        with socket.socket() as s:s.bind(("127.0.0.1",0));port=s.getsockname()[1]
        args=["-regtest","-datadir="+datadir,"-rpcport="+str(port)]
        node=subprocess.Popen(["bitcoind",*args,"-server=1","-listen=0","-networkactive=0",
            "-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-fallbackfee=0.0002","-txindex=1"],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def call(method,*params,wallet=True):
            cmd=["bitcoin-cli",*args]
            if wallet:cmd+=["-rpcwallet=praxis"]
            cmd+=[method,*[x if isinstance(x,str) else json.dumps(x) for x in params]]
            res=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=30).stdout.strip()
            try:return json.loads(res,parse_float=Decimal)
            except ValueError:return res
        try:
            for _ in range(120):
                if node.poll() is not None:raise RuntimeError("bitcoind exited")
                try:
                    info=call("getblockchaininfo",wallet=False);break
                except subprocess.CalledProcessError:time.sleep(.5)
            else:raise RuntimeError("regtest startup failed")
            assert info["chain"]=="regtest"
            call("createwallet","praxis",wallet=False)
            miner=call("getnewaddress","","bech32m")
            call("generatetoaddress",101,miner)
            genesis=bytes.fromhex(call("getblockhash",0))
            receipts=[]
            for mode in ["payout","refund"]:
                addr=call("getnewaddress","","bech32m")
                funding=call("sendtoaddress",addr,"1.00000000")
                call("generatetoaddress",1,miner)
                tx=call("getrawtransaction",funding,True)
                out=next(v for v in tx["vout"] if v["scriptPubKey"].get("address")==addr)
                prev=bytes.fromhex(out["scriptPubKey"]["hex"]);assert prev[:2]==b"\x51\x20" and len(prev)==34
                prev_sats=int(out["value"]*100000000);assert prev_sats==100000000
                payee=call("getnewaddress","","bech32m");return_addr=call("getnewaddress","","bech32m")
                height=call("getblockcount")
                def sign(recipient,lock):
                    raw=call("createrawtransaction",[{"txid":funding,"vout":out["n"],"sequence":4294967294}],
                             [{recipient:"0.99980000"}],lock)
                    signed=call("signrawtransactionwithwallet",raw,[],"DEFAULT");assert signed["complete"]
                    dec=call("decoderawtransaction",signed["hex"]);sig=bytes.fromhex(dec["vin"][0]["txinwitness"][0])
                    digest=tap_sighash(dec,prev_sats,prev);assert schnorr_verify(prev[2:],digest,sig),"BIP341/340 differential"
                    bad=bytearray(digest);bad[0]^=1;assert not schnorr_verify(prev[2:],bytes(bad),sig)
                    return signed["hex"],dec,digest
                pay,pd,ds=sign(payee,0);refund,rd,dr=sign(return_addr,height+2)
                def allowed(raw):return call("testmempoolaccept",[raw])[0]["allowed"]
                assert allowed(pay) and not allowed(refund),"early refund"
                c=Context(genesis,bytes.fromhex(funding),out["n"],sha(mode.encode()),1,
                    sha(b"dummy predecessor"),sha(b"dummy successor"),bytes.fromhex(call("getbestblockhash")),
                    sha(bytes.fromhex(funding)+u32(out["n"])),sha(bytes.fromhex(pd["vout"][0]["scriptPubKey"]["hex"])),
                    99980000,20000,ds,sha(b"UNBOUND TEST ONLY"))
                assert c.digest()!=replace(c,sighash=dr).digest()
                # Deliberately wallet-authorized spend; no WE or proof is used.
                if mode=="refund":call("generatetoaddress",3,miner);assert allowed(refund);chosen,other=refund,pay
                else:chosen,other=pay,refund
                txid=call("sendrawtransaction",chosen);call("generatetoaddress",1,miner)
                assert not allowed(other),"spent outpoint accepted"
                receipts.append({"path":mode,"txid":txid,"digest":c.digest().hex(),
                                 "sighash_verified":True,"early_refund_rejected":True,
                                 "competing_spend_rejected":True,"proof_authorized":False})
            print(json.dumps({"regtest":receipts},indent=2))
        finally:
            if node.poll() is None:
                try:call("stop",wallet=False)
                except Exception:node.terminate()
                try:node.wait(timeout=15)
                except subprocess.TimeoutExpired:node.kill();node.wait()
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--regtest",action="store_true");args=p.parse_args()
    selftest()
    if args.regtest:regtest()
