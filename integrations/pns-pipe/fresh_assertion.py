#!/usr/bin/env python3
"""PNS-PIPE-02 fresh assertion context and isolated Bitcoin Core test. No WE.
Test wallet retains every key; BIP68 only constrains the presigned transaction.
"""
import argparse, hashlib, json, socket, struct, subprocess, tempfile, time
from decimal import Decimal

DELAY=6

def sha(b): return hashlib.sha256(b).digest()
def tagged(t,b): h=sha(t.encode()); return sha(h+h+b)
def u32(n): return struct.pack('<I',n)
def u64(n): return struct.pack('<Q',n)
def h32(b):
    if not isinstance(b,bytes) or len(b)!=32: raise ValueError('32-byte digest')
    return b
def short(b):
    if len(b)>=253: raise ValueError('bounded fixture serialization')
    return bytes([len(b)])+b

def trace_domain(genesis,funding_txid,vout,case_id,epoch,verifier,statement,proof,policy):
    # txids are display-order bytes in the context. Future assertion outpoint
    # and spending digests are deliberately excluded from this domain.
    return sha(b'PNS-PIPE-TRACE/v2\0'+h32(genesis)+h32(funding_txid)+u32(vout)+h32(case_id)+u64(epoch)+h32(verifier)+h32(statement)+h32(proof)+h32(policy))
def anchor(t,rows_root,trace_root,rows,slots):
    if rows<=0 or slots<=0: raise ValueError('nonempty trace')
    return sha(b'PNS-PIPE-ANCHOR/v2\0'+h32(t)+h32(rows_root)+h32(trace_root)+u64(rows)+u64(slots))
def release(t,a,assert_txid,vout,disprove,optimistic,delay):
    if not 1<=delay<=65535: raise ValueError('height-based BIP68 delay')
    return sha(b'PNS-PIPE-RELEASE/v2\0'+h32(t)+h32(a)+h32(assert_txid)+u32(vout)+h32(disprove)+h32(optimistic)+u32(delay))
def sighash(tx,prev_sats,prev_script):
    # BIP341 one-input key path, SIGHASH_DEFAULT, no annex, all outputs.
    assert len(tx['vin'])==1 and tx['version']==2
    v=tx['vin'][0]
    outputs=b''.join(u64(int(x['value']*100000000))+short(bytes.fromhex(x['scriptPubKey']['hex'])) for x in tx['vout'])
    outpoint=bytes.fromhex(v['txid'])[::-1]+u32(v['vout'])
    msg=(b'\0'+u32(2)+u32(tx['locktime'])+sha(outpoint)+sha(u64(prev_sats))+sha(short(prev_script))+sha(u32(v['sequence']))+sha(outputs)+b'\0'+u32(0))
    return tagged('TapSighash',b'\0'+msg)

def selftest():
    h=lambda s:sha(s.encode())
    args=[h('genesis'),h('funding'),1,h('case'),7,h('verifier'),h('statement'),h('proof'),h('policy')]
    t=trace_domain(*args); rr=h('row root'); tr=h('trace root'); a=anchor(t,rr,tr,16,11)
    # One-input synthetic non-witness transaction serialization. No actual UTXO.
    def txid(commit):
        outs=u64(99000)+short(b'\x51\x20'+h('test key'))+u64(0)+short(b'\x6a\x20'+commit)
        wire=u32(2)+b'\x01'+args[1][::-1]+u32(1)+b'\0'+u32(0xfffffffe)+b'\x02'+outs+u32(0)
        return sha(sha(wire))[::-1]
    aid=txid(a); rargs=[t,a,aid,0,h('disprove'),h('optimistic'),DELAY]; x=release(*rargs)
    def mutate(v): return v+1 if isinstance(v,int) else bytes([v[0]^1])+v[1:]
    for i,v in enumerate(args):
        z=args.copy();z[i]=mutate(v);assert trace_domain(*z)!=t
    for i,v in enumerate([t,rr,tr,16,11]):
        z=[t,rr,tr,16,11];z[i]=mutate(v);assert anchor(*z)!=a and txid(anchor(*z))!=aid
    for i,v in enumerate(rargs):
        z=rargs.copy();z[i]=mutate(v);assert release(*z)!=x
        # Future release mutations do not change the previously frozen anchor.
        assert txid(a)==aid
    print(json.dumps({'scope':'synthetic context serialization; no Bitcoin spend or WE','domain_mutations':9,'anchor_mutations':5,'release_mutations':7,'trace_domain':t.hex(),'anchor':a.hex(),'assertion_txid':aid.hex(),'release_id':x.hex()},sort_keys=True))

def regtest():
    # Fresh isolated datadir, loopback-only RPC, no peer network.
    with tempfile.TemporaryDirectory(prefix='pns-pipe-regtest-') as datadir:
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        args=['-regtest','-datadir='+datadir,'-rpcport='+str(port)]
        proc=subprocess.Popen(['bitcoind',*args,'-server=1','-listen=0','-networkactive=0','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1','-fallbackfee=0.0002','-txindex=1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def call(method,*params,wallet=True):
            cmd=['bitcoin-cli',*args]+(['-rpcwallet=pipe'] if wallet else [])+[method,*[x if isinstance(x,str) else json.dumps(x) for x in params]]
            out=subprocess.run(cmd,capture_output=True,text=True,check=True,timeout=30).stdout.strip()
            try:return json.loads(out,parse_float=Decimal)
            except ValueError:return out
        def output(tx,addr):return next(o for o in tx['vout'] if o['scriptPubKey'].get('address')==addr)
        def prevs(txid,vout,script,amount):return [{'txid':txid,'vout':vout,'scriptPubKey':script.hex(),'amount':amount}]
        def sign(raw,prev):
            z=call('signrawtransactionwithwallet',raw,prev,'DEFAULT');assert z['complete'];return z['hex']
        def allowed(raw):return call('testmempoolaccept',[raw])[0]['allowed']
        def sats(o):return int(o['value']*100000000)
        try:
            for _ in range(120):
                if proc.poll() is not None:raise RuntimeError('node exited')
                try:
                    info=call('getblockchaininfo',wallet=False);break
                except subprocess.CalledProcessError:time.sleep(.5)
            else:raise RuntimeError('node startup timeout')
            assert info['chain']=='regtest';call('createwallet','pipe',wallet=False)
            miner=call('getnewaddress','','bech32m');call('generatetoaddress',101,miner)
            genesis=bytes.fromhex(call('getblockhash',0));receipts=[]
            for mode in ['fault','optimistic']:
                old_addr=call('getnewaddress','','bech32m');fund=call('sendtoaddress',old_addr,'1.00000000')
                call('generatetoaddress',DELAY+1,miner)
                old=output(call('getrawtransaction',fund,True),old_addr);ov=old['n'];osp=bytes.fromhex(old['scriptPubKey']['hex']);assert sats(old)==100000000
                dispute=call('getnewaddress','','bech32m');bad_dst=call('getnewaddress','','bech32m');ok_dst=call('getnewaddress','','bech32m')
                sp=lambda addr:bytes.fromhex(call('getaddressinfo',addr)['scriptPubKey'])
                policy=sha(b'PNS-PIPE-TEST-POLICY/v2\0'+u32(DELAY)+short(sp(bad_dst))+short(sp(ok_dst))+u64(20000)+u64(20000))
                t=trace_domain(genesis,bytes.fromhex(fund),ov,sha(mode.encode()),1,sha(b'TEST verifier'),sha(b'TEST statement'),sha(b'TEST proof'),policy)
                # Dummy roots: this test does not validate a Nova proof or trace.
                a=anchor(t,sha(b'TEST rows'),sha(b'TEST trace'),16,11)
                inp=[{'txid':fund,'vout':ov,'sequence':0xfffffffe}]
                oldprev=prevs(fund,ov,osp,'1.00000000')
                old_delay=sign(call('createrawtransaction',[{**inp[0],'sequence':DELAY}],[{ok_dst:'0.99980000'}],0),oldprev)
                assert allowed(old_delay),'old funding output already satisfies relative delay'
                raw=call('createrawtransaction',inp,[{dispute:'0.99980000'},{'data':a.hex()}],0)
                assert_unsigned=call('decoderawtransaction',raw)['txid'];assertion=sign(raw,oldprev)
                dec=call('decoderawtransaction',assertion);aid=dec['txid'];assert aid==assert_unsigned,'SegWit txid stable'
                assert any(o['scriptPubKey']['hex']=='6a20'+a.hex() for o in dec['vout'])
                v=output(dec,dispute);av=v['n'];asp=bytes.fromhex(v['scriptPubKey']['hex']);assert sats(v)==99980000
                aprev=prevs(aid,av,asp,'0.99980000')
                def child(dst,seq):
                    raw=call('createrawtransaction',[{'txid':aid,'vout':av,'sequence':seq}],[{dst:'0.99960000'}],0)
                    signed=sign(raw,aprev);tx=call('decoderawtransaction',signed)
                    assert tx['version']==2 and tx['vin'][0]['sequence']==seq
                    assert len(bytes.fromhex(tx['vin'][0]['txinwitness'][0]))==64
                    return signed,sighash(tx,99980000,asp)
                fault,fd=child(bad_dst,0xfffffffe);optimistic,od=child(ok_dst,DELAY)
                xid=release(t,a,bytes.fromhex(aid),av,fd,od,DELAY)
                assert not allowed(fault) and not allowed(optimistic),'unbroadcast parent'
                assert allowed(assertion);assert call('sendrawtransaction',assertion)==aid;call('generatetoaddress',1,miner)
                assert allowed(fault) and not allowed(optimistic),'fresh assertion clock'
                bypass,_=child(ok_dst,0xfffffffe);assert allowed(bypass),'retained wallet key can bypass presigned delay'
                if mode=='fault':
                    chosen=call('sendrawtransaction',fault);call('generatetoaddress',DELAY+1,miner);assert not allowed(optimistic)
                else:
                    call('generatetoaddress',DELAY-2,miner);assert not allowed(optimistic)
                    call('generatetoaddress',1,miner);assert allowed(optimistic),'earliest BIP68 mempool height'
                    chosen=call('sendrawtransaction',optimistic);call('generatetoaddress',1,miner);assert not allowed(fault)
                receipts.append({'mode':mode,'release_id':xid.hex(),'assertion_txid':aid,'settlement_txid':chosen,'fresh_delay_tested':True,'competing_spend_rejected':True,'retained_key_bypass_demonstrated':True,'proof_authorized':False})
            print(json.dumps({'scope':'wallet-authorized regtest, dummy trace roots; no WE','delay_blocks':DELAY,'cases':receipts},indent=2))
        finally:
            if proc.poll() is None:
                try:call('stop',wallet=False)
                except Exception:proc.terminate()
                try:proc.wait(timeout=15)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--regtest',action='store_true');args=p.parse_args()
    selftest()
    if args.regtest:regtest()
