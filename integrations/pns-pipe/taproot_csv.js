'use strict';
// Public fixture only: offline script-path and restricted CSV semantics.
function scriptFixture(lib,helper){
 const {ck,concat,le,hex,fromHex,eq}=lib;
 const {sha,tag,be,read,N,G,mod,add,neg,mul,lift,challenge,verify,sc,sighash}=helper(lib,true);
 const ascii=s=>Uint8Array.from(s,c=>c.charCodeAt(0)),flip=x=>{let y=x.slice();y[0]^=1;return y};
 const leaf=(s,v=0xc0)=>tag("TapLeaf",concat(Uint8Array.of(v),sc(s)));
 const branch=(a,b)=>tag("TapBranch",hex(a)<hex(b)?concat(a,b):concat(b,a));
 function tap(internal,root){let p=lift(read(internal)),t=read(tag("TapTweak",concat(internal,root)));ck(p&&t<N,"tweak");let q=add(p,mul(t,G));ck(q,"output");return q}
 const control=(internal,q,sibling,v=0xc0)=>concat(Uint8Array.of(v|Number(q.y&1n)),internal,sibling);
 function checkControl(sp,s,cb){
  try{if(sp.length!==34||sp[0]!==0x51||sp[1]!==0x20||cb.length!==65||(cb[0]&0xfe)!==0xc0)return false;
   const q=tap(cb.slice(1,33),branch(leaf(s),cb.slice(33)));return eq(be(q.x),sp.slice(2))&&Number(q.y&1n)===(cb[0]&1)
  }catch{return false}
 }
 // Published BIP341 wallet two-leaf test vector.
 const vi=fromHex("ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592"),
 v0=leaf(fromHex("20387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48ac")),
 v1=leaf(fromHex("06424950333431"),250),vr=branch(v0,v1),vq=tap(vi,vr);
 ck(hex(vr)==="6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef","BIP341 root");
 ck(hex(be(vq.x))==="712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5","BIP341 output");
 ck(hex(control(vi,vq,v1))==="c0ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592f224a923cd0021ab202ab139cc56802ddb92dcfc172b9212261a539df79a112a","BIP341 control");
 const internal=sha(concat(Uint8Array.of(4),be(G.x),be(G.y)));
 ck(hex(internal)==="50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0","BIP341 NUMS");
 // Public deterministic TEST scalars. Never fund this output.
 const fd=23n,od=37n,fpk=be(mul(fd,G).x),opk=be(mul(od,G).x),delay=6;
 const fs=concat(Uint8Array.of(32),fpk,Uint8Array.of(0xac)),os=concat(Uint8Array.of(0x56,0xb2,0x75,32),opk,Uint8Array.of(0xac));
 const fl=leaf(fs),ol=leaf(os),root=branch(fl,ol),q=tap(internal,root);
 const sp=concat(Uint8Array.of(0x51,0x20),be(q.x)),fc=control(internal,q,ol),oc=control(internal,q,fl);
 ck(checkControl(sp,fs,fc)&&checkControl(sp,os,oc),"control paths");
 const tx={version:2,locktime:0,txid:sha(ascii("PNS TEST ONLY assertion txid wire order")),vout:0,prevValue:1000000,prevScript:sp,sequence:delay,outputs:[{value:998000,script:concat(Uint8Array.of(0x51,0x20),be(mul(41n,G).x))}]};
 // BIP342 ext_flag=1, no annex or OP_CODESEPARATOR, one input/default.
 function digest(t,s){const outs=concat(...t.outputs.map(o=>concat(le(o.value),sc(o.script))));
 return tag("TapSighash",concat(Uint8Array.of(0,0),le(t.version,4),le(t.locktime,4),sha(concat(t.txid,le(t.vout,4))),sha(le(t.prevValue)),sha(sc(t.prevScript)),sha(le(t.sequence,4)),sha(outs),Uint8Array.of(2),le(0,4),leaf(s),Uint8Array.of(0),le(0xffffffff,4)))}
 function sign(d,m){let p=mul(d,G);if(p.y&1n)d=N-d;const px=be(p.x),aux=tag("BIP0340/aux",new Uint8Array(32)),t=be(d).map((v,i)=>v^aux[i]);let k=read(tag("BIP0340/nonce",concat(t,px,m)))%N;ck(k!==0n,"nonce");let r=mul(k,G);if(r.y&1n){k=N-k;r=neg(r)}return concat(be(r.x),be(mod(k+challenge(r,p,m)*d,N)))}
 ck(hex(sign(3n,new Uint8Array(32)))==="e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0","BIP340 sign vector");
 // Restricted model for exactly the two scripts; candidate block height.
 function csvAllows(t,birth,height){const n=t.sequence>>>0;return t.version>=2&&(n&0x80000000)===0&&(n&0x00400000)===0&&(n&0xffff)>=delay&&height>=birth+(n&0xffff)}
 function spend(t,s,cb,sig,birth,height){if(!checkControl(t.prevScript,s,cb))return false;
 if(eq(s,fs))return verify(fpk,digest(t,s),sig);if(eq(s,os))return csvAllows(t,birth,height)&&verify(opk,digest(t,s),sig);return false}
 const fault={...tx,sequence:0xfffffffe,outputs:[{...tx.outputs[0],script:concat(Uint8Array.of(0x51,0x20),be(mul(43n,G).x))}]};
 const fmsg=digest(fault,fs),omsg=digest(tx,os),fsig=sign(fd,fmsg),osig=sign(od,omsg),birth=100;
 ck(spend(fault,fs,fc,fsig,birth,birth+1),"immediate fault");ck(spend(tx,os,oc,osig,birth,birth+delay),"first eligible");
 const negatives=[],reject=(n,b)=>{ck(b,n);negatives.push(n)};
 reject("before relative height",!spend(tx,os,oc,osig,birth,birth+delay-1));
 reject("reconfirmation resets clock",!spend(tx,os,oc,osig,birth+2,birth+delay));
 for(const [name,t] of [["retained optimistic key zero sequence",{...tx,sequence:0}],["retained optimistic key disable bit",{...tx,sequence:0x80000006}],["retained optimistic key time flag",{...tx,sequence:0x00400006}],["retained optimistic key short delay",{...tx,sequence:delay-1}],["retained optimistic key version one",{...tx,version:1}]]){
 reject(name,!spend(t,os,oc,sign(od,digest(t,os)),birth,birth+100))}
 reject("wrong control sibling",!spend(tx,os,concat(oc.slice(0,33),flip(oc.slice(33))),osig,birth,birth+delay));
 let cb=oc.slice();cb[0]^=1;reject("wrong parity",!spend(tx,os,cb,osig,birth,birth+delay));
 reject("swapped leaf control",!spend(tx,os,fc,osig,birth,birth+delay));
 reject("changed CSV script",!checkControl(sp,concat(Uint8Array.of(0x55),os.slice(1)),oc));
 reject("fault signature on optimistic leaf",!spend(tx,os,oc,fsig,birth,birth+delay));
 reject("key path digest in script path",!verify(opk,digest(tx,os),sign(od,sighash(tx))));
 reject("changed recipient",!spend({...tx,outputs:[{...tx.outputs[0],script:flip(tx.outputs[0].script)}]},os,oc,osig,birth,birth+delay));
 reject("changed amount or fee",!spend({...tx,outputs:[{...tx.outputs[0],value:997000}]},os,oc,osig,birth,birth+delay));
 reject("changed outpoint",!spend({...tx,txid:flip(tx.txid)},os,oc,osig,birth,birth+delay));
 const redirected={...tx,outputs:[{...tx.outputs[0],value:996000}]};
 ck(spend(redirected,os,oc,sign(od,digest(redirected,os)),birth,birth+delay),"retained optimistic key after CSV");
 const fakeFault={...fault,outputs:redirected.outputs};ck(spend(fakeFault,fs,fc,sign(fd,digest(fakeFault,fs)),birth,birth+1),"retained fault key");
 return {scope:"Offline BIP341/BIP342 two-leaf script path and restricted CSV semantics; public test scalars; no Core consensus, DKG, WE or real spend",bip341_wallet_vector:true,bip340_signing_vector:true,internal_nums_key:hex(internal),taproot_script_pubkey:hex(sp),merkle_root:hex(root),fault_script:hex(fs),optimistic_script:hex(os),fault_control_block:hex(fc),optimistic_control_block:hex(oc),delay_blocks:delay,assertion_height:birth,first_candidate_height:birth+delay,fault_sighash:hex(fmsg),optimistic_sighash:hex(omsg),negative_controls:negatives.length,negative_control_names:negatives,retained_fault_key_bypass:true,retained_optimistic_key_after_delay_redirect:true,bitcoin_core_executed:false}
}
console.log(JSON.stringify(scriptFixture(require('./trace_fraud.js'),require('./signature_shares.js')),null,2));
