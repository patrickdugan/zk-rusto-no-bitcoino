'use strict';
// Test fixture only: public deterministic additive shares, no cryptographic release.
function signatureFixture(lib,helpersOnly){
"use strict";
const {ck,concat,le,hex,fromHex,eq,hash,context,commit,statement,pin,row}=lib;
const A=(n,f)=>Array.from({length:n},(_,i)=>f(i));
const ascii=s=>Uint8Array.from(s,c=>c.charCodeAt(0));
const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
const be=(x,n=32)=>le(x,n).reverse(),read=b=>b.reduce((s,v)=>256n*s+BigInt(v),0n);
function sha(b){
 const n=Math.ceil((b.length+9)/64)*64,v=new Uint8Array(n);v.set(b);v[b.length]=128;v.set(be(BigInt(b.length)*8n,8),n-8);
 const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],r=(x,n)=>(x>>>n)|(x<<(32-n));
 const dv=new DataView(v.buffer);
 for(let off=0;off<n;off+=64){
  const w=new Uint32Array(64);for(let i=0;i<16;i++)w[i]=dv.getUint32(off+4*i);
  for(let i=16;i<64;i++){let x=w[i-15],y=w[i-2];w[i]=w[i-16]+(r(x,7)^r(x,18)^(x>>>3))+w[i-7]+(r(y,17)^r(y,19)^(y>>>10))}
  let [a,b,c,d,e,f,g,z]=h;
  for(let i=0;i<64;i++){let t=(z+(r(e,6)^r(e,11)^r(e,25))+((e&f)^(~e&g))+K[i]+w[i])|0,u=((r(a,2)^r(a,13)^r(a,22))+((a&b)^(a&c)^(b&c)))|0;[a,b,c,d,e,f,g,z]=[(t+u)|0,a,b,c,(d+t)|0,e,f,g]}
  [a,b,c,d,e,f,g,z].forEach((x,i)=>h[i]=(h[i]+x)>>>0)
 }
 return concat(...h.map(x=>be(x,4)));
}
const tag=(s,x)=>{const h=sha(ascii(s));return sha(concat(h,h,x))};
const P=(1n<<256n)-(1n<<32n)-977n,N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G={x:0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,y:0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n};
const mod=(x,p)=>((x%p)+p)%p;
const inv=(x,p)=>{let a=mod(x,p),b=p,u=1n,v=0n;while(b){let q=a/b;[a,b]=[b,a-q*b];[u,v]=[v,u-q*v]}ck(a===1n,"inverse");return mod(u,p)};
const pow=(x,k,p)=>{let z=1n;for(;k;k>>=1n,x=x*x%p)if(k&1n)z=z*x%p;return z};
function add(a,b){if(!a)return b;if(!b)return a;if(a.x===b.x&&mod(a.y+b.y,P)===0n)return null;
 const s=mod(a.x===b.x?3n*a.x*a.x*inv(2n*a.y,P):(b.y-a.y)*inv(b.x-a.x,P),P),x=mod(s*s-a.x-b.x,P);
 return {x,y:mod(s*(a.x-x)-a.y,P)}
}
const neg=a=>a?{x:a.x,y:mod(-a.y,P)}:null;
const mul=(k,a)=>{let z=null;for(k=mod(k,N);k;k>>=1n,a=add(a,a))if(k&1n)z=add(z,a);return z};
const sum=a=>a.reduce(add,null),pointEq=(a,b)=>a===null?b===null:b!==null&&a.x===b.x&&a.y===b.y;
function lift(x){if(x>=P)return null;let y=pow(mod(x*x*x+7n,P),(P+1n)/4n,P);if(mod(y*y-x*x*x-7n,P)!==0n)return null;return{x,y:y&1n?P-y:y}}
const challenge=(R,Q,m)=>read(tag("BIP0340/challenge",concat(be(R.x),be(Q.x),m)))%N;
function verify(pub,msg,sig){
 if(pub.length!==32||sig.length!==64)return false;let q=lift(read(pub)),r=read(sig.slice(0,32)),s=read(sig.slice(32));
 if(!q||r>=P||s>=N)return false;
 const e=read(tag("BIP0340/challenge",concat(sig.slice(0,32),pub,msg)))%N,R=add(mul(s,G),mul(-e,q));
 return R!==null&&R.x===r&&(R.y&1n)===0n;
}
ck(hex(sha(ascii("abc")))==="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","SHA256 vector");
const vecs=[
["f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9","00".repeat(32),"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",true],
["dff1d77f2a671c5f36183726db2341be58feae1da2dec ed843240f7b502ba659".replace(" ",""),"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89","fff97bd5755eee a420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2".replace(" ",""),false]
];
for(const [pk,m,s,yes] of vecs)ck(verify(fromHex(pk),fromHex(m),fromHex(s))===yes,"BIP340 vector");
const sc=x=>{ck(x.length<253,"test script length");return concat(Uint8Array.of(x.length),x)};
function sighash(tx){
 ck(tx.prevScript.length<253&&tx.outputs.length>=1&&tx.outputs.length<=16,"fixture transaction shape");
 const outs=concat(...tx.outputs.map(o=>concat(le(o.value),sc(o.script))));
 return tag("TapSighash",concat(Uint8Array.of(0,0),le(tx.version,4),le(tx.locktime,4),
 sha(concat(tx.txid,le(tx.vout,4))),sha(le(tx.prevValue)),sha(sc(tx.prevScript)),sha(le(tx.sequence,4)),sha(outs),Uint8Array.of(0),le(0,4)));
}
if(helpersOnly)return {sha,tag,be,read,P,N,G,mod,add,neg,mul,lift,pointEq,challenge,verify,sc,sighash};
// Public deterministic test secrets, deliberately NOT a DKG or secure signing protocol.
let xs=[3n,5n,11n],ps=xs.map(x=>mul(x,G)),Q=sum(ps);
if(Q.y&1n){xs=xs.map(x=>N-x);ps=ps.map(neg);Q=neg(Q)}
const tx={version:2,locktime:0,txid:sha(ascii("TEST ONLY fake outpoint")),vout:1,prevValue:1000000,prevScript:concat(Uint8Array.of(0x51,0x20),be(Q.x)),sequence:0xfffffffe,outputs:[{value:998000,script:concat(Uint8Array.of(0x51,0x20),be(mul(31n,G).x))}]};
const msg=sighash(tx),ctx={...context(),bondTxid:tx.txid.slice().reverse(),vout:tx.vout,disproveSighash:msg};
const {inst}=commit(ctx,[pin(0,1),pin(1,0),row(0,0,2,15)],[1,0,0]);
const releaseId=hash(statement(inst));
let ks=xs.map((_,i)=>1n+read(sha(concat(ascii("PUBLIC TEST NONCE ONLY"),releaseId,le(i,4))))%(N-1n)),rs=ks.map(k=>mul(k,G)),R=sum(rs);
if(R.y&1n){ks=ks.map(k=>N-k);rs=rs.map(neg);R=neg(R)}
const e=challenge(R,Q,msg),shares=xs.map((x,i)=>({id:i,releaseId,s:mod(ks[i]+e*x,N)}));
function combine(shares,instId=releaseId,m=msg){
 try{
  if(shares.length!==xs.length||new Set(shares.map(x=>x.id)).size!==xs.length)return null;
  for(const p of shares){if(!Number.isInteger(p.id)||p.id<0||p.id>=xs.length||!eq(p.releaseId,instId)||p.s<0n||p.s>=N)return null;
    if(!pointEq(mul(p.s,G),add(rs[p.id],mul(challenge(R,Q,m),ps[p.id]))))return null;}
  const s=shares.reduce((s,x)=>mod(s+x.s,N),0n),sig=concat(be(R.x),be(s));return verify(be(Q.x),m,sig)?sig:null;
 }catch(e){return null}
}
const sig=combine(shares);ck(sig!==null&&verify(be(Q.x),msg,sig),"joint signature");
const negatives=[];
function reject(name,b){ck(b,name);negatives.push(name)}
reject("missing share",combine(shares.slice(1))===null);
reject("duplicate signer",combine([shares[0],shares[0],shares[2]])===null);
reject("changed scalar",combine([{...shares[0],s:mod(shares[0].s+1n,N)},...shares.slice(1)])===null);
reject("mixed assertion",combine([{...shares[0],releaseId:hash(ascii("other case"))},...shares.slice(1)])===null);
const flip=b=>{let x=b.slice();x[0]^=1;return x};
const changed=[
 ["outpoint",{...tx,txid:flip(tx.txid)}],["vout",{...tx,vout:2}],["prevout amount",{...tx,prevValue:tx.prevValue+1}],
 ["prevout script",{...tx,prevScript:flip(tx.prevScript)}],["payout amount/fee",{...tx,outputs:[{...tx.outputs[0],value:tx.outputs[0].value+1}]}],
 ["recipient",{...tx,outputs:[{...tx.outputs[0],script:flip(tx.outputs[0].script)}]}],
 ["additional output",{...tx,outputs:[...tx.outputs,{value:1,script:Uint8Array.of(0x51)}]}],
 ["sequence",{...tx,sequence:tx.sequence-1}],["locktime",{...tx,locktime:1}],["version",{...tx,version:1}]
];
for(const [n,t] of changed){const m=sighash(t);reject(n,!eq(m,msg)&&!verify(be(Q.x),m,sig)&&combine(shares,releaseId,m)===null)}
return {scope:"Public-key toy additive Schnorr shares; no DKG, no witness encryption, no real Bitcoin UTXO or broadcast",official_bip340_vectors:2,signers:3,signed_sighash:hex(msg),release_id:hex(releaseId),aggregate_xonly_pubkey:hex(be(Q.x)),signature_bytes:sig.length,partial_equations_verified:3,exact_transaction_verified:true,negative_controls:negatives.length,negative_control_names:negatives};
}
module.exports=signatureFixture;
if(require.main===module)console.log(JSON.stringify(signatureFixture(require('./trace_fraud.js')),null,2));
