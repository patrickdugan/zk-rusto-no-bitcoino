#!/usr/bin/env node
'use strict';
// Joint proof relation: actual Rust Keccak transcript BQS prefix and optimized
// scalar/curve BQS suffix share one global Boolean slot namespace. All fixtures
// are public research data. Full compressed Nova composition remains separate.
const fs=require("fs"),path=require("path"),crypto=require("crypto");
const {Bqs,PALLAS,VESTA,ck,mod,O}=require("./ipa_bqs.js");
const sha=b=>crypto.createHash("sha256").update(b).digest("hex");
const read=(d,n)=>fs.readFileSync(path.join(d,n));
const json=(d,n)=>JSON.parse(read(d,n));
function le(s){const b=Buffer.from(s,"hex");ck(b.length===32,"scalar encoding");let v=0n;for(let i=31;i>=0;i--)v=256n*v+BigInt(b[i]);return v}
function point(p){return {x:le(p.x),y:le(p.y),inf:p.infinity}}
function u64(n){const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b}
function u32(n){const b=Buffer.alloc(4);b.writeUInt32LE(n);return b}
function prefixCheck(m,w,rows){
    ck(m.format==="PNS-BQS-GATES/v1"&&m.w0===1&&m.w1===0,"prefix format");
    ck(w.length===m.boolean_unknowns+1&&rows.length===16*(m.gate_rows+m.pin_rows),"prefix dimensions");
    ck(w[0]===1&&w[1]===0,"constants");
    for(const x of w)ck(x===0||x===1,"prefix bitness");
    const h=crypto.createHash("sha256");h.update(Buffer.from("PNS-BQS-GATES/v1\0"));
    for(const n of [w.length,m.input_slots.length,m.gate_rows,m.pin_rows])h.update(u64(n));
    for(const i of m.input_slots){ck(i>=2&&i<w.length,"input slot");h.update(u32(i))}
    h.update(rows);ck(h.digest("hex")===m.shape_sha256,"prefix shape hash");
    let failed=0,quadratic=0;
    for(let off=0;off<rows.length;off+=16){
        let a=rows.readUInt32LE(off),b=rows.readUInt32LE(off+4),z=rows.readUInt32LE(off+8);
        ck(a<w.length&&b<w.length&&z<w.length,"prefix row slot");
        let d=rows.readInt8(off+12),l=rows.readInt8(off+13),r=rows.readInt8(off+14),q=rows.readInt8(off+15);
        if(q)quadratic++;
        if(w[z]!==d*w[0]+l*w[a]+r*w[b]+q*w[a]*w[b])failed++;
    }return {failed,quadratic};
}
function setScalar(w,ids,v){
    ck(ids.length===256&&new Set(ids).size===256&&ids.every(i=>i>=2&&i<w.length),"mutable scalar slots");
    for(let j=0;j<256;j++)w[ids[j]]=Number(v>>BigInt(j)&1n);
}
function run(dir,badAhat=false,emit=false,compact=false){
    const started=Date.now(),manifest=json(dir,"manifest.json"),i=json(dir,"interfaces.json"),
        fixture=json(dir,"fixture.json"),prefix=read(dir,"assignment.bin"),rows=read(dir,"rows.bin");
    ck(i.format==="PNS-IPA-SLOTS/v1"&&i.curve===fixture.curve&&i.rounds===fixture.rounds,"interface");
    const base=i.curve==="Pallas"?PALLAS:VESTA,scalar=i.curve==="Pallas"?VESTA:PALLAS;
    ck(i.curve==="Pallas"||i.curve==="Vesta","curve");
    ck(i.rounds>=1&&i.rounds<=3&&i.l.length===i.rounds&&i.r.length===i.rounds&&i.challenges.length===i.rounds,"round shape");
    const all=[i.commitment,i.point,i.evaluation,...i.l,...i.r,i.a_hat,i.rho,...i.challenges,i.suffix];
    ck(all.every(a=>a.every(x=>Number.isInteger(x)&&x>=0&&x<prefix.length)),"shared slots");
    let original=prefixCheck(manifest,prefix,rows);ck(original.failed===0,"original prefix");
    // A changed challenge output cannot be substituted after the hash circuit.
    const challengeWire=i.rho.find(x=>x>=2);ck(challengeWire!==undefined,"challenge wire");
    prefix[challengeWire]^=1;ck(prefixCheck(manifest,prefix,rows).failed>0,"changed challenge accepted");prefix[challengeWire]^=1;
    const Cwire=i.commitment[0];prefix[Cwire]^=1;ck(prefixCheck(manifest,prefix,rows).failed>0,"changed pinned commitment accepted");prefix[Cwire]^=1;
    if(badAhat)setScalar(prefix,i.a_hat,(le(fixture.a_hat)+1n)%scalar);
    // a_hat is not absorbed in the IPA transcript. This negative control
    // must pass the prefix and be rejected by the final group equation.
    ck(prefixCheck(manifest,prefix,rows).failed===0,"prefix after a_hat mutation");
    let fd=null,hash=null,output=null;
    if(emit){
        output=path.join(dir,"joint-export");fs.mkdirSync(output,{recursive:true});
        fd=fs.openSync(path.join(output,"limb-rows.jsonl"),"w");
        hash=crypto.createHash("sha256");
    }
    const onRow=emit?((ab,c)=>{
        const s=JSON.stringify({ab,c},(_,v)=>typeof v==="bigint"?v.toString():v)+"\n";
        hash.update(s);fs.writeSync(fd,s);
    }):null;
    const g=new Bqs(prefix,false,onRow);
    const imp=ids=>g.importScalar(ids,scalar);
    const x=Array.from({length:i.rounds},(_,j)=>imp(i.point.slice(j*256,(j+1)*256)));
    const y=imp(i.evaluation),ah=imp(i.a_hat),rho=imp(i.rho),ch=i.challenges.map(imp);
    const suffix=imp(i.suffix);
    ck(x.every((v,j)=>v.v===le(fixture.point[j]))&&y.v===le(fixture.evaluation)&&
       rho.v===le(fixture.rho)&&ch.every((v,j)=>v.v===le(fixture.challenges[j]))&&suffix.v===le(fixture.suffix),"native scalar differential");
    ck(ah.v===(le(fixture.a_hat)+(badAhat?1n:0n))%scalar,"a_hat interface");
    const C=g.point(null,base,i.commitment),L=i.l.map(ids=>g.point(null,base,ids)),R=i.r.map(ids=>g.point(null,base,ids));
    // Independently selected key constants for this fixture; a production
    // compiler must authenticate the complete VK from its own registry.
    const H=g.point(point(fixture.h),base,null,true),
          G=fixture.generators.map(p=>g.point(point(p),base,null,true));
    ck(G.length===2**i.rounds,"generator shape");
    const admitted=[C,...L,...R,H,...G];
    for(const p of admitted)g.admit(p,base);
    ck(g.failed===0,"point admission");
    const before=g.stats(),sc=g.ipaScalars(x,y,ah,rho,ch,scalar),after=g.stats();
    ck(g.failed===0&&sc.bhat.v===le(fixture.b_hat),"IPA scalar differential");
    ck(sc.ws.every((v,j)=>v.v===mod(-ah.v*le(fixture.s[j]),scalar)),"tensor MSM weights");
    let res,groupAdds,tableEntries=0;
    if(compact){
        const {compactAdd,fixedMSM,variableMSM}=require("./compact_msm.js");
        const v=variableMSM(g,[...L,...R],[...sc.r2,...sc.ri2],base);
        const f=fixedMSM(g,[H,...G].map(p=>g.pv(p)),[sc.hcoef,...sc.ws],base,8,32,true);
        res=compactAdd(g,C,compactAdd(g,v.r,f.r,base),base);
        groupAdds=v.adds+f.adds+2;tableEntries=f.entries;
    }else{
        const msm=g.msm([...L,...R,H,...G],[...sc.r2,...sc.ri2,sc.hcoef,...sc.ws],base,64);
        res=g.groupAdd(C,msm.r,base);groupAdds=msm.group_adds+1;
    }
    ck(g.failed===0,"group trace");
    const beforeFinal=g.nrows;
    g.pointEq(res,g.point(O,base,null,true));
    if(badAhat)ck(g.failed>0&&g.first.row>beforeFinal,"altered a_hat not rejected at group equality");
    else ck(g.failed===0,"native opening group equation failed");
    const st=g.stats(),report={
        curve:i.curve,rounds:i.rounds,opening_terms:G.length+2*i.rounds+1,
        native_positive:!badAhat,mutated_a_hat:badAhat,accepted:g.failed===0,
        prefix_equations:manifest.gate_rows+manifest.pin_rows,
        prefix_boolean_unknowns:manifest.boolean_unknowns,
        prefix_quadratic_equations:original.quadratic,
        prefix_shape_sha256:manifest.shape_sha256,
        interfaces_sha256:sha(read(dir,"interfaces.json")),
        fixture_sha256:sha(read(dir,"fixture.json")),
        scalar_folding_new_unknowns:after.boolean_unknowns-before.boolean_unknowns,
        scalar_folding_equations:after.equations-before.equations,
        group_additions:groupAdds,compact,fixed_table_entries:tableEntries,
        limb_equations:st.equations,limb_quadratic_equations:st.quadratic_equations,
        total_boolean_unknowns:st.boolean_unknowns,total_equations:manifest.gate_rows+manifest.pin_rows+st.equations,
        max_products_per_equation:Math.max(1,st.max_products_per_equation),
        failed_rows:st.failed_rows,first_failure:st.first_failure,
        negative_controls:{changed_transcript_challenge:true,changed_pinned_commitment:true},
        elapsed_seconds:(Date.now()-started)/1000,
        scope:"isolated IPA opening only; no full compressed Nova acceptance"
    };
    if(emit){
        fs.closeSync(fd);
        const af=fs.openSync(path.join(output,"assignment.bin"),"w");
        for(let pos=0;pos<g.w.n;pos+=g.w.chunk)fs.writeSync(af,g.w.chunks[pos>>>20].subarray(0,Math.min(g.w.chunk,g.w.n-pos)));
        fs.closeSync(af);
        report.limb_rows_sha256=hash.digest("hex");
        fs.writeFileSync(path.join(output,"manifest.json"),JSON.stringify(report,null,2)+"\n");
    }
    return report;
}
if(require.main===module){
    const args=process.argv.slice(2);
    ck(args.length>=1,"usage: ipa_joint.js TRANSCRIPT_DIR [--negative] [--emit] [--compact]");
    const bad=args.includes("--negative"),emit=args.includes("--emit");
    ck(!(bad&&emit),"only export positive assignments");
    console.log(JSON.stringify(run(args[0],bad,emit,args.includes("--compact"))));
}
module.exports={prefixCheck,run};
