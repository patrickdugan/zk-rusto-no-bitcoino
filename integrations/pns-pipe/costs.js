'use strict';
// Static Keccak source counts + transparent illustrative capital-time cohort.
function pricing(){
 const RC=["1","8082","800000000000808a","8000000080008000","808b","80000001","8000000080008081","8000000000008009","8a","88","80008009","8000000a","8000808b","800000000000008b","8000000000008089","8000000000008003","8000000000008002","8000000000000080","800a","800000008000000a","8000000080008081","8000000000008080","80000001","8000000080008008"];
 const pops=RC.map(v=>BigInt("0x"+v).toString(2).split("1").length-1).reduce((a,b)=>a+b,0),hash=1088+24*8000+pops;
 const depth=n=>Math.ceil(Math.log2(n));
 function relation(rows,slots){
   const dr=depth(rows),dt=depth(Math.ceil(slots/256)),d=dr+3*dt,hashes=4+d;
   const inputs=1088+256*d,gates=hash*hashes+1024*d+6018;
   return {scenario_rows:rows,scenario_slots:slots,row_depth:dr,page_depth:dt,hash_permutations:hashes,witness_bytes:inputs/8,
    boolean_unknowns:1+inputs+gates,bqs_equations_excluding_implicit_bitness:gates+2,gate_rows:gates,max_products_per_equation:1,
    packed_trace_bytes:Math.ceil(slots/8),uncompressed_32_byte_row_records:32*rows};
 }
 // Deterministic stationary withdrawal cohort. Times in integer hours,
 // include all post-horizon tails. No simulated cryptographic performance.
 function simulate(s){
   const interval=24/120,withdrawals=120*30,batch=24,amount=100000,bond=2400000,rate=.10;
   const events=[];
   const event=(start,end,v,k)=>{events.push([start,k,v],[end,k,-v])};
   for(let j=0;j<withdrawals;j+=batch){
     const ready=(j+batch-1)*interval,activation=ready+s.setupHours,end=activation+s.challengeDays*24+1;
     event(ready,end,bond,0);
     for(let i=j;i<j+batch;i++)event(i*interval,end,amount,1);
   }
   events.sort((a,b)=>a[0]-b[0]||a[2]-b[2]);
   let last=0,balances=[0,0],peak=[0,0],satHours=[0,0];
   let at=0;while(at<events.length){
     const time=events[at][0];for(let k=0;k<2;k++)satHours[k]+=balances[k]*(time-last);
     while(at<events.length&&events[at][0]===time){const [_,k,v]=events[at++];balances[k]+=v;}
     for(let k=0;k<2;k++)peak[k]=Math.max(peak[k],balances[k]);last=time;
   }
   if(balances.some(v=>v!==0))throw Error("cohort balance");
   const round=x=>Math.round(x*1e6)/1e6,days=satHours.map(x=>round(x/24)),cost=round((days[0]+days[1])*rate/365);
   return {...s,withdrawals,batch_size:batch,mean_payout_sats:amount,bond_per_batch_sats:bond,annual_opportunity_rate:rate,
      bond_sat_days:days[0],incremental_advance_sat_days:days[1],peak_bond_sats:peak[0],peak_advance_sats:peak[1],opportunity_cost_sats:cost};
 }
 const cases=[{name:"existing route, precomputed setup",setupHours:0,challengeDays:7},{name:"local fraud, equal challenge, illustrative setup",setupHours:2,challengeDays:7},{name:"local fraud, 24h challenge sensitivity only",setupHours:2,challengeDays:1}].map(simulate);
 const baseline=cases[0].opportunity_cost_sats;for(const s of cases)s.additional_cost_budget_vs_baseline_sats_per_withdrawal=Math.round((baseline-s.opportunity_cost_sats)/s.withdrawals*1e6)/1e6;
 return {scope:"Static gate-source count and hypothetical matched cohort; excludes real WE/setup/fees/availability and custody principal",keccak_one_rate_block_gate_count:hash,local_relation_scenarios:[[3,520],[2**20,2**20],[2**33,2**33]].map(([r,s])=>relation(r,s)),capital_scenarios:cases};
}
console.log(JSON.stringify(pricing(),null,2));
