#!/usr/bin/env python3
"""PRAXIS-09: reproducible paper-size accounting, not benchmark claims."""
import json, math
N,nc,nu,n,K1,K2,J,Jp,Delta,Dp=391693,1694,2048,4608,192,12,11,11,351001,315392
D=N+2+nu*nc
assert D==3861007 and J*Delta==D+4 and Dp*Jp==nu*nc
n1=(2*K1+1)*(N+1)+Delta+(nu-1)*nc//Jp
n2=6*K2*(N+1)+3*K2+3*n//2*(J+Jp)+13*n-8
assert 3*n//2==K1*3*K2
# Arkworks pointwise compressed sizes; GT serialization measured by native replay.
point_bytes=32*n1+64*2*n2
paper_gib=7.88
enc_mul=2**34.2
dec_mul=2**33
tail_mul=2**34.5
# Scenario rates are sustained base-field products/s, not measured GPU rates.
rates=[10**7,10**8,10**9,10**10]
m=round(2**28.7)
rows=[{"assumed_products_per_second":r,
       "enc_arithmetic_s":enc_mul/r,"dec_expected_arithmetic_s":dec_mul/r,
       "dec_tail_arithmetic_s":tail_mul/r} for r in rates]
sizes=[{"distinct_conditions":i,"paper_ciphertext_storage_GiB":paper_gib*i,
        "pointwise_storage_GiB":point_bytes*i/2**30} for i in [1,10,100,1000]]
print(json.dumps({"source":"Praxis Table 4; Proposition 5.7; Section 6.3",
    "parameters":{"D":D,"n1_G1":n1,"n2_G2_before_alpha":n2,"total_G2":2*n2},
    "pointwise_group_bytes_excluding_GT_seed_message":point_bytes,
    "pointwise_group_GiB":point_bytes/2**30,
    "paper_batch_compressed_GiB":paper_gib,
    "baby_steps_approx":m,"packed_table_GB":12*m/10**9,
    "paper_enc_precompute_GB":12.35,"paper_dec_table_GB":5.28,
    "arithmetic_only_scenarios":rows,"storage_scenarios":sizes,
    "io_only_seconds_for_7_88_GiB":[{"GiB_per_s":v,"seconds":paper_gib/v} for v in [0.1,0.5,1,3,6]],
    "caveat":"Do not infer end-to-end wall time from field products; include Fr/Fp mix, FFTs, MSMs, sorting, hash, serialization, file IO and transfers. Paper compression differs from pointwise Arkworks. No measured GPU throughput."},indent=2))
