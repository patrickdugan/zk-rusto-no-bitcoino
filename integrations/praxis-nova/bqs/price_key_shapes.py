#!/usr/bin/env python3
"""Price only the IPA group schedule, from verified local Nova key shape receipts."""
import json,sys,math
ADD=5639
ADD_EQ=133
VAR_LOOKUP=1051  # 16 one-hot bits, canonical x/y and infinity
def fixed(n,w,shifted):
    windows=math.ceil(255/w)
    lookups=n*windows
    doubles=0 if shifted else w*(windows-1)
    entries=n*(1<<w)*(windows if shifted else 1)
    return {"window_bits":w,"shifted":shifted,"fixed_bases":n,"windows":windows,
      "group_additions":lookups+doubles,"boolean_unknowns":ADD*(lookups+doubles)+(511+(1<<w))*lookups,
      "equations":ADD_EQ*(lookups+doubles)+(w+8)*lookups,
      "table_entries":entries,"table_coordinates_bytes_at_64_each":64*entries}
def price(s):
    n=s["ipa_domain"];ell=s["ipa_rounds"];assert n==1<<ell
    k=s["ipa_variable_bases"];assert k==2*ell
    fixed_n=s["ipa_fixed_bases"];assert fixed_n==n+1
    vadd=78*k+252;vbits=ADD*vadd+VAR_LOOKUP*64*k
    return {"domain":n,"rounds":ell,"variable_bases":k,"fixed_bases":fixed_n,
      "variable_group_additions":vadd,"variable_group_and_lookup_unknowns":vbits,
      "fixed_scenarios":[dict(x,combined_group_unknowns=x["boolean_unknowns"]+vbits+2*ADD)
          for w in [4,6,8,9,10] for shifted in [False,True] for x in [fixed(fixed_n,w,shifted)]]}
if __name__=="__main__":
    rows=[]
    for p in sys.argv[1:]:
        with open(p) as f:k=json.load(f)
        sides={s:price(k[s]) for s in ["primary","secondary"]}
        rows.append({"path":p,"vk_sha256":k["vk_sha256"],"arity":k["arity"],"sides":sides,
          "combined_8bit_unshifted_group_unknowns":sum(
            next(x["combined_group_unknowns"] for x in s["fixed_scenarios"]
                if x["window_bits"]==8 and not x["shifted"]) for s in sides.values())})
    print(json.dumps({"scope":"Static schedule estimates using actual key shape; excludes transcript, scalar coefficient generation, admission, Spartan and Nova folding; no ciphertext estimate", "fixtures":rows},indent=2))
