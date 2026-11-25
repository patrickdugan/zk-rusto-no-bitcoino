// ZKL-NOVA-17: verifier-owned immutable primitive signatures.
// The six Nat declarations keep their original IDs. Eq has carrier Sort 1.
"use strict";
const S=u=>["S",u], C=i=>["C",i], B=i=>["B",i];
const P=(a,b)=>["P",a,b], A=(a,b)=>["A",a,b];
const apply=(f,...xs)=>xs.reduce((g,x)=>A(g,x),f);
const Nat=C(0), zero=C(1), succ=C(2);
function natRec(u){
 const step=P(Nat,P(A(B(2),B(0)),A(B(3),A(succ,B(1)))));
 return P(P(Nat,S(u)),P(A(B(0),zero),P(step,P(Nat,A(B(3),B(0))))));
}
const eqType=P(S(1),P(B(0),P(B(1),S(0))));
const reflType=P(S(1),P(B(0),apply(C(6),B(1),B(0),B(0))));
function pathInduction(v){
 // Pi A : Sort 1, Pi x : A,
 // Pi M : (Pi y : A, Eq A x y -> Sort v),
 // M x (refl A x) -> Pi y : A, Pi p : Eq A x y, M y p.
 const motive=P(B(1),P(apply(C(6),B(2),B(1),B(0)),S(v)));
 const base=apply(B(0),B(1),apply(C(7),B(2),B(1)));
 const tail=P(B(3),P(apply(C(6),B(4),B(3),B(0)),apply(B(3),B(1),B(0))));
 return P(S(1),P(B(0),P(motive,P(base,tail))));
}
const environment=[S(1),Nat,P(Nat,Nat),natRec(0),natRec(1),natRec(2),eqType,reflType,pathInduction(0),pathInduction(1),pathInduction(2)];
function freeze(x){if(Array.isArray(x)){x.forEach(freeze);Object.freeze(x)}return x}
module.exports=freeze(environment);
