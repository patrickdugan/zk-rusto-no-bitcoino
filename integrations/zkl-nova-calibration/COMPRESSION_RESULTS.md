# ZKL-11 — verified Nova + Spartan/IPA compression receipt

Verified GitHub Actions execution: https://github.com/patrickdugan/zk-rusto-no-bitcoino/actions/runs/45564437510/job/139035684400

Source branch at measured run: research/zkl-authenticated-row-step-20261125 (183295047b73fa9d56a51d5b39f1b384f95647c7). Three-step ground Horn derivation; depth 4, maximum arity 2, actual Nova 0.76.0 recursive and compressed verification. No Groth16 wrapper.

| Measurement | Value |
|---|---:|
| Serialized compressed proof | 11,032 bytes |
| Compressed proving incl. setup | 7.394671705 s |
| Compressed verification | 0.157943556 s |
| Serialized verification key | 23,304,808 bytes |
| Peak process RSS | 172,104 KiB |

This is a compression measurement on a small ground Horn fixture. The verification key is substantial and excluded from proof bytes. Witness privacy, dependent-type checking, adversarial deployment and Bitcoin settlement are outstanding. Do not treat the proof size or verifier time as a Bitcoin script measurement. See CI run for the actual backend execution.
