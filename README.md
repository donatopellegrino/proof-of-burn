## Proof-of-Burn Circuits (EIP-7503 Extension)

This repo contains the Circom benchmarks used in the paper for the EIP-7503 extension.  
The extension adds linkability privileges for an admin via encrypted burn-address checks.
Run on `amd64` (x86_64).

## Benchmark Commands (Paper)

Run from the repo root:

```bash
git submodule update --init --recursive
cd circuits
```

Compile the paper circuit and generate a witness:

```bash
circom test_paper.circom --r1cs --wasm --sym -l ./circomlib/circuits
npm install -g circom
node test_paper_js/generate_witness.js test_paper_js/test_paper.wasm input.json witness.wtns
```

Groth16 setup, prove, and verify:

```bash
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final.ptau
snarkjs groth16 setup test_paper.r1cs pot12_final.ptau test_paper_0000.zkey
snarkjs zkey export verificationkey test_paper_0001.zkey verification_key.json
snarkjs groth16 prove eip7502-test_paper_0001.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```
