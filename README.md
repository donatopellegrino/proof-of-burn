## Proof-of-Burn Circuits (EIP-7503 Extension)

This repo contains the Circom benchmarks used in the paper for the EIP-7503 extension.  
The extension adds linkability privileges for an admin via encrypted burn-address checks.
Run on `amd64` (x86_64).

## Benchmark Commands (Paper)

You need circom: https://docs.circom.io/getting-started/installation/

Run from the repo root:

```bash
git submodule update --init --recursive
cd circuits
npm install
```

Compile the paper circuit and generate a witness:

```bash
circom test_paper.circom --r1cs --wasm --sym -l ./circomlib/circuits
node test_paper_js/generate_witness.js test_paper_js/test_paper.wasm input.json witness.wtns
```

Groth16 setup, prove, and verify:

```bash
wget -c https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_24.ptau
NODE_OPTIONS="--max-old-space-size=30720" npx snarkjs groth16 setup test_paper.r1cs powersOfTau28_hez_final_24.ptau test_paper_0000.zkey
npx snarkjs zkey export verificationkey test_paper_0000.zkey verification_key.json
npx snarkjs groth16 prove test_paper_0000.zkey witness.wtns proof.json public.json
npx snarkjs groth16 verify verification_key.json public.json proof.json
```

Get solidity verifier and calldata:
```
npx snarkjs zkey export solidityverifier test_paper_0000.zkey verifier.sol
npx snarkjs zkey export soliditycalldata
npx snarkjs zkey export soliditycalldata | node format_calldata.js # CALLDATA formatted for cast
```

To deploy the verifier
```
forge create circuits/verifier.sol:Groth16Verifier \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast
```
To create a wrapper that accepts buffered cyphertexts:
```
forge create circuits/ProofOfBurnWrapper.sol:ProofOfBurnWrapper \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast \
  --constructor-args 0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0
```