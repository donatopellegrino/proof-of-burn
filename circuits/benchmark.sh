#!/usr/bin/env bash
set -e

# One-time setup
npm install
curl -C - -O https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_24.ptau

bench() {
    local label="$1"; shift
    local times=()

    local n=10
    for run in $(seq 1 $n); do
        echo "--- $label: starting run $run / $n ---"
        local start=$(date +%s%3N)
        "$@"
        local elapsed=$(( $(date +%s%3N) - start ))
        times+=($elapsed)
        echo "--- $label: run $run done in ${elapsed}ms ---"
        echo ""
    done

    local sum=0
    for t in "${times[@]}"; do sum=$((sum + t)); done
    local avg=$((sum / n))
    echo ">>> $label: ${times[*]}  (avg ${avg}ms)"
    echo ""
}

circom test_paper.circom --r1cs --wasm --sym -l ./circomlib/circuits
node test_paper_js/generate_witness.js test_paper_js/test_paper.wasm input.json witness.wtns
env NODE_OPTIONS="--max-old-space-size=30720" npx snarkjs groth16 setup test_paper.r1cs powersOfTau28_hez_final_24.ptau test_paper_0000.zkey
npx snarkjs zkey export verificationkey test_paper_0000.zkey verification_key.json
bench "groth16 prove"    npx snarkjs groth16 prove test_paper_0000.zkey witness.wtns proof.json public.json
bench "groth16 verify"   npx snarkjs groth16 verify verification_key.json public.json proof.json

npx snarkjs zkey export solidityverifier test_paper_0000.zkey verifier.sol

# Deploy Groth16Verifier
echo "=== Deploying Groth16Verifier ==="
VERIFIER_ADDR=$(forge create circuits/verifier.sol:Groth16Verifier \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --broadcast \
  --json | jq -r .deployedTo)
echo "Verifier deployed at: $VERIFIER_ADDR"

# Send on-chain verification transaction
echo "=== Sending on-chain verification ==="
CAST_CMD=$(npx snarkjs zkey export soliditycalldata | node format_calldata.js \
  | grep "cast send <VERIFIER_ADDRESS>" \
  | sed "s|<VERIFIER_ADDRESS>|$VERIFIER_ADDR|")
echo "$CAST_CMD"
bash -c "$CAST_CMD"
