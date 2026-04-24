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
        local start=$(date +%s)
        "$@"
        local elapsed=$(( $(date +%s) - start ))
        times+=($elapsed)
        echo "--- $label: run $run done in ${elapsed}s ---"
        echo ""
    done

    local sum=0
    for t in "${times[@]}"; do sum=$((sum + t)); done
    local avg=$((sum / n))
    echo ">>> $label: ${times[*]}  (avg ${avg}s)"
    echo ""
}

bench "circom compile"   circom test_paper.circom --r1cs --wasm --sym -l ./circomlib/circuits
bench "generate witness" node test_paper_js/generate_witness.js test_paper_js/test_paper.wasm input.json witness.wtns
bench "groth16 setup"    env NODE_OPTIONS="--max-old-space-size=30720" npx snarkjs groth16 setup test_paper.r1cs powersOfTau28_hez_final_24.ptau test_paper_0000.zkey
bench "export vkey"      npx snarkjs zkey export verificationkey test_paper_0000.zkey verification_key.json
bench "groth16 prove"    npx snarkjs groth16 prove test_paper_0000.zkey witness.wtns proof.json public.json
bench "groth16 verify"   npx snarkjs groth16 verify verification_key.json public.json proof.json
