#!/usr/bin/env node
// Wraps "npx snarkjs zkey export soliditycalldata" and formats output for:
//   1. ProofOfBurnWrapper  — "verify(uint256[2],uint256[2][2],uint256[2],uint256,bytes)"
//   2. Groth16Verifier     — "verifyProof(uint[2],uint[2][2],uint[2],uint[101])"
//
// Usage (pipe):
//   npx snarkjs zkey export soliditycalldata test_paper_0000.zkey witness.wtns | node format_calldata.js
//
// Usage (run directly, reads proof.json + public.json from cwd):
//   node format_calldata.js

const { execSync } = require('child_process');

// Strip leading zero padding and keep only the 20 significant bytes
function pack20(hex) {
    return hex.replace(/^0x/, '').padStart(64, '0').slice(-40);
}

// cast wants unquoted hex values inside arrays, e.g. [0xabc,0xdef]
function castArray(arr) {
    if (Array.isArray(arr[0])) {
        return '[' + arr.map(inner => '[' + inner.join(',') + ']').join(',') + ']';
    }
    return '[' + arr.join(',') + ']';
}

function format(raw) {
    const [pA, pB, pC, pubSignals] = JSON.parse('[' + raw.trim() + ']');

    const commitment = pubSignals[0];
    const ciphertexts = pubSignals.slice(1);
    // 20 bytes per ciphertext — no leading zeros
    const ciphertextBytes = '0x' + ciphertexts.map(c => pack20(c)).join('');
    console.log('# ProofOfBurnWrapper');
    console.log(
        `cast send <WRAPPER_ADDRESS>` +
        ` "verify(uint256[2],uint256[2][2],uint256[2],uint256,bytes)"` +
        ` '${castArray(pA)}'` +
        ` '${castArray(pB)}'` +
        ` '${castArray(pC)}'` +
        ` '${commitment}'` +
        ` '${ciphertextBytes}'` +
        ` --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
    );

    console.log('\n# Groth16Verifier');
    console.log(
        `cast send <VERIFIER_ADDRESS>` +
        ` "verifyProof(uint[2],uint[2][2],uint[2],uint[101])"` +
        ` '${castArray(pA)}'` +
        ` '${castArray(pB)}'` +
        ` '${castArray(pC)}'` +
        ` '${castArray(pubSignals)}'` +
        ` --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
    );
}

if (process.stdin.isTTY) {
    // No pipe: run snarkjs ourselves
    try {
        const raw = execSync(
            'npx snarkjs groth16 exportsoliditycalldata witness.wtns public.json',
            { encoding: 'utf8' }
        );
        format(raw);
    } catch (e) {
        console.error('Failed to run snarkjs. Either pipe the output or ensure witness.wtns and public.json exist.\n');
        console.error('Usage: npx snarkjs zkey export soliditycalldata <zkey> <wtns> | node format_calldata.js');
        process.exit(1);
    }
} else {
    let raw = '';
    process.stdin.on('data', d => raw += d);
    process.stdin.on('end', () => format(raw));
}
