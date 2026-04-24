pragma circom 2.0.0;

// commands to run that file or debug:
// 0. node node eip7503-extension.js
// --> copy ciphertext output to input.json
// 1. circom eip7503-extension.circom --r1cs --wasm --sym -l ./node_modules/circomlib/circuits
// 2. node eip7503-extension_js/generate_witness.js eip7503-extension_js/eip7503-extension.wasm input.json witness.wtns
// 3. snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
// 4. snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v
// 5. snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
// 6. snarkjs groth16 setup eip7503-extension.r1cs pot12_final.ptau eip7502-extension_0000.zkey
// 7. snarkjs zkey contribute eip7502-extension_0000.zkey eip7502-extension_0001.zkey --name="1st Contributor Name" -v
// --> enter 123 as entropy
// 8. snarkjs zkey export verificationkey eip7502-extension_0001.zkey verification_key.json
// 9. snarkjs groth16 prove eip7502-extension_0001.zkey witness.wtns proof.json public.json
// 10. snarkjs groth16 verify verification_key.json public.json proof.json
// 11. snarkjs zkey export solidityverifier eip7502-extension_0001.zkey verifier.sol
// 12. anvil
// 13. forge create circuits/utils/verifier.sol:Groth16Verifier --rpc-url http://127.0.0.1:8545 --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
// 14. in verifier.sol, change uint[0] to uint[] and change _pubSignals to _pubSignals.offset
// 15. copy paste verifier.sol into remix ide, compile, then deploy to Remix VM
// 16. snarkjs generatecall
// 17. copy paste output of previous command to remix ide next to verifyProof button and hit that button -> inspect true below

// todo, integrate into proof-of-burn circuit -> run entire repo test with that to get metrics

// debugging
// X. snarkjs wtns export json witness.wtns witness.json
// --> here the lines at the top reflect the output wires --> useful for debugging
// X. vim witness.json
// more docs: https://docs.circom.io/getting-started/compiling-circuits/
// more docs: https://docs.circom.io/getting-started/computing-the-witness/

include "babyjub.circom";
include "poseidon.circom";
include "bitify.circom";
include "escalarmulany.circom";
include "./admin_keys.circom";

template PoseidonToKeystream() {
    signal input in;
    signal output out[20];

    component n2b = Num2Bits(256);
    n2b.in <== in;

    for (var i = 0; i < 20; i++) {
        var byteVal = 0;
        for (var j = 0; j < 8; j++) {
            // Index i*8 starts from the Least Significant Bit
            byteVal += n2b.out[i * 8 + j] * (1 << j);
        }
        // out[0] gets the 1st byte (LSB), out[19] gets the 20th byte
        // To match your JS 'unshift' order:
        out[19 - i] <== byteVal;
    }
}

// numAdmins: compile-time parameter — use the first numAdmins keys from AdminKeys (max 100)
template BurnAddressEncryptFixed(numAdmins) {
    signal input burnKey;
    signal input addressBytes[20];
    signal output outCiphertext[numAdmins];

    component ak = AdminKeys();

    // 1) Scalar r (shared across all admins)
    component rHash = Poseidon(2);
    rHash.inputs[0] <== 7503;
    rHash.inputs[1] <== burnKey;
    component rBits = Num2Bits(253);
    rBits.in <== rHash.out;

    // 2) Address bits (shared across all admins)
    component aBits[20];
    for (var i = 0; i < 20; i++) {
        aBits[i] = Num2Bits(8);
        aBits[i].in <== addressBytes[i];
    }

    // 3) Per-admin: compute shared secret, keystream, XOR, and pack into output
    component S[numAdmins];
    component pose[numAdmins];
    component ks[numAdmins];
    component kBits[numAdmins][20];
    signal xorBit[numAdmins][20][8];
    signal acc[numAdmins][20][8];
    signal byteVal[numAdmins][20];
    signal packAcc[numAdmins][21];

    for (var k = 0; k < numAdmins; k++) {
        S[k] = EscalarMulAny(253);
        for (var i = 0; i < 253; i++) { S[k].e[i] <== rBits.out[i]; }
        S[k].p[0] <== ak.PKX[k];
        S[k].p[1] <== ak.PKY[k];

        pose[k] = Poseidon(2);
        pose[k].inputs[0] <== S[k].out[0];
        pose[k].inputs[1] <== S[k].out[1];

        ks[k] = PoseidonToKeystream();
        ks[k].in <== pose[k].out;

        for (var i = 0; i < 20; i++) {
            kBits[k][i] = Num2Bits(8);
            kBits[k][i].in <== ks[k].out[i];

            for (var b = 0; b < 8; b++) {
                xorBit[k][i][b] <== aBits[i].out[b] + kBits[k][i].out[b] - 2 * aBits[i].out[b] * kBits[k][i].out[b];
                if (b == 0) {
                    acc[k][i][b] <== xorBit[k][i][b];
                } else {
                    acc[k][i][b] <== acc[k][i][b-1] + xorBit[k][i][b] * (1 << b);
                }
            }

            byteVal[k][i] <== acc[k][i][7];
        }

        // Pack 20 bytes big-endian into a single field element
        packAcc[k][0] <== 0;
        for (var i = 0; i < 20; i++) {
            packAcc[k][i+1] <== packAcc[k][i] * 256 + byteVal[k][i];
        }
        outCiphertext[k] <== packAcc[k][20];
    }

}

// Imported by proof_of_burn.circom
