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

template BurnAddressEncryptFixed() {
    signal input addressBytes[20];
    // signal input rVal;
    signal PKx;
    signal PKy;

    // 1) Scalar r
    var rVal = 123456711;
    component rBits = Num2Bits(253);
    rBits.in <== rVal;

    // 2) BabyJub Generator G
    signal G[2];
    G[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    G[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Use the values from "Actual PKx BigInt" in your JS log
    PKx <== 15919299401931535325513703139194931338293993994510664661086800834970360591752;
    PKy <== 1645780246786685895560641778865228215443840970280597910012614014295481144366; // Get this from JS log

    // 4) S = r * PK
    component S = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) { S.e[i] <== rBits.out[i]; }
    S.p[0] <== PKx;
    S.p[1] <== PKy;

    // 5) Poseidon & Keystream
    component pose = Poseidon(2);
    pose.inputs[0] <== S.out[0];
    pose.inputs[1] <== S.out[1];

    log("Sx:", S.out[0]);
    log("Sy:", S.out[1]);
    log("Poseidon:", pose.out);

    component ks = PoseidonToKeystream();
    ks.in <== pose.out;

    // 6) XOR with Burn Address
    signal byteVal[20];
    signal input outCiphertext[20];

    component aBits[20];
    component kBits[20];
    signal xorBit[20][8];
    signal acc[20][8];

    for (var i = 0; i < 20; i++) {
        aBits[i] = Num2Bits(8);
        kBits[i] = Num2Bits(8);

        aBits[i].in <== addressBytes[i]; // burn address
        kBits[i].in <== ks.out[i]; // keystream

        for (var b = 0; b < 8; b++) {
            // Assign to the pre-declared signal array
            xorBit[i][b] <== aBits[i].out[b] + kBits[i].out[b] - 2 * aBits[i].out[b] * kBits[i].out[b];
            
            if (b == 0) {
                acc[i][b] <== xorBit[i][b];
            } else {
                // Linear combination: acc + (constant * signal) is allowed!
                acc[i][b] <== acc[i][b-1] + xorBit[i][b] * (1 << b);
            }
        }
        
        byteVal[i] <== acc[i][7];
        log("Byte ", i, " Ciphertext: ", byteVal[i]);
    }
    
    for (var i = 0; i < 20; i++) {
        byteVal[i] === outCiphertext[i];
    }

}

// Imported by proof_of_burn.circom
