pragma circom 2.0.0;

// // commands to run that file or debug:
// // 1. circom test2.circom --r1cs --wasm --sym -l ./node_modules/circomlib/circuits
// // 2. node test2_js/generate_witness.js test2_js/test2.wasm input.json witness.wtns
// // 3. snarkjs wtns export json witness.wtns witness.json
// // --> here the lines at the top reflect the output wires --> useful for debugging
// // 4. vim witness.json
// // more docs: https://docs.circom.io/getting-started/compiling-circuits/
// // more docs: https://docs.circom.io/getting-started/computing-the-witness/

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
    // Dummy inputs (unused but required)
    // signal input burnKey;
    // signal input revealAmount;
    // signal input burnExtraCommitment;

    // 1) Scalar r
    var rVal = 123456711;
    component rBits = Num2Bits(253);
    rBits.in <== rVal;

    // 2) BabyJub Generator G
    signal G[2];
    G[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    G[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Replace the 32-byte array and loop with this:
    signal PKx;
    signal PKy;

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
    signal output outCiphertext[20];
    signal output expectedCiphertext[20];

    component aBits[20];
    component kBits[20];
    signal xorBit[20][8];
    signal acc[20][8];

    for (var i = 0; i < 20; i++) {
        aBits[i] = Num2Bits(8);
        kBits[i] = Num2Bits(8);

        aBits[i].in <== i + 1;
        kBits[i].in <== ks.out[i];

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
        
        outCiphertext[i] <== acc[i][7];
        log("Byte ", i, " Ciphertext: ", outCiphertext[i]);
    }

    for (var i = 0; i < 20; i++) {
        outCiphertext[i] === expectedCiphertext[i];
    }
}

component main = BurnAddressEncryptFixed();
