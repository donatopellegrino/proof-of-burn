pragma circom 2.0.0;

// commands to run that file or debug:
// 1. circom test2.circom --r1cs --wasm --sym -l ./node_modules/circomlib/circuits
// 2. node test2_js/generate_witness.js test2_js/test2.wasm input.json witness.wtns
// 3. snarkjs wtns export json witness.wtns witness.json
// --> here the lines at the top reflect the output wires --> useful for debugging
// 4. vim witness.json
// more docs: https://docs.circom.io/getting-started/compiling-circuits/
// more docs: https://docs.circom.io/getting-started/computing-the-witness/

include "babyjub.circom";
include "poseidon.circom";
include "bitify.circom";
include "convert.circom";
include "constants.circom";
include "escalarmulany.circom";

template BigEndianBytesToNum(n) {
    signal input in[n];
    signal output out;

    signal acc[n];
    acc[0] <== in[0];
    for (var i = 1; i < n; i++) {
        acc[i] <== acc[i-1] * 256 + in[i];
    }
    out <== acc[n-1];
}

template BurnAddressEncryptFixed() {

    // Dummy inputs (unused but required)
    signal input burnKey;
    signal input revealAmount;
    signal input burnExtraCommitment;

    // ----------------------------------
    // 1) Fixed ephemeral scalar r
    // ----------------------------------
    var rVal = 123456711;
    component rBits = Num2Bits(253);
    rBits.in <== rVal;

    // ----------------------------------
    // 2) Base8 generator
    // ----------------------------------
    signal G[2];
    G[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    G[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    component R = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        R.e[i] <== rBits.out[i];
    }
    R.p[0] <== G[0];
    R.p[1] <== G[1];

    // Hard-coded ciphertext from JS
    signal expectedCiphertext[20];
    expectedCiphertext[0]  <== 20;
    expectedCiphertext[1]  <== 221;
    expectedCiphertext[2]  <== 153;
    expectedCiphertext[3]  <== 251;
    expectedCiphertext[4]  <== 240;
    expectedCiphertext[5]  <== 242;
    expectedCiphertext[6]  <== 151;
    expectedCiphertext[7]  <== 191;
    expectedCiphertext[8]  <== 40;
    expectedCiphertext[9]  <== 205;
    expectedCiphertext[10] <== 250;
    expectedCiphertext[11] <== 169;
    expectedCiphertext[12] <== 56;
    expectedCiphertext[13] <== 162;
    expectedCiphertext[14] <== 244;
    expectedCiphertext[15] <== 88;
    expectedCiphertext[16] <== 152;
    expectedCiphertext[17] <== 227;
    expectedCiphertext[18] <== 250;
    expectedCiphertext[19] <== 211;


    // ----------------------------------
    // 3) Hard-coded public key bytes
    // ----------------------------------
    signal PKxBytes[32];
    signal PKyBytes[32];

    // (exactly as in your original circuit)
    PKxBytes[0] <== 178; PKxBytes[1] <== 239; PKxBytes[2] <== 88;  PKxBytes[3] <== 41;
    PKxBytes[4] <== 152; PKxBytes[5] <== 69;  PKxBytes[6] <== 27;  PKxBytes[7] <== 109;
    PKxBytes[8] <== 254; PKxBytes[9] <== 94;  PKxBytes[10] <== 92; PKxBytes[11] <== 48;
    PKxBytes[12] <== 0;  PKxBytes[13] <== 228; PKxBytes[14] <== 84; PKxBytes[15] <== 220;
    PKxBytes[16] <== 72; PKxBytes[17] <== 39;  PKxBytes[18] <== 233; PKxBytes[19] <== 195;
    PKxBytes[20] <== 252; PKxBytes[21] <== 201; PKxBytes[22] <== 43; PKxBytes[23] <== 161;
    PKxBytes[24] <== 30; PKxBytes[25] <== 110; PKxBytes[26] <== 80; PKxBytes[27] <== 105;
    PKxBytes[28] <== 10; PKxBytes[29] <== 86;  PKxBytes[30] <== 227; PKxBytes[31] <== 6;

    PKyBytes[0] <== 101; PKyBytes[1] <== 87;  PKyBytes[2] <== 56;  PKyBytes[3] <== 113;
    PKyBytes[4] <== 25;  PKyBytes[5] <== 218; PKyBytes[6] <== 212; PKyBytes[7] <== 223;
    PKyBytes[8] <== 77;  PKyBytes[9] <== 24;  PKyBytes[10] <== 74; PKyBytes[11] <== 25;
    PKyBytes[12] <== 143; PKyBytes[13] <== 31; PKyBytes[14] <== 74; PKyBytes[15] <== 82;
    PKyBytes[16] <== 236; PKyBytes[17] <== 81; PKyBytes[18] <== 190; PKyBytes[19] <== 96;
    PKyBytes[20] <== 233; PKyBytes[21] <== 21; PKyBytes[22] <== 192; PKyBytes[23] <== 148;
    PKyBytes[24] <== 144; PKyBytes[25] <== 190; PKyBytes[26] <== 171; PKyBytes[27] <== 176;
    PKyBytes[28] <== 15;  PKyBytes[29] <== 141; PKyBytes[30] <== 178; PKyBytes[31] <== 5;

    component PKx = BigEndianBytesToNum(32);
    component PKy = BigEndianBytesToNum(32);
    for (var i = 0; i < 32; i++) {
        PKx.in[i] <== PKxBytes[i];
        PKy.in[i] <== PKyBytes[i];
    }

    // ----------------------------------
    // 4) Shared secret S = r * PK
    // ----------------------------------
    component S = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        S.e[i] <== rBits.out[i];
    }
    S.p[0] <== PKx.out;
    S.p[1] <== PKy.out;

    // ----------------------------------
    // 5) Poseidon(Sx, Sy)
    // ----------------------------------
    component pose = Poseidon(2);
    pose.inputs[0] <== S.out[0];
    pose.inputs[1] <== S.out[1];

    component poseBytes = Num2BigEndianBytes(32);
    poseBytes.in <== pose.out;

    signal keystream[20];
    for (var i = 0; i < 20; i++) {
        keystream[i] <== poseBytes.out[i];
    }

    // ----------------------------------
    // 6) Burn address
    // ----------------------------------
    signal burnAddr[20];
    for (var i = 0; i < 20; i++) {
        burnAddr[i] <== i + 1;
    }

    // ----------------------------------
    // 7) XOR
    // ----------------------------------
    component aBits[20];
    component kBits[20];
    signal xorbit[20][8];
    signal acc[20][8];
    signal byteVal[20];

    for (var i = 0; i < 20; i++) {
        aBits[i] = Num2Bits(8);
        kBits[i] = Num2Bits(8);

        aBits[i].in <== burnAddr[i];
        kBits[i].in <== keystream[i];

        for (var b = 0; b < 8; b++) {
            xorbit[i][b] <==
                aBits[i].out[b] +
                kBits[i].out[b] -
                2 * aBits[i].out[b] * kBits[i].out[b];
        }

        acc[i][0] <== xorbit[i][0];
        for (var b = 1; b < 8; b++) {
            acc[i][b] <== acc[i][b-1] + xorbit[i][b] * (1 << b);
        }

        byteVal[i] <== acc[i][7];
    }

    // assertion
    for (var i = 0; i < 20; i++) {
        byteVal[i] === expectedCiphertext[i];
    }
}

component main = BurnAddressEncryptFixed();
