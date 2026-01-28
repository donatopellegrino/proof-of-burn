pragma circom 2.0.0;

include "babyjub.circom";
include "poseidon.circom";
include "bitify.circom";
include "convert.circom";
include "array.circom";
include "constants.circom";
include "escalarmulany.circom";

// run inside circuits/utils folder: circom test2.circom --wasm --sym -l ./node_modules/circomlib/circuits

template BigEndianBytesToNum(n) {
    signal input in[n];
    signal output out;

    signal partial[n]; // partial sums

    var i;
    partial[0] <== in[0];
    for (i = 1; i < n; i++) {
        partial[i] <== partial[i-1]*256 + in[i];
    }

    out <== partial[n-1];
}

// ---------------------------
// BurnAddressEncrypt using EscalarMulAny
// ---------------------------
template BurnAddressEncryptFixed() {
    // ---------------------------
    // 1️⃣ Hard-coded ephemeral scalar r (for demo)
    // ---------------------------
    signal input burnKey;
    signal input revealAmount;
    signal input burnExtraCommitment;

    signal output addressHashNibbles[64];

    // ---------------------------
    // Hard-coded r
    // ---------------------------
    var rVal = 123456711;
    component rBits = Num2Bits(253);
    rBits.in <== rVal;

    // ---------------------------
    // 2️⃣ Compute R = r * G
    // ---------------------------
    signal G[2];
    G[0] <== 5299619240641551281634865583518297030282874472190772894086521144482721001553; // Base8.x
    G[1] <== 16950150798460657717958625567821834550301663161624707787222815936182638968203; // Base8.y

    component Rcomp = EscalarMulAny(253);
    for (var i=0; i<253; i++) {
        Rcomp.e[i] <== rBits.out[i];
    }
    Rcomp.p[0] <== G[0];
    Rcomp.p[1] <== G[1];

    signal Rx <== Rcomp.out[0];
    signal Ry <== Rcomp.out[1];

    // ---------------------------
    // 3️⃣ Convert JS PK bytes to field element
    // ---------------------------
    signal PKxBytes[32];
    signal PKyBytes[32];

    // Fill with JS-generated values (same as before)
    PKxBytes[0]  <== 178; PKxBytes[1]  <== 239; PKxBytes[2]  <==  88; PKxBytes[3]  <==  41;
    PKxBytes[4]  <== 152; PKxBytes[5]  <==  69; PKxBytes[6]  <==  27; PKxBytes[7]  <== 109;
    PKxBytes[8]  <== 254; PKxBytes[9]  <==  94; PKxBytes[10] <==  92; PKxBytes[11] <==  48;
    PKxBytes[12] <==   0; PKxBytes[13] <== 228; PKxBytes[14] <==  84; PKxBytes[15] <== 220;
    PKxBytes[16] <==  72; PKxBytes[17] <==  39; PKxBytes[18] <== 233; PKxBytes[19] <== 195;
    PKxBytes[20] <== 252; PKxBytes[21] <== 201; PKxBytes[22] <==  43; PKxBytes[23] <== 161;
    PKxBytes[24] <==  30; PKxBytes[25] <== 110; PKxBytes[26] <==  80; PKxBytes[27] <== 105;
    PKxBytes[28] <==  10; PKxBytes[29] <==  86; PKxBytes[30] <== 227; PKxBytes[31] <==   6;

    PKyBytes[0]  <== 101; PKyBytes[1]  <==  87; PKyBytes[2]  <==  56; PKyBytes[3]  <== 113;
    PKyBytes[4]  <==  25; PKyBytes[5]  <== 218; PKyBytes[6]  <== 212; PKyBytes[7]  <== 223;
    PKyBytes[8]  <==  77; PKyBytes[9]  <==  24; PKyBytes[10] <==  74; PKyBytes[11] <==  25;
    PKyBytes[12] <== 143; PKyBytes[13] <==  31; PKyBytes[14] <==  74; PKyBytes[15] <==  82;
    PKyBytes[16] <== 236; PKyBytes[17] <==  81; PKyBytes[18] <== 190; PKyBytes[19] <==  96;
    PKyBytes[20] <== 233; PKyBytes[21] <==  21; PKyBytes[22] <== 192; PKyBytes[23] <== 148;
    PKyBytes[24] <== 144; PKyBytes[25] <== 190; PKyBytes[26] <== 171; PKyBytes[27] <== 176;
    PKyBytes[28] <==  15; PKyBytes[29] <== 141; PKyBytes[30] <== 178; PKyBytes[31] <==   5;

    component PKxNum = BigEndianBytesToNum(32);
    component PKyNum = BigEndianBytesToNum(32);
    for (var i=0; i<32; i++) {
        PKxNum.in[i] <== PKxBytes[i];
        PKyNum.in[i] <== PKyBytes[i];
    }

    // ---------------------------
    // 4️⃣ Compute S = r * PK
    // ---------------------------
    component S = EscalarMulAny(253);
    for (var i=0; i<253; i++) {
        S.e[i] <== rBits.out[i];
    }
    S.p[0] <== PKxNum.out;
    S.p[1] <== PKyNum.out;

    signal Sx <== S.out[0];
    signal Sy <== S.out[1];

    // ---------------------------
    // 5️⃣ Poseidon hash on Sx → keystream
    // ---------------------------
    component pose = Poseidon(1);
    pose.inputs[0] <== Sx;

    component poseBytes = Num2BigEndianBytes(32);
    poseBytes.in <== pose.out;

    signal keystream[20];
    for (var i=0; i<20; i++) {
        keystream[i] <== poseBytes.out[i];
    }

    // ---------------------------
    // 6️⃣ Hard-coded burn address
    // ---------------------------
    signal burnAddr[20];
    for (var i=0; i<20; i++) {
        burnAddr[i] <== i+1;
    }

    // ---------------------------
    // 7️⃣ XOR with keystream → assert ciphertext
    // ---------------------------
    // Hard-coded ciphertext from JS
    signal ciphertextBytes[20];
    ciphertextBytes[0]  <== 99;
    ciphertextBytes[1]  <== 102;
    ciphertextBytes[2]  <== 128;
    ciphertextBytes[3]  <== 198;
    ciphertextBytes[4]  <== 85;
    ciphertextBytes[5]  <== 76;
    ciphertextBytes[6]  <== 109;
    ciphertextBytes[7]  <== 147;
    ciphertextBytes[8]  <== 180;
    ciphertextBytes[9]  <== 228;
    ciphertextBytes[10] <== 183;
    ciphertextBytes[11] <== 239;
    ciphertextBytes[12] <== 228;
    ciphertextBytes[13] <== 2;
    ciphertextBytes[14] <== 121;
    ciphertextBytes[15] <== 72;
    ciphertextBytes[16] <== 215;
    ciphertextBytes[17] <== 19;
    ciphertextBytes[18] <== 134;
    ciphertextBytes[19] <== 77;

    component aBits[20];
    component kBits[20];
    signal byteVal[20];
    signal xorbit[20][8];
    signal acc[20][8];

    for (var i = 0; i < 20; i++) {
        aBits[i] = Num2Bits(8);
        kBits[i] = Num2Bits(8);

        aBits[i].in <== burnAddr[i];
        kBits[i].in <== keystream[i];

        for (var b = 0; b < 8; b++) {
            xorbit[i][b] <== aBits[i].out[b] + kBits[i].out[b] - 2 * (aBits[i].out[b] * kBits[i].out[b]);
            if (b == 0) {
                acc[i][b] <== xorbit[i][b] * (1 << b);
            } else {
                acc[i][b] <== acc[i][b-1] + xorbit[i][b] * (1 << b);
            }
        }

        byteVal[i] <== acc[i][7];
        byteVal[i] === ciphertextBytes[i];
    }
}

// ---------------------------
// Main instantiation
// ---------------------------
component main = BurnAddressEncryptFixed();
