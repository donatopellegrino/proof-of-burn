
pragma circom 2.0.0;

include "babyjub.circom";
include "poseidon.circom";
include "bitify.circom";

// include "../circomlib/circuits/poseidon.circom";
// include "../circomlib/circuits/babyjub.circom";
// include "../circomlib/circuits/bitify.circom";
include "./convert.circom";
include "./array.circom";
include "./constants.circom";

// template BurnAddress() {
//     signal input burnKey;
//     signal input revealAmount;
//     signal input burnExtraCommitment;
//     signal output addressBytes[20];

//     // Take the first 20-bytes of
//     //   Poseidon4(POSEIDON_BURN_ADDRESS_PREFIX, burnKey, revealAmount, burnExtraCommitment) as a burn-address
//     signal hash <== Poseidon(4)([POSEIDON_BURN_ADDRESS_PREFIX(), burnKey, revealAmount, burnExtraCommitment]);
//     signal hashBytes[32] <== Num2BigEndianBytes(32)(hash);
//     addressBytes <== Fit(32, 20)(hashBytes);
// }

// ---------------------------
// Dummy BurnAddress template
// ---------------------------
// template BurnAddress() {
//     signal input burnKey;
//     signal input revealAmount;
//     signal input burnExtraCommitment;
//     signal output addressBytes[20];

//     // For demo purposes, fill with deterministic values
//     for (var i = 0; i < 20; i++) {
//         addressBytes[i] <== i + 1;
//     }
// }

// -------------------------------------------
// Constants
// -------------------------------------------
// -------------------------------------------
// BabyJub generator constants
// -------------------------------------------
function Gx() -> res {
    res = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
}

function Gy() -> res {
    res = 16950150798460657717958625567821834550301663161624707787222815936182638968203;
}

// -------------------------------------------
// Example: Subgroup order constant
// -------------------------------------------
function SUBORDER() -> res {
    res = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
}

// -------------------------------------------
// Converts 32 bytes to a single field element
// -------------------------------------------
template BytesToField(n) {
    signal input in[n];
    signal output out;

    signal acc;
    acc <== 0;
    for (var i = 0; i < n; i++) {
        acc <== acc * 256 + in[i];
    }
    out <== acc;
}

// -------------------------------------------
//   Main circuit combining both
//   + asserting expected public R
// -------------------------------------------
// Encrypt addressBytes[20] with hard-coded PK and check ciphertext
template BurnAddressEncryptFixed() {
    var r = 123456711; // small test value for demonstration

    // ---------------------------
    // 1️⃣ Compute R = r * G
    // ---------------------------
    component Rcomp = BabyJubScalarMul();
    Rcomp.scalar <== r;
    Rcomp.P[0] <== BabyJub.Base8[0]; // G.x
    Rcomp.P[1] <== BabyJub.Base8[1]; // G.y

    // Hard-coded R.x and R.y (32-byte arrays for example)
    signal Rx[32];
    signal Ry[32];

    // Assign each byte of R.x
    Rx[0]  <== 120;
    Rx[1]  <== 57;
    Rx[2]  <== 107;
    Rx[3]  <== 247;
    Rx[4]  <== 54;
    Rx[5]  <== 92;
    Rx[6]  <== 240;
    Rx[7]  <== 229;
    Rx[8]  <== 11;
    Rx[9]  <== 158;
    Rx[10] <== 139;
    Rx[11] <== 17;
    Rx[12] <== 17;
    Rx[13] <== 80;
    Rx[14] <== 221;
    Rx[15] <== 198;
    Rx[16] <== 32;
    Rx[17] <== 212;
    Rx[18] <== 113;
    Rx[19] <== 202;
    Rx[20] <== 157;
    Rx[21] <== 95;
    Rx[22] <== 14;
    Rx[23] <== 42;
    Rx[24] <== 164;
    Rx[25] <== 55;
    Rx[26] <== 17;
    Rx[27] <== 241;
    Rx[28] <== 247;
    Rx[29] <== 31;
    Rx[30] <== 230;
    Rx[31] <== 42;

    // Assign each byte of R.y
    Ry[0]  <== 155;
    Ry[1]  <== 246;
    Ry[2]  <== 194;
    Ry[3]  <== 121;
    Ry[4]  <== 164;
    Ry[5]  <== 185;
    Ry[6]  <== 86;
    Ry[7]  <== 178;
    Ry[8]  <== 82;
    Ry[9]  <== 116;
    Ry[10] <== 148;
    Ry[11] <== 134;
    Ry[12] <== 0;
    Ry[13] <== 23;
    Ry[14] <== 251;
    Ry[15] <== 255;
    Ry[16] <== 253;
    Ry[17] <== 126;
    Ry[18] <== 66;
    Ry[19] <== 70;
    Ry[20] <== 168;
    Ry[21] <== 136;
    Ry[22] <== 185;
    Ry[23] <== 85;
    Ry[24] <== 2;
    Ry[25] <== 238;
    Ry[26] <== 212;
    Ry[27] <== 239;
    Ry[28] <== 97;
    Ry[29] <== 209;
    Ry[30] <== 229;
    Ry[31] <== 41;

    // First, pack the Rx and Ry bytes back into field elements
    component RxNum = BigEndianBytesToNum(32);
    component RyNum = BigEndianBytesToNum(32);

    for (var i = 0; i < 32; i++) {
        RxNum.in[i] <== Rx[i];
        RyNum.in[i] <== Ry[i];
    }

    // Now assert that Rcomp equals these constants
    Rcomp.out[0] === RxNum.out;
    Rcomp.out[1] === RyNum.out;

    signal input burnKey;
    signal input revealAmount;
    signal input burnExtraCommitment;
    signal output addressHashNibbles[64];

    // ---------------------------
    // Hard-coded constants
    // ---------------------------
    // Hardcoded public key bytes
    signal PKxBytes[32];
    signal PKyBytes[32];

    // Fill with the JS-generated values
    PKxBytes[0]  <== 178;
    PKxBytes[1]  <== 239;
    PKxBytes[2]  <==  88;
    PKxBytes[3]  <==  41;
    PKxBytes[4]  <== 152;
    PKxBytes[5]  <==  69;
    PKxBytes[6]  <==  27;
    PKxBytes[7]  <== 109;
    PKxBytes[8]  <== 254;
    PKxBytes[9]  <==  94;
    PKxBytes[10] <==  92;
    PKxBytes[11] <==  48;
    PKxBytes[12] <==   0;
    PKxBytes[13] <== 228;
    PKxBytes[14] <==  84;
    PKxBytes[15] <== 220;
    PKxBytes[16] <==  72;
    PKxBytes[17] <==  39;
    PKxBytes[18] <== 233;
    PKxBytes[19] <== 195;
    PKxBytes[20] <== 252;
    PKxBytes[21] <== 201;
    PKxBytes[22] <==  43;
    PKxBytes[23] <== 161;
    PKxBytes[24] <==  30;
    PKxBytes[25] <== 110;
    PKxBytes[26] <==  80;
    PKxBytes[27] <== 105;
    PKxBytes[28] <==  10;
    PKxBytes[29] <==  86;
    PKxBytes[30] <== 227;
    PKxBytes[31] <==   6;

    // Similarly for PKy
    PKyBytes[0]  <== 101;
    PKyBytes[1]  <==  87;
    PKyBytes[2]  <==  56;
    PKyBytes[3]  <== 113;
    PKyBytes[4]  <==  25;
    PKyBytes[5]  <== 218;
    PKyBytes[6]  <== 212;
    PKyBytes[7]  <== 223;
    PKyBytes[8]  <==  77;
    PKyBytes[9]  <==  24;
    PKyBytes[10] <==  74;
    PKyBytes[11] <==  25;
    PKyBytes[12] <== 143;
    PKyBytes[13] <==  31;
    PKyBytes[14] <==  74;
    PKyBytes[15] <==  82;
    PKyBytes[16] <== 236;
    PKyBytes[17] <==  81;
    PKyBytes[18] <== 190;
    PKyBytes[19] <==  96;
    PKyBytes[20] <== 233;
    PKyBytes[21] <==  21;
    PKyBytes[22] <== 192;
    PKyBytes[23] <== 148;
    PKyBytes[24] <== 144;
    PKyBytes[25] <== 190;
    PKyBytes[26] <== 171;
    PKyBytes[27] <== 176;
    PKyBytes[28] <==  15;
    PKyBytes[29] <== 141;
    PKyBytes[30] <== 178;
    PKyBytes[31] <==   5;

    // Convert bytes to field elements
    component PKxNum = BigEndianBytesToNum(32);
    component PKyNum = BigEndianBytesToNum(32);

    for (var i = 0; i < 32; i++) {
        PKxNum.in[i] <== PKxBytes[i];
        PKyNum.in[i] <== PKyBytes[i];
    }

    // Now PKxNum.out and PKyNum.out are the field elements representing the public key coordinates
    // var PKx <== PKxNum.out;
    // var PKy <== PKyNum.out;
    // var PKx = 123456789;
    // var PKy = 987654321;

    // Hard-coded ciphertext
    // signal ciphertextBytes[20];
    // ciphertextBytes[0] <== 90;
    // ciphertextBytes[1] <== 107;
    // ciphertextBytes[2] <== 124;
    // ciphertextBytes[3] <== 141;
    // ciphertextBytes[4] <== 158;
    // ciphertextBytes[5] <== 175;
    // ciphertextBytes[6] <== 176;
    // ciphertextBytes[7] <== 193;
    // ciphertextBytes[8] <== 210;
    // ciphertextBytes[9] <== 227;
    // ciphertextBytes[10] <== 244;
    // ciphertextBytes[11] <== 5;
    // ciphertextBytes[12] <== 22;
    // ciphertextBytes[13] <== 39;
    // ciphertextBytes[14] <== 56;
    // ciphertextBytes[15] <== 73;
    // ciphertextBytes[16] <== 90;
    // ciphertextBytes[17] <== 107;
    // ciphertextBytes[18] <== 124;
    // ciphertextBytes[19] <== 141;

    // Hard-coded ciphertext (from your JS output)
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

    // ---------------------------
    // Compute burn address
    // ---------------------------
    // component burnAddr = BurnAddress();
    // burnAddr.burnKey <== burnKey;
    // burnAddr.revealAmount <== revealAmount;
    // burnAddr.burnExtraCommitment <== burnExtraCommitment;
    signal burnAddr[20];
    // Hard-coded burn address
    burnAddr[0]  <== 1;
    burnAddr[1]  <== 2;
    burnAddr[2]  <== 3;
    burnAddr[3]  <== 4;
    burnAddr[4]  <== 5;
    burnAddr[5]  <== 6;
    burnAddr[6]  <== 7;
    burnAddr[7]  <== 8;
    burnAddr[8]  <== 9;
    burnAddr[9]  <== 10;
    burnAddr[10] <== 11;
    burnAddr[11] <== 12;
    burnAddr[12] <== 13;
    burnAddr[13] <== 14;
    burnAddr[14] <== 15;
    burnAddr[15] <== 16;
    burnAddr[16] <== 17;
    burnAddr[17] <== 18;
    burnAddr[18] <== 19;
    burnAddr[19] <== 20;

    signal addressBytes[20];
    for (var i = 0; i < 20; i++) {
        // addressBytes[i] <== burnAddr.addressBytes[i];
        addressBytes[i] <== burnAddr[i];
    }

    // encryption

    // Compute S = r * PK
    component S = BabyJubScalarMul();
    S.scalar <== r;
    S.P[0] <== PKxNum.out;
    S.P[1] <== PKyNum.out;

    // Now S.out[0] is Sx, S.out[1] is Sy
    signal Sx <== S.out[0];
    signal Sy <== S.out[1];

    // ---------------------------
    // Compute Poseidon-based keystream
    // ---------------------------

    // Sx and Sy are the outputs from BabyJubScalarMul
    component pose = Poseidon(1);
    pose.inputs[0] <== Sx;

    // Convert Poseidon output to bytes for XOR
    component poseBytes = Num2BigEndianBytes(32);
    poseBytes.in <== pose.out;

    signal keystream[20];
    for (var i = 0; i < 20; i++) {
        keystream[i] <== poseBytes.out[i]; // take first 20 bytes as keystream
    }

    // component pose = Poseidon(4);
    // pose.inputs[0] <== PKxNum.out;
    // pose.inputs[1] <== PKyNum.out;
    // // capital R
    // pose.inputs[2] <== RxNum.out;
    // pose.inputs[3] <== RyNum.out;

    // // Convert Poseidon output to bytes
    // component poseBytes = Num2BigEndianBytes(32);
    // poseBytes.in <== pose.out;

    // signal keystream[20];
    // for (var i = 0; i < 20; i++) {
    //     keystream[i] <== poseBytes.out[i]; // first 20 bytes
    // }

    // ---------------------------
    // XOR with keystream and assert ciphertext
    // ---------------------------
    // Declare Num2Bits components outside loop
    component aBits[20];
    component kBits[20];
    signal byteVal[20];
    signal xorbit[20][8];
    signal acc[20][8]; // acc[i][b] stores partial sum up to bit b

    for (var i = 0; i < 20; i++) {
        aBits[i] = Num2Bits(8);
        kBits[i] = Num2Bits(8);

        aBits[i].in <== addressBytes[i];
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
        byteVal[i] === ciphertextBytes[i]; // use constant array outside template
    }

}


// Instantiate the template as the main component
component main = BurnAddressEncryptFixed();
