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
    signal input burnKey;
    signal input addressBytes[20];
    signal input outCiphertext[10][20];

    var NUM_ADMINS = 10;

    // Hardcoded admin public keys (derived from private keys 123456789, 1..9)
    var PKX[10];
    var PKY[10];
    PKX[0] = 15919299401931535325513703139194931338293993994510664661086800834970360591752;
    PKY[0] = 1645780246786685895560641778865228215443840970280597910012614014295481144366;
    PKX[1] = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    PKY[1] = 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    PKX[2] = 10031262171927540148667355526369034398030886437092045105752248699557385197826;
    PKY[2] = 633281375905621697187330766174974863687049529291089048651929454608812697683;
    PKX[3] = 2763488322167937039616325905516046217694264098671987087929565332380420898366;
    PKY[3] = 15305195750036305661220525648961313310481046260814497672243197092298550508693;
    PKX[4] = 12252886604826192316928789929706397349846234911198931249025449955069330867144;
    PKY[4] = 1286140751908834028607023759717162073146610688084909004843365841635476459484;
    PKX[5] = 11480966271046430430613841218147196773252373073876138147006741179837832100836;
    PKY[5] = 15148236048131954717802795400425086368006776860859772698778589175317365693546;
    PKX[6] = 10483991165196995731760716870725509190315033255344071753161464961897900552628;
    PKY[6] = 16822899191463256771813724222715007505997804748105685077895991386716774358231;
    PKX[7] = 20092560661213339045022877747484245238324772779820628739268223482659246842641;
    PKY[7] = 12112450042127193446189577552007703839818242727902437791835414514847797088033;
    PKX[8] = 7582035475627193640797276505418002166691739036475590846121162698650004832581;
    PKY[8] = 7801528930831391612913542953849263092120765287178679640990215688947513841260;
    PKX[9] = 4705897243203718691035604313913899717760209962238015362153877735592901317263;
    PKY[9] = 11533909001000295577818857040682494493436124051895563619976413559559984357704;

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

    // 3) Per-admin: compute shared secret, keystream, XOR, and assert ciphertext
    component S[10];
    component pose[10];
    component ks[10];
    component kBits[10][20];
    signal xorBit[10][20][8];
    signal acc[10][20][8];
    signal byteVal[10][20];

    for (var k = 0; k < NUM_ADMINS; k++) {
        S[k] = EscalarMulAny(253);
        for (var i = 0; i < 253; i++) { S[k].e[i] <== rBits.out[i]; }
        S[k].p[0] <== PKX[k];
        S[k].p[1] <== PKY[k];

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

        for (var i = 0; i < 20; i++) {
            byteVal[k][i] === outCiphertext[k][i];
        }
    }

}

// Imported by proof_of_burn.circom
