// import * as circomlib from "circomlibjs";
const circomlib = require("circomlibjs");

async function main() {
    const babyJub = await circomlib.buildBabyjub();
    const poseidon = await circomlib.buildPoseidon();

    // Generate a private key
    const privKey = 123456789n;
    const r = 123456711n;

    // Standard BabyJub generator point G
    const G = babyJub.Base8; // G is Base8 in circomlibjs

    // Compute R = r * G
    const R = babyJub.mulPointEscalar(G, r);

    // Multiply base point
    const pubKey = babyJub.mulPointEscalar(babyJub.Base8, privKey);

    console.log("Private key:", privKey.toString());
    console.log("Public key X:", pubKey[0].toString());
    console.log("Public key Y:", pubKey[1].toString());

    console.log("Ephemeral scalar r:", r.toString());
    console.log("Computed R.x:", R[0].toString());
    console.log("Computed R.y:", R[1].toString());

    // ---------------------------
    // 2️⃣ Hard-coded burn address
    // ---------------------------
    const burnAddr = [
        1,2,3,4,5,6,7,8,9,10,
        11,12,13,14,15,16,17,18,19,20
    ];

    // ---------------------------
    // 3️⃣ Compute S = r * PK
    // ---------------------------
    const S = babyJub.mulPointEscalar(pubKey, r);

    // ---------------------------
    // 4️⃣ Poseidon hash to derive keystream
    // ---------------------------
    // Convert S components to BigInt
    const SxBigInt = bytesToBigInt(S[0]);
    const SyBigInt = bytesToBigInt(S[1]);

    // Compute keystream via Poseidon
    const poseidonOutputObj = poseidon([SxBigInt, SyBigInt]);
    const poseidonOutput = poseidon.F.toObject(poseidonOutputObj);

    // Convert to 20-byte keystream
    let keystream = [];
    let tmp = BigInt(poseidonOutput);
    for (let i = 0; i < 20; i++) {
        keystream.unshift(Number(tmp % 256n));
        tmp = tmp / 256n;
    }

    console.log("Keystream bytes:", keystream);

    // ---------------------------
    // 5️⃣ XOR burnAddr with keystream → ciphertext
    // ---------------------------
    const ciphertext = burnAddr.map((b, i) => b ^ keystream[i]);

    console.log("Ciphertext:", ciphertext);

    // ----------------------------------------
    // 🔓 DECRYPT USING PRIVATE KEY sk
    // ----------------------------------------
    const S2 = babyJub.mulPointEscalar(R, privKey);

    const SxBig = bytesToBigInt(S2[0]);
    const SyBig = bytesToBigInt(S2[1]);

    const poseidonOutObj2 = poseidon([SxBig, SyBig]);
    const poseidonOut2 = poseidon.F.toObject(poseidonOutObj2);

    let keystream2 = [];
    let tmp2 = BigInt(poseidonOut2);
    for (let i = 0; i < 20; i++) {
        keystream2.unshift(Number(tmp2 % 256n));
        tmp2 = tmp2 / 256n;
    }

    const recovered = ciphertext.map((b, i) => b ^ keystream[i]);

    console.log("Recovered:", recovered);

    // Assertion
    const ok = JSON.stringify(burnAddr) === JSON.stringify(recovered);
    console.log("Correct decryption:", ok);

    if (!ok) throw new Error("Decryption failed!");
}

main();

function bytesToBigInt(bytes) {
    let result = 0n;
    for (let b of bytes) {
        result = (result << 8n) + BigInt(b);
    }
    return result;
}

// Yes — the pattern you’re trying to implement is basically BabyJubjub + Poseidon asymmetric “one-time pad” encryption, which is the common approach in ZK-friendly encryption schemes like Tornado Cash’s “note encryption.” Let me explain step by step so it’s clear:

// 1️⃣ Key Generation

// The receiver has a BabyJubjub key pair:

// Private key: sk (BigInt)

// Public key: PK = sk * G

// The sender generates a random ephemeral scalar r (small r) per message.

// 2️⃣ Compute Ephemeral Public Key

// The sender computes the ephemeral public key R = r * G

// This is analogous to R in standard ECIES: it will be sent along with the ciphertext as a public input.

// 3️⃣ Compute Shared Secret

// The sender computes a shared secret S = r * PK

// PK is the receiver’s public key.

// This ensures that only someone knowing the receiver’s private key can compute S (via S = sk * R) to decrypt.

// 4️⃣ Derive Keystream

// S (BabyJubjub point) is then converted into a keystream:

// Option 1: Serialize S.x (or both x and y) to bytes and use directly.

// Option 2: Hash S with Poseidon to get a fixed-length output.

// This produces the pseudo-random bytes that will XOR with the message (burn address in your case).

// 5️⃣ Encrypt Message

// XOR the burn address bytes with the keystream bytes → ciphertext.

// 6️⃣ Decryption

// Receiver sees (ciphertext, R):

// Compute S = sk * R (using their private key).

// Serialize/hash S to the keystream.

// XOR ciphertext with keystream → original burn address.

// ✅ Note:

// The ephemeral scalar r must remain secret, otherwise the attacker can compute S and decrypt.

// This is analogous to ECIES with elliptic curves, except using BabyJubjub + Poseidon so it’s efficient in ZK circuits.