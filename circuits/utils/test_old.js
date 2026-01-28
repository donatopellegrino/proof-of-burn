// decrypt_burn_address.js
import * as circomlib from 'circomlibjs';

async function main() {
    // -----------------------------
    // Hard-coded Circom test parameters
    // -----------------------------
    const PKx = 123456789n;
    const PKy = 987654321n;
    // const Rx  = 111111111n;
    // const Ry  = 222222222n;

    const ciphertext = [90,107,124,141,158,175,176,193,210,227,244,5,22,39,56,73,90,107,124,141];

    // -----------------------------
    // Compute Poseidon keystream
    // -----------------------------
    const poseidon = await circomlib.buildPoseidon();
    const poseidonOutput = poseidon([PKx, PKy, Rx, Ry]); // Uint8Array or array of numbers in bytes

    // If output is array of numbers, use directly
    const poseBytes = Array.isArray(poseidonOutput) ? poseidonOutput : Array.from(poseidonOutput);

    // Take first 20 bytes as keystream
    const keystream = poseBytes.slice(0, 20);

    // -----------------------------
    // XOR ciphertext with keystream
    // -----------------------------
    const decrypted = ciphertext.map((c, i) => c ^ keystream[i]);

    // -----------------------------
    // Output results
    // -----------------------------
    console.log("Keystream (20 bytes):", keystream);
    console.log("Ciphertext:", ciphertext);
    console.log("Decrypted burn address:", decrypted);
}

main();
