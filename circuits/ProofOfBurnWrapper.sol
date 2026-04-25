// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import "./verifier.sol";

// Wrapper around Groth16Verifier that accepts ciphertexts as a flat bytes blob
// instead of a uint[101] array, making it easier to call from on-chain contracts
// that build the ciphertext list dynamically.
//
// pubSignals layout (matches circom output order):
//   [0]      commitment
//   [1..100] outCiphertext[0..99]  (100 admin ciphertexts, each a packed 20-byte field element)
contract ProofOfBurnWrapper {
    Groth16Verifier public immutable verifier;
    uint256 constant NUM_CIPHERTEXTS = 100;

    constructor(address _verifier) {
        verifier = Groth16Verifier(_verifier);
    }

    // ciphertexts: exactly NUM_CIPHERTEXTS * 20 bytes, each ciphertext packed
    //              as its 20 significant bytes (leading zero padding stripped).
    function verify(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 commitment,
        bytes calldata ciphertexts
    ) external view returns (bool) {
        require(ciphertexts.length == NUM_CIPHERTEXTS * 20, "wrong ciphertext length");

        uint[101] memory pubSignals;
        pubSignals[0] = commitment;

        uint256 cdOffset;
        assembly { cdOffset := ciphertexts.offset }

        for (uint i = 0; i < NUM_CIPHERTEXTS; i++) {
            uint256 ct;
            // calldataload reads 32 bytes; our value occupies the first 20 (high bits),
            // so right-shift by 96 bits to drop the trailing overlap with the next entry.
            assembly { ct := shr(96, calldataload(add(cdOffset, mul(i, 20)))) }
            pubSignals[i + 1] = ct;
        }

        return verifier.verifyProof(pA, pB, pC, pubSignals);
    }
}
