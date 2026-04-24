pragma circom 2.2.2;

        include "./circomlib/circuits/poseidon.circom";
        include "utils/shift.circom";
        include "utils/public_commitment.circom";
        include "utils/concat.circom";
        include "utils/rlp/integer.circom";
        include "utils/rlp/empty_account.circom";
        include "utils/rlp/merkle_patricia_trie_leaf.circom";
        include "utils/selector.circom";
        include "utils/substring_check.circom";
        include "utils/array.circom";
        include "utils/divide.circom";
        include "utils/convert.circom";
        include "utils/keccak.circom";
        include "proof_of_burn.circom";
        include "spend.circom";

component main = ProofOfBurn(4, 4, 5, 20, 31, 2, 10 ** 18, 10 ** 19);