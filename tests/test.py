import io
import subprocess
import json
import struct


def parse_wtns_outputs(path, num_outputs):
    with open(path, "rb") as f:
        data = f.read()
    offset = 12  # skip magic(4) + version(4) + numSections(4)
    n8 = None
    witness_data = None
    for _ in range(struct.unpack_from("<I", data, 8)[0]):
        section_type = struct.unpack_from("<I", data, offset)[0]
        section_size = struct.unpack_from("<Q", data, offset + 4)[0]
        section_start = offset + 12
        if section_type == 1:
            n8 = struct.unpack_from("<I", data, section_start)[0]
        elif section_type == 2:
            witness_data = data[section_start : section_start + section_size]
        offset = section_start + section_size
    return [
        int.from_bytes(witness_data[i * n8 : (i + 1) * n8], "little")
        for i in range(1, num_outputs + 1)
    ]


def run(main, test_cases):
    print()
    print(f"Testing {main}")
    print("=" * 20)
    with io.open("circuits/test.circom", "w") as f:
        imports = """
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

        """
        f.write(imports + f"component main = {main};")
    subprocess.run(
        ["circom", "--wasm", "circuits/test.circom", "--O0", "-l", "circuits/circomlib/circuits"],
        check=True,
    )
    outputs = []
    for test_case, expected in test_cases:
        with io.open("test_js/input.json", "w") as f:
            json.dump(test_case, f)
        res = subprocess.run(
            ["node", "--unhandled-rejections=strict", "test_js/generate_witness.js",
             "test_js/test.wasm", "test_js/input.json", "test_js/witness.wtns"],
            capture_output=True,
        )
        if res.returncode != 0:
            if expected is not None:
                raise Exception(f"Expected success but failed: {res.stderr.decode()}")
            outputs.append(None)
        else:
            if expected is None:
                raise Exception(f"Expected failure but succeeded!")
            output = parse_wtns_outputs("test_js/witness.wtns", len(expected))
            if output != expected:
                raise Exception(f"Unexpected output! {output} != {expected}")
            outputs.append(output)
    return outputs


from .testcases.public_commitment import (
    test_public_commitment_1,
    test_public_commitment_2,
    test_public_commitment_6,
)
from .testcases.rlp.merkle_patricia_trie_leaf import (
    test_truncated_address_hash,
    test_is_in_range,
    test_leaf_detector_1,
    test_leaf_detector_2,
    test_rlp_merkle_patricia_trie_leaf,
)
from .testcases.divide import test_divide
from .testcases.poseidon import test_poseidon_2, test_poseidon_3, test_poseidon_4
from .testcases.substring_check import test_substring_check
from .testcases.shift import test_shift_left, test_shift_right
from .testcases.concat import test_concat, test_mask
from .testcases.selector import (
    test_selector,
    test_selector_array_1d,
    test_selector_array_2d,
)
from .testcases.convert import (
    test_big_endian_bytes_2_num,
    test_bytes_2_nibbles,
    test_little_endian_bytes_2_num,
    test_num_2_big_endian_bytes,
    test_num_2_little_endian_bytes,
    test_nibbles_2_bytes,
    test_num_2_bits_safe_32,
    test_num_2_bits_safe_254,
    test_num_2_bits_safe_256,
)
from .testcases.keccak import test_pad, test_keccak_1, test_keccak_2
from .testcases.burn_address import test_burn_address_hash, test_burn_address
from .testcases.assertion import (
    test_assert_bits,
    test_assert_byte_string,
    test_assert_greater_eq_than,
    test_assert_less_eq_than,
    test_assert_less_than,
)
from .testcases.array import (
    test_fit_1,
    test_fit_2,
    test_reverse,
    test_flatten,
    test_filter,
    test_reshape,
)
from .testcases.rlp.integer import (
    test_rlp_integer_1,
    test_rlp_integer_2,
    test_count_bytes,
)
from .testcases.proof_of_burn import test_proof_of_burn
from .testcases.rlp.empty_account import (
    test_rlp_empty_account_1,
    test_rlp_empty_account_2,
    test_rlp_empty_account_3,
)
from .testcases.proof_of_work import (
    test_proof_of_work,
    test_concat_fixed_4,
    test_pow_eip7503_postfix,
)
from .testcases.spend import test_spend

if __name__ == "__main__":
    run(*test_spend)
    run(*test_pow_eip7503_postfix)
    run(*test_concat_fixed_4)
    run(*test_proof_of_work)
    run(*test_public_commitment_1)
    run(*test_public_commitment_2)
    run(*test_public_commitment_6)
    run(*test_poseidon_2)
    run(*test_poseidon_3)
    run(*test_poseidon_4)
    run(*test_divide)
    run(*test_substring_check)
    run(*test_shift_left)
    run(*test_shift_right)
    run(*test_mask)
    run(*test_concat)
    run(*test_selector)
    run(*test_selector_array_1d)
    run(*test_selector_array_2d)
    run(*test_big_endian_bytes_2_num)
    run(*test_bytes_2_nibbles)
    run(*test_little_endian_bytes_2_num)
    run(*test_num_2_big_endian_bytes)
    run(*test_num_2_little_endian_bytes)
    run(*test_nibbles_2_bytes)
    run(*test_num_2_bits_safe_32)
    run(*test_num_2_bits_safe_254)
    run(*test_num_2_bits_safe_256)
    run(*test_pad)
    run(*test_keccak_1)
    run(*test_keccak_2)
    run(*test_burn_address)
    run(*test_burn_address_hash)
    run(*test_assert_bits)
    run(*test_assert_byte_string)
    run(*test_assert_less_eq_than)
    run(*test_assert_less_than)
    run(*test_assert_greater_eq_than)
    run(*test_proof_of_burn)
    run(*test_filter)
    run(*test_fit_1)
    run(*test_fit_2)
    run(*test_reverse)
    run(*test_flatten)
    run(*test_reshape)
    run(*test_rlp_integer_1)
    run(*test_rlp_integer_2)
    run(*test_count_bytes)
    run(*test_rlp_empty_account_1)
    run(*test_rlp_empty_account_2)
    run(*test_rlp_empty_account_3)
    run(*test_truncated_address_hash)
    run(*test_is_in_range)
    run(*test_leaf_detector_1)
    run(*test_leaf_detector_2)
    run(*test_rlp_merkle_patricia_trie_leaf)
