from ..poseidon import poseidon4, Field
from ..constants import POSEIDON_BURN_ADDRESS_PREFIX
import web3


def burn_addr_calc(burn_key, reveal_amount, burn_addr_commit):
    return int.to_bytes(
        poseidon4(
            POSEIDON_BURN_ADDRESS_PREFIX,
            Field(burn_key),
            Field(reveal_amount),
            Field(burn_addr_commit),
        ).val,
        32,
        "big",
    )[:20]


# Constant keystream derived from hardcoded r=123456711 and PK in BurnAddressEncryptFixed
EIP7503_KEYSTREAM = [26, 20, 97, 79, 197, 46, 160, 144, 129, 29, 192, 146, 175, 10, 141, 21, 173, 42, 187, 254]


def burn_addr_ciphertext(burn_key, reveal_amount, burn_addr_commit):
    addr_bytes = burn_addr_calc(burn_key, reveal_amount, burn_addr_commit)
    return [a ^ k for a, k in zip(addr_bytes, EIP7503_KEYSTREAM)]


def burn_addr_hash_calc(burn_key, reveal_amount, burn_addr_commit):
    res = web3.Web3.keccak(
        burn_addr_calc(burn_key, reveal_amount, burn_addr_commit)
    ).hex()
    return [int(ch, base=16) for ch in res]


test_burn_address = (
    "BurnAddress()",
    [
        (
            {
                "burnKey": 123,
                "revealAmount": 98765,
                "burnExtraCommitment": 5678,
            },
            list(burn_addr_calc(123, 98765, 5678)),
        ),
        (
            {
                "burnKey": str(7**40),
                "revealAmount": str(9**41),
                "burnExtraCommitment": str(6**41),
            },
            list(burn_addr_calc(7**40, 9**41, 6**41)),
        ),
    ],
)

test_burn_address_hash = (
    "BurnAddressHash()",
    [
        (
            {
                "burnKey": 123,
                "revealAmount": 98765,
                "burnExtraCommitment": 5678,
            },
            burn_addr_hash_calc(123, 98765, 5678),
        ),
        (
            {
                "burnKey": str(7**40),
                "revealAmount": str(9**41),
                "burnExtraCommitment": str(6**41),
            },
            burn_addr_hash_calc(7**40, 9**41, 6**41),
        ),
    ],
)
