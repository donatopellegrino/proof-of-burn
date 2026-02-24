from ..poseidon import poseidon2, poseidon4, Field, FIELD_SIZE
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


BABYJUB_A = 168700
BABYJUB_D = 168696

# Hard-coded PK from circuits/utils/eip7503-extension.circom
EIP7503_PKX = 15919299401931535325513703139194931338293993994510664661086800834970360591752
EIP7503_PKY = 1645780246786685895560641778865228215443840970280597910012614014295481144366

# Domain separator for r derivation
EIP7503_R_DOMAIN = 7503


def _inv(x):
    return pow(x, FIELD_SIZE - 2, FIELD_SIZE)


def _ed_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    x1y2 = (x1 * y2) % FIELD_SIZE
    y1x2 = (y1 * x2) % FIELD_SIZE
    dx1x2y1y2 = (BABYJUB_D * x1 * x2 * y1 * y2) % FIELD_SIZE

    x_num = (x1y2 + y1x2) % FIELD_SIZE
    x_den = (1 + dx1x2y1y2) % FIELD_SIZE
    x3 = (x_num * _inv(x_den)) % FIELD_SIZE

    y_num = (y1 * y2 - BABYJUB_A * x1 * x2) % FIELD_SIZE
    y_den = (1 - dx1x2y1y2) % FIELD_SIZE
    y3 = (y_num * _inv(y_den)) % FIELD_SIZE
    return x3, y3


def _ed_mul(point, scalar):
    # Edwards identity
    res = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            res = _ed_add(res, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return res


def _keystream_from_burn_key(burn_key):
    r = poseidon2(Field(EIP7503_R_DOMAIN), Field(burn_key)).val
    r_scalar = r & ((1 << 253) - 1)
    sx, sy = _ed_mul((EIP7503_PKX, EIP7503_PKY), r_scalar)
    h = poseidon2(Field(sx), Field(sy)).val
    keystream = []
    tmp = h
    for _ in range(20):
        keystream.insert(0, tmp % 256)
        tmp //= 256
    return keystream


def burn_addr_ciphertext(burn_key, reveal_amount, burn_addr_commit):
    addr_bytes = burn_addr_calc(burn_key, reveal_amount, burn_addr_commit)
    keystream = _keystream_from_burn_key(burn_key)
    return [a ^ k for a, k in zip(addr_bytes, keystream)]


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
