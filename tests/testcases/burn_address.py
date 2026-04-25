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

# Admin public keys from circuits/utils/admin_keys.circom: keys[i] = (i+1)*G on BabyJubJub
# Default circuit uses first 10 (numAdmins=10)
EIP7503_PKS = [
    (5299619240641551281634865583518297030282874472190772894086521144482721001553,   # sk=1
     16950150798460657717958625567821834550301663161624707787222815936182638968203),
    (10031262171927540148667355526369034398030886437092045105752248699557385197826,  # sk=2
     633281375905621697187330766174974863687049529291089048651929454608812697683),
    (2763488322167937039616325905516046217694264098671987087929565332380420898366,   # sk=3
     15305195750036305661220525648961313310481046260814497672243197092298550508693),
    (12252886604826192316928789929706397349846234911198931249025449955069330867144,  # sk=4
     1286140751908834028607023759717162073146610688084909004843365841635476459484),
    (11480966271046430430613841218147196773252373073876138147006741179837832100836,  # sk=5
     15148236048131954717802795400425086368006776860859772698778589175317365693546),
    (10483991165196995731760716870725509190315033255344071753161464961897900552628,  # sk=6
     16822899191463256771813724222715007505997804748105685077895991386716774358231),
    (20092560661213339045022877747484245238324772779820628739268223482659246842641,  # sk=7
     12112450042127193446189577552007703839818242727902437791835414514847797088033),
    (7582035475627193640797276505418002166691739036475590846121162698650004832581,   # sk=8
     7801528930831391612913542953849263092120765287178679640990215688947513841260),
    (4705897243203718691035604313913899717760209962238015362153877735592901317263,   # sk=9
     11533909001000295577818857040682494493436124051895563619976413559559984357704),
    (153240920024090527149238595127650983736082984617707450012091413752625486998,    # sk=10
     4020276081434545615309760015178511782232038136121596626881988383789905359767),
]

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


def _keystream_from_burn_key(burn_key, pkx, pky):
    r = poseidon2(Field(EIP7503_R_DOMAIN), Field(burn_key)).val
    r_scalar = r & ((1 << 253) - 1)
    sx, sy = _ed_mul((pkx, pky), r_scalar)
    h = poseidon2(Field(sx), Field(sy)).val
    keystream = []
    tmp = h
    for _ in range(20):
        keystream.insert(0, tmp % 256)
        tmp //= 256
    return keystream


def burn_addr_ciphertext(burn_key, reveal_amount, burn_addr_commit):
    addr_bytes = burn_addr_calc(burn_key, reveal_amount, burn_addr_commit)
    result = []
    for pkx, pky in EIP7503_PKS:
        ct_bytes = [a ^ k for a, k in zip(addr_bytes, _keystream_from_burn_key(burn_key, pkx, pky))]
        packed = int.from_bytes(bytes(ct_bytes), "big")
        result.append(packed)
    return result


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
