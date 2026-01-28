# # --- Toy KDF (simulates Poseidon) ---
# def toy_kdf(shared):
#     """Derive 20-byte keystream from shared secret (toy example)."""
#     return bytes((shared * 13 + i * 7) % 256 for i in range(20))

# # --- Toy scalar multiplication: sk * R ---
# def scalar_mul(sk, R):
#     """Simulate scalar multiplication on a toy curve."""
#     return (sk * R) % 97  # modulo small prime for demo

# # --- XOR helper ---
# def xor_bytes(a, b):
#     """XOR two byte arrays."""
#     return bytes(x ^ y for x, y in zip(a, b))

# def main():
#     # Hard-coded "private key"
#     sk = 17

#     # Hard-coded ephemeral public key
#     R = 23

#     # Hard-coded ciphertext (encrypted addressBytes)
#     ciphertext = bytes([
#         0x5a, 0x6b, 0x7c, 0x8d, 0x9e,
#         0xaf, 0xb0, 0xc1, 0xd2, 0xe3,
#         0xf4, 0x05, 0x16, 0x27, 0x38,
#         0x49, 0x5a, 0x6b, 0x7c, 0x8d,
#     ])

#     # 1️⃣ Compute shared secret using sk
#     shared = scalar_mul(sk, R)

#     # 2️⃣ Derive keystream using toy KDF
#     keystream = toy_kdf(shared)

#     # 3️⃣ Decrypt ciphertext
#     address_bytes = xor_bytes(ciphertext, keystream)

#     print("Recovered addressBytes:", address_bytes.hex())

# if __name__ == "__main__":
#     main()

from hashlib import sha256
from circomlib import poseidon

def poseidon_keystream(PKx, PKy, Rx, Ry, length=20):
    val = poseidon([PKx, PKy, Rx, Ry])
    # convert field element to bytes
    val_bytes = val.to_bytes(32, 'big')
    return list(val_bytes[:length])


# def poseidon_keystream(PKx, PKy, Rx, Ry, length=20):
#     # deterministic keystream for demo
#     data = f"{PKx},{PKy},{Rx},{Ry}".encode()
#     hash_bytes = sha256(data).digest()
#     while len(hash_bytes) < length:
#         hash_bytes += sha256(hash_bytes).digest()
#     return list(hash_bytes[:length])

def decrypt(ciphertext, PKx, PKy, Rx, Ry):
    keystream = poseidon_keystream(PKx, PKy, Rx, Ry, length=len(ciphertext))
    plaintext = [c ^ k for c, k in zip(ciphertext, keystream)]
    return plaintext

if __name__ == "__main__":
    ciphertext = [90,107,124,141,158,175,176,193,210,227,244,5,22,39,56,73,90,107,124,141]
    PKx = 123456789
    PKy = 987654321
    Rx  = 111111111
    Ry  = 222222222

    decrypted = decrypt(ciphertext, PKx, PKy, Rx, Ry)
    print("Decrypted burn address:", decrypted)
