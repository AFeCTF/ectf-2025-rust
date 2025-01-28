import hashlib
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# KEY LEVEL IS A BITMASK

def gen_key(secrets: bytes, start_timestamp: int, mask_width: int, channel: int, decoder_id: int) -> bytes:
    return hashlib.sha256(secrets + struct.pack("<QBBI", start_timestamp, mask_width, channel, decoder_id)).digest()


def encrypt_with(data: bytes, key: bytes) -> bytes:
    # Ensure the key is 256 bits (32 bytes)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-GCM.")

    # Generate a random 96-bit (12-byte) IV
    iv = os.urandom(12)

    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()

    # Return IV, ciphertext, and tag as a single concatenated result
    return iv + ciphertext + encryptor.tag
    

def decrypt_with(encrypted_data: bytes, key: bytes) -> bytes:
    # Ensure the key is 256 bits (32 bytes)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-GCM.")

    # Extract the IV, ciphertext, and tag from the input
    iv = encrypted_data[:12]  # First 12 bytes are the IV
    tag = encrypted_data[-16:]  # Last 16 bytes are the tag
    ciphertext = encrypted_data[12:-16]  # Middle part is the ciphertext

    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    return decryptor.update(ciphertext) + decryptor.finalize()


def encode(frame: bytes, secrets: bytes, channel: int, timestamp: int, decoder_id: int) -> list[bytes]:
    res = []

    for key_level in range(64):
        key = gen_key(secrets, timestamp << key_level, key_level, channel, decoder_id)
        res.append(encrypt_with(frame, key))
        timestamp >>= 1

    return res

decoder_id = 0xdeadbeef
secrets = b"super secret"
channel = 1
timestamp = 12345

encoded = encode(b"test", b"super secret", channel, timestamp, decoder_id)

level = 63
n = timestamp >> level
key = gen_key(secrets, n, level, channel, decoder_id)

decoded = decrypt_with(encoded[level], key)

print(f"decoded = {repr(decoded)}")

def characterize_range(a: int, b: int) -> list[tuple[int, int]]:
    print(f"From {bin(a)} to {bin(b)}")

    res = []

    block_level = 0

    while a <= b:
        next_block_span = (1 << block_level + 1) - 1
        if a & next_block_span == 0 and a | next_block_span <= b:
            block_level += 1
        else:
            block_span = (1 << block_level) - 1
            print(f"block level {block_level}: {bin(a)} => {bin(a | block_span)}")
            res.append((block_level, a >> block_level))
            a |= block_span
            a += 1
            block_level = 0

    return res

print(characterize_range(0, 10))
