# crypto_utils.py
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Configurable parameters
KDF_ITERATIONS = 200_000
KEY_LEN = 32  # 256-bit AES key
SALT_LEN = 16
NONCE_LEN = 12  # recommended for GCM

def derive_key(master_key: bytes, salt: bytes) -> bytes:
    """
    Derive an AES key from a master key and salt using PBKDF2.
    master_key should be kept secret (from env).
    """
    return PBKDF2(master_key, salt, dkLen=KEY_LEN, count=KDF_ITERATIONS)

def encrypt_bytes(plaintext: bytes, master_key: bytes):
    """
    Returns (ciphertext, salt, nonce, tag)
    """
    salt = get_random_bytes(SALT_LEN)
    key = derive_key(master_key, salt)
    nonce = get_random_bytes(NONCE_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, salt, nonce, tag

def decrypt_bytes(ciphertext: bytes, master_key: bytes, salt: bytes, nonce: bytes, tag: bytes):
    key = derive_key(master_key, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
