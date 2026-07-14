"""
AES-CBC encryption matching the C# AesOperation class.
Uses raw UTF-8 key bytes for both Key and IV (IV truncated to 16 bytes).
"""
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def fix_secret_key(secret_key: str) -> str:
    """FixSecretKey: if the key contains 'q', replace the first 'q' with 'm8'."""
    if 'q' not in secret_key:  # if no 'q' found, return unchanged
        return secret_key
    # split on first 'q' and insert 'm8' in its place
    arr = secret_key.split('q', 1)  # split only on first occurrence
    return f"{arr[0]}m8{arr[1]}"


def encrypt_string(secret_key: str, plain_text: str) -> str:
    """
    Encrypt plaintext using AES-CBC with PKCS7 padding.
    Key derivation matches C# AesOperation:
      - FixSecretKey applied first
      - Raw UTF-8 bytes used for both AES Key and IV
      - IV truncated to first 16 bytes (AES BlockSize = 128)
    Returns base64-encoded ciphertext.
    """
    # Step 1: fix the key (C# FixSecretKey logic)
    fixed_key = fix_secret_key(secret_key)

    # Step 2: get raw UTF-8 bytes of the fixed key
    key_bytes = fixed_key.encode("utf-8")  # raw bytes, same as C# Encoding.UTF8.GetBytes()

    # Step 3: IV must be exactly 16 bytes for AES (C# would throw otherwise)
    if len(key_bytes) < 16:
        raise ValueError("Encryption key must be at least 16 characters long.")

    # Step 4: use same bytes for both Key and IV (IV truncated to first 16)
    aes_key = key_bytes
    aes_iv = key_bytes[:16]  # first 16 bytes for IV

    # Step 5: set up AES-CBC with PKCS7 padding
    padder = padding.PKCS7(128).padder()  # 128-bit block size
    padded_data = padder.update(plain_text.encode("utf-8")) + padder.finalize()

    # Step 6: encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Step 7: return base64 (same as C# Convert.ToBase64String)
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_string(secret_key: str, cipher_text: str) -> str:
    """
    Decrypt base64-encoded ciphertext using AES-CBC with PKCS7 padding.
    Key derivation matches C# AesOperation.
    """
    # Step 1: fix the key (C# FixSecretKey logic)
    fixed_key = fix_secret_key(secret_key)

    # Step 2: get raw UTF-8 bytes of the fixed key
    key_bytes = fixed_key.encode("utf-8")

    # Step 3: IV must be exactly 16 bytes for AES
    if len(key_bytes) < 16:
        raise ValueError("Encryption key must be at least 16 characters long.")

    # Step 4: use same bytes for both Key and IV (IV truncated to first 16)
    aes_key = key_bytes
    aes_iv = key_bytes[:16]

    # Step 5: decode base64 ciphertext
    ciphertext = base64.b64decode(cipher_text)

    # Step 6: decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Step 7: remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    return plaintext.decode("utf-8")