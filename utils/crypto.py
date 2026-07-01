"""
CipherGuard — Cryptographic Utilities
AES-256-GCM encryption/decryption and key derivation for the Vault module.
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from config import VAULT_PBKDF2_ITERATIONS


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The master password string.
        salt: A 16-byte random salt.

    Returns:
        A 32-byte (256-bit) derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=VAULT_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_salt() -> bytes:
    """Generate a cryptographically secure 16-byte random salt."""
    return os.urandom(16)


def encrypt_data(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt a plaintext string using AES-256-GCM.

    The output format is: nonce (12 bytes) + ciphertext + tag (16 bytes)

    Args:
        plaintext: The string to encrypt.
        key: A 32-byte AES key.

    Returns:
        Encrypted bytes (nonce + ciphertext + tag).
    """
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext


def decrypt_data(token: bytes, key: bytes) -> str:
    """
    Decrypt AES-256-GCM encrypted data.

    Expects token format: nonce (12 bytes) + ciphertext + tag (16 bytes)

    Args:
        token: The encrypted bytes.
        key: A 32-byte AES key.

    Returns:
        Decrypted plaintext string.

    Raises:
        cryptography.exceptions.InvalidTag: If the key is wrong or data is tampered.
    """
    nonce = token[:12]
    ciphertext = token[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def hash_content(content: str) -> str:
    """
    Compute SHA-256 hash of a string.
    Used for clipboard integrity checking.

    Args:
        content: The string to hash.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
