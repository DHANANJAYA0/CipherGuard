"""
CipherGuard — Unit Tests for Crypto Module
Tests for utils/crypto.py: AES-256-GCM encryption/decryption, key derivation, and hashing.
"""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.crypto import (
    derive_key,
    generate_salt,
    encrypt_data,
    decrypt_data,
    hash_content,
)


class TestKeyDerivation(unittest.TestCase):
    """Tests for PBKDF2 key derivation."""

    def test_deterministic_derivation(self):
        """Same password + salt should always produce the same key."""
        salt = b'\x00' * 16  # Fixed salt for testing
        key1 = derive_key("MyPassword123", salt)
        key2 = derive_key("MyPassword123", salt)
        self.assertEqual(key1, key2)

    def test_different_passwords_differ(self):
        """Different passwords should produce different keys."""
        salt = generate_salt()
        key1 = derive_key("password_alpha", salt)
        key2 = derive_key("password_beta", salt)
        self.assertNotEqual(key1, key2)

    def test_different_salts_differ(self):
        """Same password with different salts should produce different keys."""
        key1 = derive_key("same_password", b'\x01' * 16)
        key2 = derive_key("same_password", b'\x02' * 16)
        self.assertNotEqual(key1, key2)

    def test_key_length_256_bits(self):
        """Derived key should be 32 bytes (256 bits)."""
        salt = generate_salt()
        key = derive_key("test_password", salt)
        self.assertEqual(len(key), 32)


class TestSaltGeneration(unittest.TestCase):
    """Tests for cryptographic salt generation."""

    def test_salt_length(self):
        """Salt should be 16 bytes."""
        salt = generate_salt()
        self.assertEqual(len(salt), 16)

    def test_salt_uniqueness(self):
        """Two generated salts should be different."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        self.assertNotEqual(salt1, salt2)

    def test_salt_is_bytes(self):
        """Salt should be a bytes object."""
        salt = generate_salt()
        self.assertIsInstance(salt, bytes)


class TestEncryptDecrypt(unittest.TestCase):
    """Tests for AES-256-GCM encryption and decryption."""

    def setUp(self):
        self.salt = generate_salt()
        self.key = derive_key("test_master_password", self.salt)

    def test_roundtrip(self):
        """Encrypt then decrypt should return the original plaintext."""
        plaintext = "Hello, CipherGuard! 🛡️"
        encrypted = encrypt_data(plaintext, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(plaintext, decrypted)

    def test_roundtrip_empty_string(self):
        """Empty string should encrypt and decrypt correctly."""
        plaintext = ""
        encrypted = encrypt_data(plaintext, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(plaintext, decrypted)

    def test_roundtrip_long_text(self):
        """Long text should encrypt and decrypt correctly."""
        plaintext = "A" * 10000
        encrypted = encrypt_data(plaintext, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(plaintext, decrypted)

    def test_roundtrip_special_chars(self):
        """Special characters and unicode should survive encryption."""
        plaintext = "p@$$w0rd!@#$%^&*() 日本語 中文 한국어 🔐"
        encrypted = encrypt_data(plaintext, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        self.assertEqual(plaintext, decrypted)

    def test_wrong_key_fails(self):
        """Decrypting with wrong key should raise an exception."""
        plaintext = "sensitive data"
        encrypted = encrypt_data(plaintext, self.key)

        wrong_key = derive_key("wrong_password", self.salt)
        with self.assertRaises(Exception):
            decrypt_data(encrypted, wrong_key)

    def test_different_nonces(self):
        """Two encryptions of the same plaintext should produce different ciphertext."""
        plaintext = "same text twice"
        encrypted1 = encrypt_data(plaintext, self.key)
        encrypted2 = encrypt_data(plaintext, self.key)
        self.assertNotEqual(encrypted1, encrypted2)

    def test_encrypted_data_is_bytes(self):
        """Encrypted output should be a bytes object."""
        encrypted = encrypt_data("test", self.key)
        self.assertIsInstance(encrypted, bytes)

    def test_encrypted_data_longer_than_plaintext(self):
        """Encrypted data should be longer (nonce + ciphertext + tag)."""
        plaintext = "short"
        encrypted = encrypt_data(plaintext, self.key)
        # At minimum: 12 bytes nonce + plaintext length + 16 bytes tag
        self.assertGreater(len(encrypted), len(plaintext.encode()) + 12 + 16 - 1)


class TestHashContent(unittest.TestCase):
    """Tests for SHA-256 content hashing."""

    def test_consistent_hash(self):
        """Same input should always produce the same hash."""
        hash1 = hash_content("clipboard data")
        hash2 = hash_content("clipboard data")
        self.assertEqual(hash1, hash2)

    def test_different_inputs_differ(self):
        """Different inputs should produce different hashes."""
        hash1 = hash_content("content A")
        hash2 = hash_content("content B")
        self.assertNotEqual(hash1, hash2)

    def test_hash_is_hex_string(self):
        """Hash output should be a hex string."""
        result = hash_content("test")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # SHA-256 = 64 hex chars
        # Should only contain hex characters
        int(result, 16)  # Will raise if not valid hex

    def test_known_hash(self):
        """Known SHA-256 hash for 'hello' should match."""
        import hashlib
        expected = hashlib.sha256(b"hello").hexdigest()
        result = hash_content("hello")
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
