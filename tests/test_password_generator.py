"""
CipherGuard — Unit Tests for Password Generator Module
Tests for utils/password_generator.py: generation, character categories,
edge cases, and passphrase generation.
"""

import sys
import os
import unittest
import string

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.password_generator import generate_password, generate_passphrase


class TestPasswordLength(unittest.TestCase):
    """Tests for generated password length."""

    def test_default_length(self):
        """Default length should be 16."""
        password = generate_password()
        self.assertEqual(len(password), 16)

    def test_custom_length_8(self):
        password = generate_password(length=8)
        self.assertEqual(len(password), 8)

    def test_custom_length_32(self):
        password = generate_password(length=32)
        self.assertEqual(len(password), 32)

    def test_custom_length_128(self):
        password = generate_password(length=128)
        self.assertEqual(len(password), 128)

    def test_minimum_length_4(self):
        password = generate_password(length=4)
        self.assertEqual(len(password), 4)


class TestCharacterCategories(unittest.TestCase):
    """Tests for required character category inclusion."""

    def test_contains_uppercase(self):
        """When uppercase=True, password should contain at least one uppercase letter."""
        password = generate_password(length=16, uppercase=True, lowercase=True,
                                     digits=True, symbols=True)
        has_upper = any(c in string.ascii_uppercase for c in password)
        self.assertTrue(has_upper, f"No uppercase found in: {password}")

    def test_contains_lowercase(self):
        """When lowercase=True, password should contain at least one lowercase letter."""
        password = generate_password(length=16, uppercase=True, lowercase=True,
                                     digits=True, symbols=True)
        has_lower = any(c in string.ascii_lowercase for c in password)
        self.assertTrue(has_lower, f"No lowercase found in: {password}")

    def test_contains_digits(self):
        """When digits=True, password should contain at least one digit."""
        password = generate_password(length=16, uppercase=True, lowercase=True,
                                     digits=True, symbols=True)
        has_digit = any(c in string.digits for c in password)
        self.assertTrue(has_digit, f"No digit found in: {password}")

    def test_contains_symbols(self):
        """When symbols=True, password should contain at least one symbol."""
        password = generate_password(length=16, uppercase=True, lowercase=True,
                                     digits=True, symbols=True)
        symbol_chars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
        has_symbol = any(c in symbol_chars for c in password)
        self.assertTrue(has_symbol, f"No symbol found in: {password}")

    def test_uppercase_only(self):
        """Uppercase-only password should have no lowercase, digits, or symbols."""
        password = generate_password(length=8, uppercase=True, lowercase=False,
                                     digits=False, symbols=False)
        for ch in password:
            self.assertIn(ch, string.ascii_uppercase,
                          f"Non-uppercase char '{ch}' in uppercase-only password")

    def test_digits_only(self):
        """Digits-only password should contain only digits."""
        password = generate_password(length=8, uppercase=False, lowercase=False,
                                     digits=True, symbols=False)
        for ch in password:
            self.assertIn(ch, string.digits,
                          f"Non-digit char '{ch}' in digits-only password")


class TestEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_all_disabled_raises_error(self):
        """All character types disabled should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(uppercase=False, lowercase=False,
                              digits=False, symbols=False)

    def test_length_too_short_raises_error(self):
        """Length < 4 should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(length=3)

    def test_length_too_long_raises_error(self):
        """Length > 128 should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(length=129)

    def test_exclude_ambiguous(self):
        """Exclude ambiguous chars should not contain 0, O, l, 1, I."""
        ambiguous = set("0OlI1|")
        # Generate several passwords to reduce flakiness
        for _ in range(10):
            password = generate_password(length=32, exclude_ambiguous=True)
            for ch in password:
                self.assertNotIn(ch, ambiguous,
                                 f"Ambiguous char '{ch}' found in: {password}")


class TestCryptographicRandomness(unittest.TestCase):
    """Tests for randomness properties."""

    def test_two_passwords_differ(self):
        """Two generated passwords should be different (extremely high probability)."""
        pw1 = generate_password(length=32)
        pw2 = generate_password(length=32)
        self.assertNotEqual(pw1, pw2)

    def test_passwords_vary_with_settings(self):
        """Passwords with different settings should look different."""
        pw_all = generate_password(length=16, uppercase=True, lowercase=True,
                                   digits=True, symbols=True)
        pw_alpha = generate_password(length=16, uppercase=True, lowercase=True,
                                     digits=False, symbols=False)
        # They should use different character pools
        self.assertNotEqual(set(pw_all), set(pw_alpha))


class TestPassphraseGeneration(unittest.TestCase):
    """Tests for passphrase generation."""

    def test_default_passphrase(self):
        """Default passphrase should have 4 words."""
        passphrase = generate_passphrase()
        words = passphrase.split("-")
        self.assertEqual(len(words), 4)

    def test_custom_word_count(self):
        passphrase = generate_passphrase(word_count=6)
        words = passphrase.split("-")
        self.assertEqual(len(words), 6)

    def test_custom_separator(self):
        passphrase = generate_passphrase(separator="_")
        self.assertIn("_", passphrase)
        self.assertNotIn("-", passphrase)

    def test_capitalization(self):
        """With capitalize=True, each word should start with uppercase."""
        passphrase = generate_passphrase(capitalize=True)
        words = passphrase.split("-")
        for word in words:
            self.assertTrue(word[0].isupper(), f"Word '{word}' not capitalized")

    def test_no_capitalization(self):
        """With capitalize=False, words should be lowercase."""
        passphrase = generate_passphrase(capitalize=False)
        words = passphrase.split("-")
        for word in words:
            self.assertTrue(word.islower(), f"Word '{word}' should be lowercase")

    def test_min_word_count_error(self):
        """word_count < 3 should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_passphrase(word_count=2)

    def test_two_passphrases_differ(self):
        """Two generated passphrases should be different."""
        pp1 = generate_passphrase()
        pp2 = generate_passphrase()
        self.assertNotEqual(pp1, pp2)


if __name__ == "__main__":
    unittest.main()
