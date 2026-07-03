"""
CipherGuard — Unit Tests for Pattern Detection Module
Tests for utils/patterns.py: crypto address detection, sensitivity classification,
and same-type comparison.
"""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.patterns import (
    detect_pattern,
    is_same_pattern_type,
    is_sensitive_content,
    get_pattern_label,
)


class TestBitcoinDetection(unittest.TestCase):
    """Tests for Bitcoin address pattern detection."""

    def test_bitcoin_legacy_valid(self):
        """Valid Bitcoin legacy address (starting with 1) should be detected."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        pattern, label = detect_pattern(address)
        self.assertEqual(pattern, "bitcoin_legacy")
        self.assertEqual(label, "Bitcoin (Legacy)")

    def test_bitcoin_legacy_3_prefix(self):
        """Valid Bitcoin legacy address (starting with 3) should be detected."""
        address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        pattern, label = detect_pattern(address)
        self.assertEqual(pattern, "bitcoin_legacy")

    def test_bitcoin_segwit_valid(self):
        """Valid Bitcoin SegWit address should be detected."""
        address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        pattern, label = detect_pattern(address)
        self.assertEqual(pattern, "bitcoin_segwit")
        self.assertEqual(label, "Bitcoin (SegWit)")


class TestEthereumDetection(unittest.TestCase):
    """Tests for Ethereum address pattern detection."""

    def test_ethereum_valid(self):
        """Valid Ethereum address should be detected."""
        address = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08"
        pattern, label = detect_pattern(address)
        self.assertEqual(pattern, "ethereum")
        self.assertEqual(label, "Ethereum")

    def test_ethereum_wrong_length(self):
        """Ethereum address with wrong length should not match."""
        address = "0x742d35Cc6634C053"  # Too short
        pattern, _ = detect_pattern(address)
        self.assertIsNone(pattern)


class TestUPIDetection(unittest.TestCase):
    """Tests for UPI ID pattern detection."""

    def test_upi_valid(self):
        """Valid UPI ID should be detected."""
        address = "user@paytm"
        pattern, label = detect_pattern(address)
        self.assertEqual(pattern, "upi")
        self.assertEqual(label, "UPI ID")

    def test_upi_with_dots(self):
        """UPI ID with dots should be detected."""
        address = "john.doe@ybl"
        pattern, _ = detect_pattern(address)
        self.assertEqual(pattern, "upi")


class TestNoMatchDetection(unittest.TestCase):
    """Tests that regular text doesn't falsely match patterns."""

    def test_random_text(self):
        """Plain English text should not match any pattern."""
        pattern, label = detect_pattern("Hello, this is a test")
        self.assertIsNone(pattern)
        self.assertEqual(label, "Unknown")

    def test_empty_string(self):
        """Empty string should not match."""
        pattern, label = detect_pattern("")
        self.assertIsNone(pattern)
        self.assertEqual(label, "Unknown")

    def test_whitespace_only(self):
        """Whitespace-only string should not match."""
        pattern, label = detect_pattern("   \n\t  ")
        self.assertIsNone(pattern)
        self.assertEqual(label, "Unknown")

    def test_short_number(self):
        """Short number should not match Bitcoin addresses."""
        pattern, _ = detect_pattern("12345")
        self.assertIsNone(pattern)


class TestSamePatternType(unittest.TestCase):
    """Tests for is_same_pattern_type comparison."""

    def test_two_btc_addresses(self):
        """Two Bitcoin legacy addresses should be same type."""
        addr1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        addr2 = "1HACKER999xyzABCDEFGHJKLMNPQRSTUVWX"
        self.assertTrue(is_same_pattern_type(addr1, addr2))

    def test_btc_and_eth(self):
        """Bitcoin and Ethereum addresses should NOT be same type."""
        btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08"
        self.assertFalse(is_same_pattern_type(btc, eth))

    def test_both_none(self):
        """Two regular texts (no pattern) should return False."""
        self.assertFalse(is_same_pattern_type("hello", "world"))

    def test_one_none(self):
        """One pattern + one regular text should return False."""
        btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        self.assertFalse(is_same_pattern_type(btc, "just text"))


class TestSensitiveContent(unittest.TestCase):
    """Tests for is_sensitive_content classification."""

    def test_btc_is_sensitive(self):
        """Bitcoin address should be classified as sensitive."""
        address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        self.assertTrue(is_sensitive_content(address))

    def test_eth_is_sensitive(self):
        """Ethereum address should be classified as sensitive."""
        address = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD08"
        self.assertTrue(is_sensitive_content(address))

    def test_regular_text_not_sensitive(self):
        """Regular English text should not be sensitive."""
        self.assertFalse(is_sensitive_content("Hello world"))

    def test_password_like_is_sensitive(self):
        """Password-like string (mixed case, digits, symbols) should be sensitive."""
        self.assertTrue(is_sensitive_content("MyStr0ng!Pass"))

    def test_long_api_key_is_sensitive(self):
        """Long alphanumeric string (32+ chars) should be sensitive as API key."""
        api_key = "a" * 32 + "B" * 8  # 40 chars, mixed but API_KEY_PATTERN wants [A-Za-z0-9_-]
        api_key = "abcdefghijklmnopqrstuvwxyz1234567890ABCD"  # 40 chars
        self.assertTrue(is_sensitive_content(api_key))


class TestGetPatternLabel(unittest.TestCase):
    """Tests for get_pattern_label helper."""

    def test_known_pattern(self):
        self.assertEqual(get_pattern_label("bitcoin_legacy"), "Bitcoin (Legacy)")
        self.assertEqual(get_pattern_label("ethereum"), "Ethereum")

    def test_none_pattern(self):
        self.assertEqual(get_pattern_label(None), "Unknown")

    def test_unknown_key(self):
        self.assertEqual(get_pattern_label("nonexistent"), "Unknown")


if __name__ == "__main__":
    unittest.main()
