"""
CipherGuard — Unit Tests for Password Strength Module
Tests for utils/password_strength.py: scoring, labels, crack time, suggestions.
"""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.password_strength import calculate_strength, StrengthResult


class TestEmptyPassword(unittest.TestCase):
    """Tests for empty/missing password input."""

    def test_empty_string(self):
        result = calculate_strength("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.label, "Very Weak")
        self.assertEqual(result.crack_time, "instant")

    def test_returns_strength_result(self):
        result = calculate_strength("anything")
        self.assertIsInstance(result, StrengthResult)


class TestWeakPasswords(unittest.TestCase):
    """Tests for known weak passwords."""

    def test_common_password_123456(self):
        """'123456' is in the common passwords list and should score very low."""
        result = calculate_strength("123456")
        self.assertLess(result.score, 20)
        self.assertIn(result.label, ("Very Weak", "Weak"))

    def test_common_password_password(self):
        """'password' should be detected and penalized."""
        result = calculate_strength("password")
        self.assertLess(result.score, 25)

    def test_single_char(self):
        result = calculate_strength("a")
        self.assertLess(result.score, 15)
        self.assertEqual(result.label, "Very Weak")

    def test_short_repeating(self):
        """Repeating characters should be penalized."""
        result = calculate_strength("aaaaaa")
        self.assertLess(result.score, 20)

    def test_sequential_pattern(self):
        """Sequential patterns like 'abcdef' should be penalized."""
        result = calculate_strength("abcdefgh")
        self.assertLess(result.score, 30)


class TestStrongPasswords(unittest.TestCase):
    """Tests for strong passwords."""

    def test_complex_password(self):
        """Mixed case, digits, symbols, 16+ chars should score high."""
        result = calculate_strength("MyStr0ng!P@ss#2024xY")
        self.assertGreater(result.score, 70)
        self.assertIn(result.label, ("Strong", "Very Strong"))

    def test_very_long_password(self):
        """20+ character password with diversity should be Very Strong."""
        result = calculate_strength("Th1s-Is_A.Very!Long@Pass#2024")
        self.assertGreater(result.score, 75)

    def test_passphrase_style(self):
        """Long passphrase with mixed characters should score well."""
        result = calculate_strength("Correct-Horse-Battery-Staple!")
        self.assertGreater(result.score, 60)


class TestStrengthLabels(unittest.TestCase):
    """Tests that labels map correctly to score ranges."""

    def test_very_weak_label(self):
        """Score 0-19 should be 'Very Weak'."""
        result = calculate_strength("ab")
        self.assertLess(result.score, 20)
        self.assertEqual(result.label, "Very Weak")

    def test_strong_color(self):
        """Strong passwords should have green-ish color."""
        result = calculate_strength("MyStr0ng!P@ss#2024xY")
        self.assertIn(result.color, ("#00ff88", "#44cc44"))


class TestCrackTime(unittest.TestCase):
    """Tests for crack time estimation."""

    def test_instant_for_empty(self):
        result = calculate_strength("")
        self.assertEqual(result.crack_time, "instant")

    def test_instant_for_short(self):
        result = calculate_strength("ab")
        self.assertEqual(result.crack_time, "instant")

    def test_not_instant_for_strong(self):
        result = calculate_strength("MyStr0ng!P@ss#2024xY")
        self.assertNotEqual(result.crack_time, "instant")


class TestSuggestions(unittest.TestCase):
    """Tests for improvement suggestions."""

    def test_short_password_suggests_length(self):
        result = calculate_strength("abc")
        # Should suggest using at least 8 characters
        has_length_suggestion = any("8" in s for s in result.suggestions)
        self.assertTrue(has_length_suggestion)

    def test_no_uppercase_suggestion(self):
        result = calculate_strength("lowercase123!")
        has_upper_suggestion = any("uppercase" in s.lower() for s in result.suggestions)
        self.assertTrue(has_upper_suggestion)

    def test_no_symbol_suggestion(self):
        result = calculate_strength("NoSymbols123")
        has_symbol_suggestion = any("symbol" in s.lower() for s in result.suggestions)
        self.assertTrue(has_symbol_suggestion)

    def test_common_password_warning(self):
        result = calculate_strength("password")
        has_common_warning = any("commonly" in s.lower() for s in result.suggestions)
        self.assertTrue(has_common_warning)


class TestEntropyBits(unittest.TestCase):
    """Tests for entropy calculation."""

    def test_entropy_positive(self):
        result = calculate_strength("test_password")
        self.assertGreater(result.entropy_bits, 0)

    def test_entropy_zero_for_empty(self):
        result = calculate_strength("")
        self.assertEqual(result.entropy_bits, 0)

    def test_higher_entropy_for_diverse(self):
        """More diverse passwords should have higher entropy."""
        simple = calculate_strength("aaaaaaa")
        diverse = calculate_strength("aB3!xY9")
        self.assertGreater(diverse.entropy_bits, simple.entropy_bits)


if __name__ == "__main__":
    unittest.main()
