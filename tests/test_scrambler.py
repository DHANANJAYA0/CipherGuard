"""
CipherGuard — Unit Tests for Scrambler Module
Tests for core/scrambler.py: algorithm generation, character scrambling, and roundtrip validation.
"""

import sys
import os
import unittest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.scrambler import (
    generate_random_map,
    generate_reverse_map,
    generate_caesar_map,
    generate_phonetic_map,
    scramble_char,
    get_algorithm_map,
)
from config import SCRAMBLE_CHARS


class TestRandomMap(unittest.TestCase):
    """Tests for the random_map scrambling algorithm."""

    def test_deterministic_same_seed(self):
        """Same seed should always produce the same map."""
        map1 = generate_random_map("test_seed_123")
        map2 = generate_random_map("test_seed_123")
        self.assertEqual(map1, map2)

    def test_different_seeds_differ(self):
        """Different seeds should produce different maps."""
        map1 = generate_random_map("seed_alpha")
        map2 = generate_random_map("seed_beta")
        self.assertNotEqual(map1, map2)

    def test_bijective_mapping(self):
        """Each character should map to a unique output (no collisions)."""
        char_map = generate_random_map("bijective_test")
        values = list(char_map.values())
        self.assertEqual(len(values), len(set(values)),
                         "Map is not bijective — duplicate output values found")

    def test_covers_all_scramble_chars(self):
        """The map should contain an entry for every SCRAMBLE_CHARS character."""
        char_map = generate_random_map("coverage_test")
        for ch in SCRAMBLE_CHARS:
            self.assertIn(ch, char_map, f"Character '{ch}' missing from map")

    def test_reverse_map_roundtrip(self):
        """Scramble then unscramble should return the original character."""
        forward = generate_random_map("roundtrip_test")
        reverse = generate_reverse_map(forward)
        for ch in SCRAMBLE_CHARS:
            scrambled = forward[ch]
            unscrambled = reverse[scrambled]
            self.assertEqual(ch, unscrambled,
                             f"Roundtrip failed: '{ch}' → '{scrambled}' → '{unscrambled}'")


class TestCaesarMap(unittest.TestCase):
    """Tests for the Caesar shift scrambling algorithm."""

    def test_caesar_shift_produces_dict(self):
        """Caesar map should return a dictionary."""
        char_map = generate_caesar_map(shift=13)
        self.assertIsInstance(char_map, dict)

    def test_caesar_shift_correct(self):
        """A character shifted by N positions should land at the correct index."""
        char_map = generate_caesar_map(shift=1)
        chars = list(SCRAMBLE_CHARS)
        # 'a' at index 0 should map to 'b' at index 1
        self.assertEqual(char_map[chars[0]], chars[1])

    def test_caesar_wraps_around(self):
        """Last character should wrap around to the first."""
        char_map = generate_caesar_map(shift=1)
        chars = list(SCRAMBLE_CHARS)
        self.assertEqual(char_map[chars[-1]], chars[0])

    def test_caesar_identity_at_zero(self):
        """Shift of 0 should map each character to itself."""
        char_map = generate_caesar_map(shift=0)
        for ch in SCRAMBLE_CHARS:
            self.assertEqual(char_map[ch], ch)


class TestPhoneticMap(unittest.TestCase):
    """Tests for the phonetic/leet-speak scrambling algorithm."""

    def test_phonetic_returns_dict(self):
        """Phonetic map should return a dictionary."""
        char_map = generate_phonetic_map()
        self.assertIsInstance(char_map, dict)

    def test_phonetic_known_mappings(self):
        """Known phonetic mappings should be correct."""
        char_map = generate_phonetic_map()
        self.assertEqual(char_map.get('a'), '@')
        self.assertEqual(char_map.get('e'), '3')
        self.assertEqual(char_map.get('s'), '$')
        self.assertEqual(char_map.get('A'), '4')


class TestScrambleChar(unittest.TestCase):
    """Tests for the scramble_char function."""

    def test_known_mapping(self):
        """A character in the map should return its mapped value."""
        test_map = {'a': 'z', 'b': 'y'}
        self.assertEqual(scramble_char('a', test_map), 'z')

    def test_unknown_char_passthrough(self):
        """A character NOT in the map should pass through unchanged."""
        test_map = {'a': 'z'}
        self.assertEqual(scramble_char('★', test_map), '★')

    def test_empty_map(self):
        """Empty map should pass all characters through."""
        self.assertEqual(scramble_char('x', {}), 'x')


class TestGetAlgorithmMap(unittest.TestCase):
    """Tests for the get_algorithm_map factory function."""

    def test_random_map_returns_dict(self):
        result = get_algorithm_map("random_map", seed="test")
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)

    def test_caesar_returns_dict(self):
        result = get_algorithm_map("caesar")
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)

    def test_phonetic_returns_dict(self):
        result = get_algorithm_map("phonetic")
        self.assertIsInstance(result, dict)
        self.assertGreater(len(result), 0)

    def test_unknown_algorithm_fallback(self):
        """Unknown algorithm should fallback to random_map."""
        result = get_algorithm_map("nonexistent", seed="fallback")
        expected = get_algorithm_map("random_map", seed="fallback")
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
