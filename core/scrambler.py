"""
CipherGuard — Keyboard Scrambling Algorithms
Multiple scrambling strategies to defeat keyloggers.
"""

import random
import string
from typing import Dict

from config import SCRAMBLE_CHARS


def generate_random_map(seed: str) -> Dict[str, str]:
    """
    Generate a deterministic random 1-to-1 character substitution map.
    Each session uses a unique seed, producing a unique map.

    Args:
        seed: A string seed (e.g., session ID or master password hash).

    Returns:
        A dict mapping each character to its scrambled replacement.
    """
    chars = list(SCRAMBLE_CHARS)
    shuffled = chars.copy()
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    return dict(zip(chars, shuffled))


def generate_reverse_map(forward_map: Dict[str, str]) -> Dict[str, str]:
    """
    Generate the reverse map for unscrambling.

    Args:
        forward_map: The forward substitution map.

    Returns:
        A dict mapping scrambled characters back to originals.
    """
    return {v: k for k, v in forward_map.items()}


def generate_caesar_map(shift: int = 13) -> Dict[str, str]:
    """
    Generate a Caesar cipher substitution map.

    Args:
        shift: Number of positions to shift (default: 13 for ROT13-like).

    Returns:
        A dict mapping each character to its shifted replacement.
    """
    chars = list(SCRAMBLE_CHARS)
    n = len(chars)
    return {chars[i]: chars[(i + shift) % n] for i in range(n)}


def generate_phonetic_map() -> Dict[str, str]:
    """
    Generate a phonetic/leet-speak substitution map.
    Maps characters to visually similar alternatives.

    Returns:
        A dict with phonetic substitutions.
    """
    phonetic = {
        'a': '@', 'b': '8', 'c': '(', 'd': '|)', 'e': '3',
        'f': '|=', 'g': '9', 'h': '#', 'i': '!', 'j': ']',
        'k': '|<', 'l': '1', 'm': '|v|', 'n': '^', 'o': '0',
        'p': '|>', 'q': '&', 'r': '2', 's': '$', 't': '+',
        'u': 'v', 'v': '\\/', 'w': 'vv', 'x': '><', 'y': '`/',
        'z': '2',
        'A': '4', 'B': '|3', 'C': '<', 'D': '|)', 'E': '3',
        'F': '|=', 'G': '6', 'H': '|-|', 'I': '|', 'J': '_|',
        'K': '|<', 'L': '|_', 'M': '|V|', 'N': '/V', 'O': '()',
        'P': '|*', 'Q': '(,)', 'R': '|2', 'S': '5', 'T': '7',
        'U': '|_|', 'V': '\\/', 'W': 'VV', 'X': '}{', 'Y': '`/',
        'Z': '7_',
        '0': 'O', '1': 'l', '2': 'Z', '3': 'E', '4': 'A',
        '5': 'S', '6': 'b', '7': 'T', '8': 'B', '9': 'g',
    }
    return phonetic


def scramble_char(char: str, scramble_map: Dict[str, str]) -> str:
    """
    Scramble a single character using the provided map.

    Args:
        char: The original character.
        scramble_map: The substitution map to use.

    Returns:
        The scrambled character, or the original if not in the map.
    """
    return scramble_map.get(char, char)


def get_algorithm_map(algorithm: str, seed: str = "default") -> Dict[str, str]:
    """
    Get the scrambling map for a given algorithm name.

    Args:
        algorithm: One of 'random_map', 'caesar', 'phonetic'.
        seed: Seed string for random_map algorithm.

    Returns:
        The character substitution map.
    """
    if algorithm == "random_map":
        return generate_random_map(seed)
    elif algorithm == "caesar":
        return generate_caesar_map(shift=13)
    elif algorithm == "phonetic":
        return generate_phonetic_map()
    else:
        return generate_random_map(seed)
