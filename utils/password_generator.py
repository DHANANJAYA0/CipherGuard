"""
CipherGuard — Secure Password Generator
Generates cryptographically secure random passwords with configurable
character sets and guaranteed category inclusion.
"""

import secrets
import string
from typing import Optional


def generate_password(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """
    Generate a cryptographically secure random password.

    Uses the `secrets` module (CSPRNG) to ensure each password is
    suitable for security-sensitive applications.

    Args:
        length: Desired password length (minimum 4, maximum 128).
        uppercase: Include uppercase letters (A-Z).
        lowercase: Include lowercase letters (a-z).
        digits: Include numeric digits (0-9).
        symbols: Include special characters (!@#$%^&*...).
        exclude_ambiguous: Exclude visually ambiguous chars (0, O, l, 1, I).

    Returns:
        A random password string of the specified length.

    Raises:
        ValueError: If length < 4 or no character types are selected.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")
    if length > 128:
        raise ValueError("Password length must not exceed 128 characters")

    # Build character pool
    pool = ""
    required_chars = []  # Guarantee at least one from each selected category

    ambiguous = set("0OlI1|")

    if uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in ambiguous)
        pool += chars
        required_chars.append(secrets.choice(chars))

    if lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in ambiguous)
        pool += chars
        required_chars.append(secrets.choice(chars))

    if digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in ambiguous)
        pool += chars
        required_chars.append(secrets.choice(chars))

    if symbols:
        chars = "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in ambiguous)
        pool += chars
        required_chars.append(secrets.choice(chars))

    if not pool:
        raise ValueError(
            "At least one character type must be selected "
            "(uppercase, lowercase, digits, or symbols)"
        )

    # Fill remaining length with random choices from the full pool
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [
        secrets.choice(pool) for _ in range(remaining_length)
    ]

    # Shuffle to avoid predictable positions of required chars
    # Use Fisher-Yates shuffle with secrets for cryptographic security
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


def generate_passphrase(
    word_count: int = 4,
    separator: str = "-",
    capitalize: bool = True,
) -> str:
    """
    Generate a passphrase from random words.

    Uses a curated word list for memorable but secure passphrases.

    Args:
        word_count: Number of words (minimum 3).
        separator: Character between words.
        capitalize: Capitalize the first letter of each word.

    Returns:
        A passphrase string.

    Raises:
        ValueError: If word_count < 3.
    """
    if word_count < 3:
        raise ValueError("Passphrase must have at least 3 words")

    # Curated word list (common, memorable, 4-8 letter words)
    words = [
        "amber", "arrow", "blade", "bloom", "brave", "cedar", "chain",
        "charm", "chess", "cliff", "cloud", "cobra", "coral", "crane",
        "crown", "dance", "delta", "dream", "drift", "eagle", "ember",
        "fable", "flame", "flash", "forge", "frost", "ghost", "glade",
        "gleam", "globe", "grace", "grain", "grape", "haven", "heart",
        "ivory", "jewel", "karma", "knife", "lemon", "light", "lunar",
        "maple", "marsh", "medal", "mirth", "noble", "ocean", "orbit",
        "pearl", "petal", "pixel", "plume", "prism", "pulse", "quartz",
        "quest", "raven", "realm", "ridge", "river", "robin", "royal",
        "sage", "satin", "scale", "shade", "shark", "shine", "shore",
        "siege", "silk", "slate", "solar", "spark", "spire", "steam",
        "steel", "stone", "storm", "surge", "swift", "thorn", "tiger",
        "torch", "trail", "tulip", "vapor", "vault", "vigor", "vivid",
        "wheat", "winds", "woven", "yacht", "zebra", "zen", "blaze",
    ]

    selected = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        selected = [w.capitalize() for w in selected]

    return separator.join(selected)
