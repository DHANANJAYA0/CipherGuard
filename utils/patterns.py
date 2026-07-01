"""
CipherGuard — Pattern Detection
Regex patterns for detecting cryptocurrency addresses, financial identifiers,
and sensitive content in clipboard data.
"""

import re
from typing import Optional, Tuple


# ─── Compiled Regex Patterns ──────────────────────────────────────

PATTERNS = {
    "bitcoin_legacy": re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"),
    "bitcoin_segwit": re.compile(r"^bc1[a-zA-HJ-NP-Z0-9]{25,90}$", re.IGNORECASE),
    "ethereum": re.compile(r"^0x[0-9a-fA-F]{40}$"),
    "upi": re.compile(r"^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$"),
    "iban": re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$"),
    "phone_indian": re.compile(r"^(\+91)?[6-9]\d{9}$"),
    "litecoin": re.compile(r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$"),
    "ripple": re.compile(r"^r[0-9a-zA-Z]{24,34}$"),
    "solana": re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$"),
}

# Human-readable labels for pattern types
PATTERN_LABELS = {
    "bitcoin_legacy": "Bitcoin (Legacy)",
    "bitcoin_segwit": "Bitcoin (SegWit)",
    "ethereum": "Ethereum",
    "upi": "UPI ID",
    "iban": "IBAN",
    "phone_indian": "Phone (India)",
    "litecoin": "Litecoin",
    "ripple": "Ripple (XRP)",
    "solana": "Solana",
}

# Patterns considered "sensitive" (auto-expire in vault)
SENSITIVE_PATTERNS = {"bitcoin_legacy", "bitcoin_segwit", "ethereum",
                      "litecoin", "ripple", "solana"}

# Regex for detecting potential passwords or API keys
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)
API_KEY_PATTERN = re.compile(
    r"^[A-Za-z0-9_\-]{20,64}$"
)


def detect_pattern(content: str) -> Tuple[Optional[str], str]:
    """
    Detect if clipboard content matches a known financial/crypto pattern.

    Args:
        content: The clipboard text to analyze (stripped of whitespace).

    Returns:
        A tuple of (pattern_key, human_label).
        Returns (None, "Unknown") if no pattern matches.
    """
    stripped = content.strip()
    if not stripped:
        return None, "Unknown"

    for pattern_key, regex in PATTERNS.items():
        if regex.match(stripped):
            return pattern_key, PATTERN_LABELS.get(pattern_key, "Unknown")

    return None, "Unknown"


def is_same_pattern_type(content_a: str, content_b: str) -> bool:
    """
    Check if two strings match the same financial pattern type.
    Used to detect address substitution attacks (e.g., BTC address replaced with another BTC address).

    Args:
        content_a: Original clipboard content.
        content_b: Potentially hijacked content.

    Returns:
        True if both match the same pattern type.
    """
    pattern_a, _ = detect_pattern(content_a)
    pattern_b, _ = detect_pattern(content_b)

    if pattern_a is None or pattern_b is None:
        return False

    return pattern_a == pattern_b


def is_sensitive_content(content: str) -> bool:
    """
    Determine if clipboard content should be treated as sensitive
    (for auto-expiry in the vault).

    Content is sensitive if it matches a crypto address, looks like a password,
    or looks like an API key.

    Args:
        content: The clipboard text to check.

    Returns:
        True if the content appears sensitive.
    """
    stripped = content.strip()

    # Check crypto/financial patterns
    pattern_key, _ = detect_pattern(stripped)
    if pattern_key in SENSITIVE_PATTERNS:
        return True

    # Check password-like patterns
    if PASSWORD_PATTERN.match(stripped):
        return True

    # Check API key-like patterns (long alphanumeric strings)
    if API_KEY_PATTERN.match(stripped) and len(stripped) >= 32:
        return True

    return False


def get_pattern_label(pattern_key: Optional[str]) -> str:
    """Get human-readable label for a pattern key."""
    if pattern_key is None:
        return "Unknown"
    return PATTERN_LABELS.get(pattern_key, "Unknown")
