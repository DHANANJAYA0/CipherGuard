"""
CipherGuard — Password Strength Analyzer
Calculates password strength based on entropy, length, character diversity,
and common password checks. Returns a score, label, color, crack time estimate,
and improvement suggestions.
"""

import math
import re
from dataclasses import dataclass, field
from typing import List


# Common weak passwords (top subset for quick check)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "letmein", "football", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "ashley", "jessica", "charlie", "password1",
    "000000", "1234567", "123456789", "1234567890", "admin", "welcome",
    "login", "passw0rd", "p@ssword", "p@ssw0rd",
}

# Sequential patterns to penalize
SEQUENTIAL_PATTERNS = [
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "01234567890",
    "09876543210",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


@dataclass
class StrengthResult:
    """Result of a password strength analysis."""
    score: int = 0                  # 0-100
    label: str = "Very Weak"        # Human-readable label
    color: str = "#ff4444"          # Hex color for UI
    crack_time: str = "instant"     # Human-readable crack time
    entropy_bits: float = 0.0       # Shannon entropy in bits
    suggestions: List[str] = field(default_factory=list)


def _calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password in bits."""
    if not password:
        return 0.0

    # Count character frequencies
    freq = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(password)
    entropy = 0.0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)

    return entropy * length


def _estimate_charset_size(password: str) -> int:
    """Estimate the size of the character pool used."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:',.<>?/`~\"\\]", password):
        pool += 32
    return max(pool, 1)


def _estimate_crack_time(password: str) -> str:
    """
    Estimate brute-force crack time assuming 10 billion guesses/second
    (modern GPU cluster).
    """
    charset_size = _estimate_charset_size(password)
    length = len(password)

    if length == 0:
        return "instant"

    # Total combinations = charset_size ^ length
    combinations = charset_size ** length

    # 10 billion guesses per second (high-end GPU attack)
    guesses_per_second = 10_000_000_000
    seconds = combinations / guesses_per_second

    if seconds < 1:
        return "instant"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 86400 * 365:
        return f"{int(seconds / 86400)} days"
    elif seconds < 86400 * 365 * 1000:
        return f"{int(seconds / (86400 * 365))} years"
    elif seconds < 86400 * 365 * 1_000_000:
        return f"{int(seconds / (86400 * 365 * 1000))}K years"
    elif seconds < 86400 * 365 * 1_000_000_000:
        return f"{int(seconds / (86400 * 365 * 1_000_000))}M years"
    else:
        return "centuries"


def _has_sequential(password: str, min_len: int = 3) -> bool:
    """Check if password contains sequential patterns."""
    lower = password.lower()
    for pattern in SEQUENTIAL_PATTERNS:
        for i in range(len(pattern) - min_len + 1):
            if pattern[i:i + min_len] in lower:
                return True
    return False


def _has_repeating(password: str, min_len: int = 3) -> bool:
    """Check if password contains repeating characters (e.g., 'aaa', '111')."""
    for i in range(len(password) - min_len + 1):
        if len(set(password[i:i + min_len])) == 1:
            return True
    return False


def calculate_strength(password: str) -> StrengthResult:
    """
    Analyze password strength and return a detailed result.

    Scoring breakdown (0-100):
      - Length contribution:     up to 30 points
      - Character diversity:    up to 25 points
      - Entropy:                up to 25 points
      - Penalties:              up to -30 points
      - Bonuses:                up to 20 points

    Args:
        password: The password string to analyze.

    Returns:
        StrengthResult with score, label, color, crack time, and suggestions.
    """
    result = StrengthResult()

    if not password:
        result.suggestions = ["Enter a password to check its strength"]
        return result

    score = 0
    suggestions = []
    length = len(password)

    # ─── Length Score (up to 30 pts) ────────────────────────
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 10:
        score += 16
    elif length >= 8:
        score += 10
    elif length >= 6:
        score += 5
    else:
        score += 2

    if length < 8:
        suggestions.append("Use at least 8 characters")
    elif length < 12:
        suggestions.append("Consider using 12+ characters for better security")

    # ─── Character Diversity (up to 25 pts) ────────────────
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    diversity_count = sum([has_lower, has_upper, has_digit, has_symbol])
    diversity_score = {0: 0, 1: 5, 2: 12, 3: 18, 4: 25}
    score += diversity_score.get(diversity_count, 0)

    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z)")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z)")
    if not has_digit:
        suggestions.append("Add numbers (0-9)")
    if not has_symbol:
        suggestions.append("Add symbols (!@#$%^&*)")

    # ─── Entropy Score (up to 25 pts) ──────────────────────
    entropy = _calculate_entropy(password)
    result.entropy_bits = round(entropy, 1)

    if entropy >= 60:
        score += 25
    elif entropy >= 45:
        score += 18
    elif entropy >= 30:
        score += 12
    elif entropy >= 15:
        score += 6
    else:
        score += 2

    # ─── Penalties ─────────────────────────────────────────
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        score -= 30
        suggestions.insert(0, "⚠️ This is a commonly used password!")

    # Sequential characters
    if _has_sequential(password):
        score -= 10
        suggestions.append("Avoid sequential patterns (abc, 123, qwerty)")

    # Repeating characters
    if _has_repeating(password):
        score -= 10
        suggestions.append("Avoid repeating characters (aaa, 111)")

    # All same case
    if password.isalpha() and (password.islower() or password.isupper()):
        score -= 5

    # ─── Bonuses ───────────────────────────────────────────
    # Long diverse password
    if length >= 12 and diversity_count >= 3:
        score += 10

    # Very long password (passphrase-style)
    if length >= 20:
        score += 10

    # ─── Clamp and Classify ────────────────────────────────
    score = max(0, min(100, score))

    if score >= 80:
        label = "Very Strong"
        color = "#00ff88"
    elif score >= 60:
        label = "Strong"
        color = "#44cc44"
    elif score >= 40:
        label = "Fair"
        color = "#ffaa00"
    elif score >= 20:
        label = "Weak"
        color = "#ff8800"
    else:
        label = "Very Weak"
        color = "#ff4444"

    result.score = score
    result.label = label
    result.color = color
    result.crack_time = _estimate_crack_time(password)
    result.suggestions = suggestions

    return result
