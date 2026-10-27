"""
checker_core.py - Core logic for password strength analysis.

Provides pure functions for evaluating password security, detecting patterns,
calculating entropy, estimating crack time, and generating actionable feedback.
Zero I/O operations (no input() or print() calls).
"""

import math
import re
import string

COMMON_PASSWORDS = {
    "password",
    "123456",
    "qwerty",
    "admin",
    "letmein",
    "welcome",
    "password123",
    "abc123",
}

KEYBOARD_PATTERNS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def check_length(password: str, min_length: int = 8) -> bool:
    """Check if the password meets the minimum length requirement."""
    return len(password) >= min_length


def check_uppercase(password: str) -> bool:
    """Check if the password contains at least one uppercase letter."""
    return any(c.isupper() for c in password)


def check_lowercase(password: str) -> bool:
    """Check if the password contains at least one lowercase letter."""
    return any(c.islower() for c in password)


def check_digits(password: str) -> bool:
    """Check if the password contains at least one numeric digit."""
    return any(c.isdigit() for c in password)


def check_special_chars(password: str) -> bool:
    """Check if the password contains at least one special character."""
    special_set = set(string.punctuation)
    return any(c in special_set for c in password)


def check_common_password(password: str) -> bool:
    """
    Check if the password matches a known common password.
    Comparison is case-insensitive and ignores leading/trailing whitespace.
    """
    return password.strip().lower() in COMMON_PASSWORDS


def check_patterns(password: str) -> bool:
    """
    Detect predictable patterns such as sequential numbers ('1234'),
    repeated characters ('aaaa'), or keyboard walks ('qwerty', 'asdf').
    Returns True if any pattern is found, False otherwise.
    """
    if len(password) < 3:
        return False

    lowered = password.lower()

    # 1. Repeated characters (3 or more of the same character consecutively, e.g. 'aaa', '1111')
    if re.search(r"(.)\1{2,}", lowered):
        return True

    # 2. Sequential numbers (3 or more digits in forward or reverse sequence, e.g. '1234', '987')
    digits_forward = "0123456789"
    digits_backward = "9876543210"
    for i in range(len(digits_forward) - 2):
        seq = digits_forward[i : i + 3]
        if seq in lowered:
            return True
    for i in range(len(digits_backward) - 2):
        seq = digits_backward[i : i + 3]
        if seq in lowered:
            return True

    # 3. Keyboard walks (4 or more consecutive keys in a row, forward or reverse)
    for row in KEYBOARD_PATTERNS:
        rev_row = row[::-1]
        for i in range(len(row) - 3):
            if row[i : i + 4] in lowered or rev_row[i : i + 4] in lowered:
                return True

    return False


def calculate_entropy(password: str) -> float:
    """
    Estimate bits of entropy based on character set pool size (R) and password length (L).
    Formula: Entropy = L * log2(R)
    """
    if not password:
        return 0.0

    pool_size = 0
    if check_lowercase(password):
        pool_size += 26
    if check_uppercase(password):
        pool_size += 26
    if check_digits(password):
        pool_size += 10
    if check_special_chars(password):
        pool_size += 32

    # Include any other printable characters (such as whitespace) if present
    other_chars = set(password) - set(string.ascii_letters + string.digits + string.punctuation)
    if other_chars:
        pool_size += len(other_chars)

    if pool_size == 0:
        return 0.0

    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Estimate time to crack assuming 1 billion (10^9) guesses per second.
    Returns a human-readable duration string.
    """
    if entropy_bits <= 0:
        return "Instant"

    guesses = 2**entropy_bits
    guesses_per_second = 10**9
    seconds = guesses / guesses_per_second

    if seconds < 0.001:
        return "Instant"
    if seconds < 1:
        return "Less than a second"
    if seconds < 60:
        return f"{math.ceil(seconds)} seconds"
    
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    
    years = days / 365.25
    if years < 100:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years:,.0f} years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:.1f} billion years"
    
    return f"{years / 1_000_000_000_000:.1f} trillion years"


def calculate_score(password: str) -> int:
    """
    Combine all checks into a score out of 100.
    Considers length, character variety, pattern penalties, and common passwords.
    """
    if not password:
        return 0

    # Common passwords get heavily penalized
    if check_common_password(password):
        return 5

    score = 0
    length = len(password)

    # 1. Length scoring (up to 40 points)
    if length < 8:
        score += length * 2  # up to 14 points
    elif 8 <= length < 12:
        score += 20 + (length - 8) * 2  # 20 to 26 points
    elif 12 <= length < 16:
        score += 28 + (length - 12) * 2  # 28 to 34 points
    else:
        score += 40  # 16+ chars gets full 40 points

    # 2. Character variety (up to 40 points)
    has_upper = check_uppercase(password)
    has_lower = check_lowercase(password)
    has_num = check_digits(password)
    has_spec = check_special_chars(password)

    variety_count = sum([has_upper, has_lower, has_num, has_spec])

    if has_lower:
        score += 10
    if has_upper:
        score += 10
    if has_num:
        score += 10
    if has_spec:
        score += 10

    # 3. Bonus points (up to 20 points)
    # Full variety bonus
    if variety_count == 4:
        score += 10
    # Length + variety bonus
    if length >= 12 and variety_count >= 3:
        score += 10

    # 4. Deductions for weaknesses
    if check_patterns(password):
        score -= 15

    # Deduction if only letters or only digits
    if (has_lower or has_upper) and not (has_num or has_spec):
        score -= 10
    elif has_num and not (has_lower or has_upper or has_spec):
        score -= 15

    # Clamp score between 0 and 100
    return max(0, min(100, score))


def get_strength_rating(score: int) -> str:
    """
    Return strength rating based on score:
    - Weak: 0 - 40
    - Moderate: 41 - 70
    - Strong: 71 - 90
    - Very Strong: 91 - 100
    """
    if score <= 40:
        return "Weak"
    elif score <= 70:
        return "Moderate"
    elif score <= 90:
        return "Strong"
    else:
        return "Very Strong"


def get_feedback(password: str) -> list[str]:
    """
    Return a list of specific issues found in the password.
    """
    if not password:
        return ["Password cannot be empty."]

    issues = []

    if check_common_password(password):
        issues.append("Common password detected (easily cracked in seconds).")

    if not check_length(password, 8):
        issues.append(f"Too short ({len(password)} characters). Minimum recommended is 8 characters.")
    elif len(password) < 12:
        issues.append(f"Moderate length ({len(password)} characters). 12 or more characters recommended.")

    if not check_lowercase(password):
        issues.append("No lowercase letters (a-z).")

    if not check_uppercase(password):
        issues.append("No uppercase letters (A-Z).")

    if not check_digits(password):
        issues.append("No numeric digits (0-9).")

    if not check_special_chars(password):
        issues.append("No special characters (!@#$%^&*...).")

    if check_patterns(password):
        issues.append("Contains sequential patterns, repeated characters, or keyboard walks.")

    if not issues:
        issues.append("No weaknesses detected! Great password structure.")

    return issues


def get_suggestions(password: str) -> list[str]:
    """
    Return a list of actionable improvement tips for the password.
    """
    if not password:
        return [
            "Use at least 12 to 16 characters.",
            "Combine uppercase letters, lowercase letters, numbers, and symbols.",
            "Avoid common words, sequential numbers, or personal details.",
        ]

    suggestions = []

    if check_common_password(password):
        suggestions.append("Avoid common dictionary words, well-known phrases, or predictable passwords.")

    if len(password) < 8:
        suggestions.append("Increase length to at least 8 characters (12+ is strongly recommended).")
    elif len(password) < 12:
        suggestions.append("Extend length to 12 or more characters for stronger defense against brute-force.")

    if not check_uppercase(password):
        suggestions.append("Add uppercase letters (A-Z) to expand character diversity.")

    if not check_lowercase(password):
        suggestions.append("Add lowercase letters (a-z).")

    if not check_digits(password):
        suggestions.append("Add numeric digits (0-9) throughout the password.")

    if not check_special_chars(password):
        suggestions.append("Add special characters (e.g. !@#$%^&*()_+~).")

    if check_patterns(password):
        suggestions.append("Replace sequential sequences (e.g. '1234', 'qwerty') and repeated characters with unpredictable characters.")

    if not suggestions:
        suggestions.append("Your password satisfies all recommended security practices!")

    return suggestions
