# analyzer.py
import math
import re
from typing import Dict, List

def score_password(password: str) -> Dict:
    """
    Analyze the password strength.
    Returns a dict with:
      - score (0–100)
      - entropy (bits)
      - details (list of messages)
      - feedback (suggestions for improvement)
    """
    details: List[str] = []
    feedback: List[str] = []

    length = len(password)
    details.append(f"Length: {length}")

    # --- Character diversity checks ---
    lower = bool(re.search(r"[a-z]", password))
    upper = bool(re.search(r"[A-Z]", password))
    digits = bool(re.search(r"[0-9]", password))
    symbols = bool(re.search(r"[^a-zA-Z0-9]", password))

    charsets = sum([lower, upper, digits, symbols])
    details.append(
        f"Character sets used: {charsets} (lowercase, uppercase, digits, symbols)"
    )

    # --- Basic score calculation ---
    base_score = length * 5 + charsets * 10
    base_score = min(base_score, 100)

    # --- Entropy estimation ---
    charset_size = 0
    if lower:
        charset_size += 26
    if upper:
        charset_size += 26
    if digits:
        charset_size += 10
    if symbols:
        # estimate common printable symbols (approx)
        charset_size += 32

    if charset_size == 0:
        entropy = 0.0
    else:
        entropy = round(length * math.log2(charset_size), 2)

    details.append(f"Estimated entropy: {entropy} bits")

    # --- Pattern checks (dictionary, repetition, sequences) ---
    weak_patterns = ["password", "1234", "qwerty", "admin", "letmein", "welcome"]
    if any(p in password.lower() for p in weak_patterns):
        feedback.append("Avoid common words or patterns like 'password' or '1234'.")
        base_score -= 20

    if re.match(r"^(.)\1{2,}$", password):
        feedback.append("Avoid repeating the same character multiple times.")
        base_score -= 10

    if re.search(r"(?:abc|123|qwe|xyz)", password.lower()):
        feedback.append("Avoid simple sequences like 'abc' or '123'.")
        base_score -= 10

    # --- Feedback for diversity ---
    if not lower or not upper:
        feedback.append("Use both uppercase and lowercase letters.")
    if not digits:
        feedback.append("Add numbers to increase complexity.")
    if not symbols:
        feedback.append("Add symbols (e.g. !@#$) for more security.")
    if length < 8:
        feedback.append("Use at least 8 characters.")
    if length >= 12 and all([lower, upper, digits, symbols]):
        feedback.append("Great! Your password looks strong.")

    # Normalize score
    score = max(0, min(base_score, 100))

    return {
        "score": int(score),
        "entropy": entropy,
        "details": details,
        "feedback": feedback,
    }


# -----------------------
# Time-to-crack utilities
# -----------------------
def estimate_time_to_crack_seconds(entropy_bits: float, guesses_per_second: float) -> float:
    """
    Estimate time in seconds to crack the password, assuming:
    - the attacker tries half the keyspace on average (2^entropy / 2 attempts)
    - guesses_per_second is the attacker's guess rate
    """
    if entropy_bits <= 0 or guesses_per_second <= 0:
        return float("inf")
    # total possibilities = 2^entropy, average attempts = 2^(entropy-1)
    attempts = 2 ** (entropy_bits - 1)
    seconds = attempts / guesses_per_second
    return seconds


def human_readable_seconds(seconds: float) -> str:
    """Convert seconds into a friendly human-readable string."""
    if seconds == float("inf"):
        return "∞"
    units = [
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    ]
    parts = []
    remainder = int(round(seconds))
    for name, size in units:
        if remainder >= size:
            value, remainder = divmod(remainder, size)
            parts.append(f"{value} {name}")
    if not parts:
        return "less than 1 second"
    # show up to two largest units
    return ", ".join(parts[:2])
