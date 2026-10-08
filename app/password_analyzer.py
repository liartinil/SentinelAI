from __future__ import annotations

import math
import re

COMMON_PATTERNS = [
    "password", "qwerty", "123456", "111111", "admin",
    "letmein", "welcome", "iloveyou", "abc123"
]


def analyze_password(password: str) -> dict:
    score = 0
    feedback: list[str] = []

    length = len(password)
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 28
    elif length >= 8:
        score += 18
    else:
        score += max(0, length * 2)
        feedback.append("Use at least 12 characters; 16+ is better.")

    categories = 0
    checks = [
        (r"[a-z]", "lowercase letter"),
        (r"[A-Z]", "uppercase letter"),
        (r"\d", "number"),
        (r"[^A-Za-z0-9]", "special character"),
    ]
    for pattern, _ in checks:
        if re.search(pattern, password):
            categories += 1

    score += categories * 12

    lower = password.lower()
    if any(p in lower for p in COMMON_PATTERNS):
        score -= 25
        feedback.append("Avoid common passwords and predictable patterns.")

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating the same character many times.")

    if re.search(r"(1234|2345|3456|4567|5678|6789|abcd|qwer)", lower):
        score -= 12
        feedback.append("Avoid obvious sequences such as 1234 or qwer.")

    if categories < 3:
        feedback.append("Use a mix of uppercase, lowercase, numbers, and symbols.")

    score = max(0, min(score, 100))
    label = "weak" if score < 40 else "fair" if score < 65 else "strong" if score < 85 else "very strong"

    # Rough entropy estimate, not a cracking-time promise.
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"\d", password): pool += 10
    if re.search(r"[^A-Za-z0-9]", password): pool += 32
    entropy_bits = round(length * math.log2(pool), 1) if pool and length else 0

    if not feedback:
        feedback.append("Good length and character variety. Prefer a unique password for every account.")

    return {
        "score": score,
        "label": label,
        "entropy_bits_estimate": entropy_bits,
        "feedback": feedback,
        "privacy_note": "The password is processed in memory and is not stored in scan history."
    }
