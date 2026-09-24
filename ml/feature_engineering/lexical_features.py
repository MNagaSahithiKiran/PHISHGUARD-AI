"""
PhishGuard AI - Lexical Feature Extractor.
Implements mathematical, statistical, and token-based lexical metrics.
"""

import math
from collections import Counter
import re


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy H(X) = -sum(P(x) * log2(P(x)))
    Measures information randomness and algorithmic string generation (e.g. DGA).
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def calculate_repeated_char_max(text: str) -> int:
    """
    Identifies the maximum run length of consecutive identical characters.
    Phishing URLs often employ repeated tokens for evasion or typosquatting (e.g., 'gooogle').
    """
    if not text:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 1
    return max_run


def count_special_characters(text: str) -> int:
    """Counts non-alphanumeric ASCII characters excluding typical protocol tokens."""
    return sum(1 for c in text if not c.isalnum() and c not in ["/", ":", "."])


def calculate_char_ratios(text: str) -> tuple[float, float]:
    """
    Computes:
    1. Digit-to-character ratio
    2. Special-character-to-character ratio
    """
    if not text:
        return 0.0, 0.0
    length = len(text)
    digits = sum(c.isdigit() for c in text)
    specials = sum(1 for c in text if not c.isalnum())
    return round(digits / length, 4), round(specials / length, 4)
