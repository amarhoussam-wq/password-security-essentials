"""
Diceware Passphrase Generator
Generates high-entropy, human-memorable passphrases using the Diceware method
and the EFF Large Wordlist (7,776 words).
Uses cryptographically secure random number generator (secrets module).
"""

import json
import math
import os
import secrets
from typing import List, Literal, Optional

# Path to the EFF large wordlist
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "eff_wordlist.json")

# Fallback curated wordlist in case JSON is missing or inaccessible
FALLBACK_WORDS = [
    "correct", "horse", "battery", "staple", "galaxy", "quantum", "crypto",
    "shield", "falcon", "anchor", "silver", "planet", "timber", "rocket",
    "shadow", "canyon", "velvet", "harbor", "marble", "breeze", "thunder",
    "pyramid", "summit", "beacon", "horizon", "glacier", "phoenix", "whisper"
]


def load_wordlist() -> List[str]:
    """Load the 7,776-word EFF Large Wordlist."""
    if os.path.exists(WORDLIST_PATH):
        try:
            with open(WORDLIST_PATH, "r", encoding="utf-8") as f:
                words = json.load(f)
                if isinstance(words, list) and len(words) > 0:
                    return words
        except Exception:
            pass
    return FALLBACK_WORDS


EFF_WORDS: List[str] = load_wordlist()
WORDLIST_SIZE: int = len(EFF_WORDS)
# Exact entropy per word from 7,776 possibilities: log2(7776) ≈ 12.9248 bits
ENTROPY_PER_WORD: float = math.log2(WORDLIST_SIZE) if WORDLIST_SIZE > 0 else 12.92


def estimate_passphrase_crack_time(entropy_bits: float) -> str:
    """Estimate time to crack passphrase at 10 billion guesses/second (modern GPU cluster)."""
    guesses = 2 ** entropy_bits
    seconds = guesses / 10_000_000_000

    if seconds < 1:
        return "less than a second"
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
        return f"{int(seconds / (86400 * 365 * 1000))}k years"
    else:
        return "centuries"


def generate_passphrase(
    num_words: int = 5,
    separator: str = "-",
    capitalize: Literal["title", "upper", "lower", "none"] = "title",
    include_number: bool = True,
    number_position: Literal["end", "start", "random"] = "end",
) -> dict:
    """
    Generate a cryptographically secure, high-entropy, human-memorable passphrase.
    
    Args:
        num_words: Number of words to select (3 to 10, default 5).
        separator: Character or string between words (e.g. '-', ' ', '_', '.').
        capitalize: Capitalization format ('title', 'upper', 'lower', 'none').
        include_number: Whether to append/prepend a random digit (0-9).
        number_position: Where to place the number ('end', 'start', 'random').
    
    Returns:
        Dictionary with passphrase, words, entropy, score, crack time estimate.
    """
    num_words = max(3, min(10, num_words))
    words = [secrets.choice(EFF_WORDS) for _ in range(num_words)]

    # Apply capitalization
    if capitalize == "title":
        processed_words = [w.capitalize() for w in words]
    elif capitalize == "upper":
        processed_words = [w.upper() for w in words]
    elif capitalize == "lower" or capitalize == "none":
        processed_words = [w.lower() for w in words]
    else:
        processed_words = [w.capitalize() for w in words]

    # Calculate entropy
    entropy = num_words * ENTROPY_PER_WORD

    if include_number:
        digit = str(secrets.randbelow(10))
        # Adding a single digit 0-9 adds log2(10) ≈ 3.32 bits
        entropy += math.log2(10)

        if number_position == "start":
            passphrase = digit + separator + separator.join(processed_words)
        elif number_position == "random":
            # Can insert between words or at ends
            insert_idx = secrets.randbelow(len(processed_words) + 1)
            processed_copy = list(processed_words)
            processed_copy.insert(insert_idx, digit)
            passphrase = separator.join(processed_copy)
            # Extra entropy from position choice: log2(num_words + 1)
            entropy += math.log2(num_words + 1)
        else:  # 'end'
            passphrase = separator.join(processed_words) + separator + digit
    else:
        passphrase = separator.join(processed_words)

    # Score calculation (0-100)
    # 5 words ~ 65 bits -> score ~ 85
    # 6 words ~ 78 bits -> score 95-100
    if entropy >= 75:
        score = min(100, int(85 + (entropy - 75) * 1.5))
        label = "very strong"
    elif entropy >= 55:
        score = int(70 + (entropy - 55) * 0.75)
        label = "strong"
    elif entropy >= 40:
        score = int(50 + (entropy - 40) * 1.33)
        label = "moderate"
    else:
        score = max(20, int(entropy))
        label = "weak"

    crack_time = estimate_passphrase_crack_time(entropy)

    return {
        "passphrase": passphrase,
        "words": words,
        "word_count": num_words,
        "separator": separator,
        "entropy_bits": round(entropy, 2),
        "score": score,
        "label": label,
        "crack_time_display": crack_time,
        "method": f"Diceware (EFF Long Wordlist, {WORDLIST_SIZE} words)",
    }
