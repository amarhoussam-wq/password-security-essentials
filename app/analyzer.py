import math
import re
import string

# Common leaked / dictionary passwords to catch high-risk patterns immediately
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "abc123", "111111", "password1", "iloveyou",
    "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
    "princess", "letmein", "654321", "monkey", "27653", "1qaz2wsx",
    "123321", "qwertyuiop", "superman", "asdfghjkl", "trustno1",
    "bazinga", "batman", "football", "shadow", "master", "michael",
    "baseball", "access", "hello", "charlie", "donald", "password123",
    "admin", "welcome", "login", "starwars", "solo", "whatever",
    "passw0rd", "summer", "spring", "autumn", "winter", "cheese",
    "corvette", "cookie", "richard", "ranger", "striker", "hunter",
    "buster", "soccer", "harley", "andrew", "tigger", "joshua",
    "pepper", "george", "matrix", "yankees", "thunder", "taylor",
    "austin", "merlin", "ginger", "robert", "bailey", "testing",
    "hockey", "dallas", "jordan", "thomas", "compaq", "internet",
    "mustang", "golfer", "chicken", "maverick", "secret", "computer",
    "jennifer", "jessica", "banana", "1234", "abcdef", "qazwsx",
    "ashley", "killer", "diamond", "maggie", "nicole", "daniel",
    "andrea", "spider", "junior", "nathan", "orange", "winner",
    "mother", "hannah", "jasmine", "peanut", "london", "abcdefg",
    "freedom", "william", "samantha", "lovers", "phoenix", "chelsea",
    "biteme", "amanda", "melissa", "midnight", "anthony", "admin123",
}

# Keyboard spatial sequences
KEYBOARD_PATTERNS = [
    "qwerty", "qwertz", "azerty", "asdf", "zxcv", "wasd",
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "abcd", "bcde", "cdef", "defg",
    "!@#$", "@#$%", "#$%^",
]


def get_charset_size(password: str) -> int:
    """Calculate the effective search space character pool size."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += 32
    if any(ord(c) > 127 for c in password):
        size += 128
    return max(size, 2) if password else 0


def calculate_entropy(password: str) -> float:
    """
    Shannon search-space entropy:
    E = L * log2(R) where L is password length and R is the character set size.
    """
    if not password:
        return 0.0

    charset_size = get_charset_size(password)
    return len(password) * math.log2(charset_size)


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Ballpark brute force time estimate assuming 10 billion guesses/sec (modern GPU rig).
    """
    guesses = 2 ** entropy_bits
    seconds = guesses / 10_000_000_000  # 10B guesses/sec

    if seconds < 0.001:
        return "instantly"
    elif seconds < 1:
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


def analyze_password(password: str) -> dict:
    """
    Algorithmic evaluation of password complexity based on:
    - Length
    - Character diversity (lowercase, uppercase, digits, symbols)
    - Search-space entropy
    - Structural patterns (common passwords, keyboard walks, repetitions, sequences)
    """
    score = 0
    suggestions = []
    patterns_detected = []

    length = len(password)
    charset_size = get_charset_size(password)
    entropy_bits = calculate_entropy(password)

    # --- 1. Length scoring (up to 30 points) ---
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 22
    elif length >= 10:
        score += 15
    elif length >= 8:
        score += 10
    else:
        score += 3
        suggestions.append("Use at least 8 characters, 12+ is strongly recommended")
        patterns_detected.append("Short length (< 8 chars)")

    # --- 2. Character diversity (up to 32 points) ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety_count * 8  # up to 32 points

    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z)")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z)")
    if not has_digit:
        suggestions.append("Add numeric digits (0-9)")
    if not has_symbol:
        suggestions.append("Add special symbols (!@#$%...)")

    # --- 3. Common password check ---
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 5)  # Severe penalty
        suggestions.insert(0, "This is an extremely common password - change it immediately")
        patterns_detected.append("Common leaked password match")

    # --- 4. Keyboard walk pattern check ---
    lower_pw = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower_pw:
            score -= 10
            suggestions.append(f"Avoid keyboard patterns like '{pattern}'")
            patterns_detected.append(f"Keyboard pattern: {pattern}")
            break  # Penalize once

    # --- 5. Repeating characters (e.g., aaa, 111) ---
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1

    if max_repeat >= 3:
        score -= 15
        suggestions.append("Avoid repeating characters (e.g., 'aaa', '111')")
        patterns_detected.append("Repeated characters (3+)")
    elif max_repeat >= 2:
        score -= 5

    # --- 6. Sequential characters (e.g., abc, 123) ---
    sequential_count = 0
    for i in range(2, len(password)):
        if (ord(password[i]) == ord(password[i-1]) + 1 and
                ord(password[i-1]) == ord(password[i-2]) + 1):
            sequential_count += 1

    if sequential_count >= 2:
        score -= 10
        suggestions.append("Avoid sequential characters (e.g., 'abc', '123')")
        patterns_detected.append("Sequential characters")

    # --- 7. Single case penalty ---
    if password.isalpha() and (password.islower() or password.isupper()):
        score -= 5
        suggestions.append("Mix uppercase and lowercase letters")
        patterns_detected.append("Single case alphabetic")

    # --- 8. Entropy bonus ---
    if entropy_bits >= 60:
        score += 20
    elif entropy_bits >= 45:
        score += 12
    elif entropy_bits >= 30:
        score += 5

    # Clamp score to 0-100 range
    score = max(0, min(100, score))

    # Determine classification label
    if score >= 80:
        label = "very strong"
    elif score >= 60:
        label = "strong"
    elif score >= 40:
        label = "moderate"
    elif score >= 20:
        label = "weak"
    else:
        label = "very weak"

    crack_time = estimate_crack_time(entropy_bits)

    return {
        "score": score,
        "label": label,
        "entropy_bits": round(entropy_bits, 2),
        "charset_size": charset_size,
        "length": length,
        "crack_time_display": crack_time,
        "character_diversity": {
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_symbols": has_symbol,
            "diversity_count": variety_count,
        },
        "patterns_detected": patterns_detected,
        "suggestions": suggestions,
    }
