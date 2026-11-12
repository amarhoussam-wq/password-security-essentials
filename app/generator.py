"""
Secure Password Generator Module
Implements cryptographically secure pseudo-random number generator (CSPRNG)
via Python's secrets module (backed by os.urandom / kernel entropy pool).

Cryptographic Note:
Python's standard 'random' module uses the Mersenne Twister (MT19937) algorithm,
which is deterministic and strictly unsuitable for security or cryptography
because its internal state can be reconstructed after observing 624 outputs.
The 'secrets' module accesses the operating system's cryptographic CSPRNG
(e.g., CryptGenRandom / BCryptGenRandom on Windows, /dev/urandom on Linux).
"""

import math
import secrets
import string
from typing import Optional

# Characters that are visually confusing in common fonts
AMBIGUOUS_CHARS = "0O1lI|`"


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
    
    Args:
        length: Desired length (minimum 8, maximum 128).
        uppercase: Include uppercase characters [A-Z].
        lowercase: Include lowercase characters [a-z].
        digits: Include numeric digits [0-9].
        symbols: Include special symbols.
        exclude_ambiguous: Exclude characters that look similar (e.g., 0, O, 1, l, I).
        
    Returns:
        str: Cryptographically secure generated password.
    """
    length = max(8, min(128, length))
    charset = ""

    categories = []
    if lowercase:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        charset += chars
        categories.append(chars)

    if uppercase:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        charset += chars
        categories.append(chars)

    if digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        charset += chars
        categories.append(chars)

    if symbols:
        chars = string.punctuation
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARS)
        charset += chars
        categories.append(chars)

    if not charset:
        # Fallback if all options were toggled off
        charset = string.ascii_letters + string.digits
        categories = [string.ascii_letters, string.digits]

    # CSPRNG selection
    # Ensure at least one character from each active category
    while True:
        password_chars = [secrets.choice(charset) for _ in range(length)]
        password = "".join(password_chars)

        # Verify that all selected categories have at least one representative
        if all(any(c in cat for c in password) for cat in categories if cat):
            return password
