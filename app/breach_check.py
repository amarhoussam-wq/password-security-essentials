"""
Breached Passwords Analysis Module
Integrates with Have I Been Pwned (HIBP) Pwned Passwords API v3
using the mathematical k-anonymity model.

Security Property (k-anonymity):
The client only transmits the first 5 hexadecimal characters of the SHA-1 hash (prefix).
The external API never receives the password or the full hash.
Matching occurs locally on the received range list.
"""

import hashlib
import logging
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_breach(password: str) -> dict:
    """
    Check if a password has appeared in known data breaches.
    Uses HIBP k-anonymity API:
    1. Compute SHA-1(password).
    2. Extract first 5 hex chars as prefix.
    3. Query HIBP range API with the 5-char prefix.
    4. Match the remaining 35 hex chars (suffix) locally.
    
    Returns:
        dict: {
            "breached": bool or None,
            "breach_count": int or None,
            "sha1_prefix": str,
            "k_anonymity": bool,
            "message": str
        }
    """
    if not password:
        return {
            "breached": False,
            "breach_count": 0,
            "sha1_prefix": "",
            "k_anonymity": True,
            "message": "Empty password provided.",
        }

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    try:
        response = httpx.get(
            f"{HIBP_API_URL}{prefix}",
            headers={"User-Agent": "PasswordSecurityApp-UnivOuargla/1.0"},
            timeout=5.0,
        )

        if response.status_code != 200:
            logger.warning("HIBP API returned status %s", response.status_code)
            return {
                "breached": None,
                "breach_count": None,
                "sha1_prefix": prefix,
                "k_anonymity": True,
                "message": f"HIBP service temporarily unavailable (status {response.status_code}).",
            }

        # Response consists of lines formatted as "HASH_SUFFIX:COUNT"
        for line in response.text.splitlines():
            if ":" in line:
                hash_suffix, count_str = line.split(":", 1)
                if hash_suffix.strip() == suffix:
                    count = int(count_str.strip())
                    return {
                        "breached": True,
                        "breach_count": count,
                        "sha1_prefix": prefix,
                        "k_anonymity": True,
                        "message": f"Compromised! Found in {count:,} known data breach occurrences.",
                    }

        return {
            "breached": False,
            "breach_count": 0,
            "sha1_prefix": prefix,
            "k_anonymity": True,
            "message": "Safe: No matching records found in known breach databases.",
        }

    except (httpx.RequestError, httpx.TimeoutException) as exc:
        logger.warning("HIBP lookup network error: %s", exc)
        return {
            "breached": None,
            "breach_count": None,
            "sha1_prefix": prefix,
            "k_anonymity": True,
            "message": "External breach check skipped due to network timeout or connection limits.",
        }
