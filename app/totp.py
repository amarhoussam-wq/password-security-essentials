"""
Two-Factor Authentication (2FA) Module
Implements RFC 6238 (TOTP: Time-Based One-Time Password Algorithm)
and RFC 4226 (HOTP: HMAC-Based One-Time Password Algorithm).
Includes Base32 secret generation, provisioning URI creation,
and QR code generation for authenticator apps (Google Authenticator, Authy, etc.).
"""

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
import urllib.parse
from typing import Optional, Tuple

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False


def generate_secret(byte_length: int = 20) -> str:
    """
    Generate a cryptographically secure random Base32 secret key.
    RFC 6238 recommends at least 160 bits (20 bytes) for SHA-1.
    """
    random_bytes = secrets.token_bytes(byte_length)
    # Base32 encoding (RFC 3548 / RFC 4648)
    return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def get_provisioning_uri(
    secret: str,
    account_name: str = "user@example.com",
    issuer: str = "PasswordSecurityApp",
    digits: int = 6,
    period: int = 30,
) -> str:
    """
    Build standard otpauth:// URI for authenticator applications.
    Format: otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
    """
    # Clean secret: remove spaces and uppercase
    clean_secret = secret.replace(" ", "").upper()
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    params = urllib.parse.urlencode({
        "secret": clean_secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": digits,
        "period": period,
    })
    return f"otpauth://totp/{label}?{params}"


def generate_qr_code_base64(uri: str) -> Optional[str]:
    """
    Generate a PNG QR code for the provisioning URI and return as a base64 Data URL.
    Returns None if qrcode library is not installed or generation fails.
    """
    if not HAS_QRCODE:
        return None

    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=8,
            border=2,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="#000000", back_color="#ffffff")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except Exception:
        return None


def generate_hotp(secret: str, counter: int, digits: int = 6) -> str:
    """
    Compute HMAC-based One-Time Password (RFC 4226).
    """
    # Clean secret and pad if necessary
    clean_secret = secret.replace(" ", "").upper()
    missing_padding = len(clean_secret) % 8
    if missing_padding:
        clean_secret += "=" * (8 - missing_padding)

    key = base64.b32decode(clean_secret, casefold=True)
    # Counter as 8-byte big-endian integer
    counter_bytes = struct.pack(">Q", counter)

    # HMAC-SHA1
    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic Truncation
    offset = hmac_digest[-1] & 0x0F
    code = (
        ((hmac_digest[offset] & 0x7F) << 24)
        | ((hmac_digest[offset + 1] & 0xFF) << 16)
        | ((hmac_digest[offset + 2] & 0xFF) << 8)
        | (hmac_digest[offset + 3] & 0xFF)
    )

    otp = code % (10 ** digits)
    return f"{otp:0{digits}d}"


def generate_totp(
    secret: str,
    timestamp: Optional[float] = None,
    time_step: int = 30,
    digits: int = 6,
) -> str:
    """
    Compute Time-based One-Time Password (RFC 6238).
    """
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp // time_step)
    return generate_hotp(secret, counter, digits)


def verify_totp(
    token: str,
    secret: str,
    timestamp: Optional[float] = None,
    time_step: int = 30,
    window: int = 1,
    digits: int = 6,
) -> Tuple[bool, int]:
    """
    Verify TOTP token against secret key with time drift tolerance.
    
    Args:
        token: User-submitted 6-digit code.
        secret: Base32 secret key.
        timestamp: Evaluation timestamp (defaults to current time).
        time_step: Time step in seconds (default 30s).
        window: Number of steps before and after current time to allow (drift tolerance).
                window=1 allows [-1, 0, +1] steps = 90s total tolerance.
        digits: Code length (default 6).
    
    Returns:
        (is_valid, drift_offset): Tuple where is_valid is True if match found,
                                  and drift_offset indicates the step difference (-1, 0, 1).
    """
    if timestamp is None:
        timestamp = time.time()

    current_counter = int(timestamp // time_step)
    clean_token = token.replace(" ", "").replace("-", "").strip()

    if len(clean_token) != digits or not clean_token.isdigit():
        return False, 0

    for offset in range(-window, window + 1):
        counter = current_counter + offset
        expected_token = generate_hotp(secret, counter, digits)
        # Use constant-time comparison to prevent side-channel timing attacks
        if hmac.compare_digest(clean_token, expected_token):
            return True, offset

    return False, 0


def get_remaining_seconds(time_step: int = 30) -> int:
    """Calculate remaining seconds before the current TOTP step expires."""
    return time_step - (int(time.time()) % time_step)
