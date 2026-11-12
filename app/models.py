"""
Pydantic Data Models for Request and Response validation.
Covers all five practical work modules:
1. Password Strength Verifier
2. Secure Password Generator (CSPRNG)
3. Passphrase Generator (Diceware)
4. Two-Factor Authentication (TOTP / RFC 6238)
5. Breached Passwords Analysis (HIBP k-anonymity)
"""

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field


# ============================================================================
# 1. Password Strength Verifier Models
# ============================================================================

class CharacterDiversity(BaseModel):
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    diversity_count: int


class AnalyzeRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256, description="Password to evaluate")
    check_breach: bool = Field(default=False, description="Optionally check Have I Been Pwned API")


class AnalyzeResponse(BaseModel):
    score: int = Field(..., ge=0, le=100, description="Overall score 0-100")
    label: str = Field(..., description="Complexity classification: very weak, weak, moderate, strong, very strong")
    entropy_bits: float = Field(..., description="Calculated Shannon search-space entropy in bits")
    charset_size: Optional[int] = Field(default=None, description="Effective character set pool size")
    length: Optional[int] = Field(default=None, description="Password length in characters")
    crack_time_display: str = Field(..., description="Estimated brute-force crack time")
    character_diversity: Optional[CharacterDiversity] = None
    patterns_detected: Optional[List[str]] = Field(default_factory=list, description="Vulnerabilities or patterns detected")
    suggestions: List[str] = Field(default_factory=list, description="Actionable recommendations")
    breached: Optional[bool] = Field(default=None, description="Breach status if checked")
    breach_count: Optional[int] = Field(default=None, description="Number of breach occurrences")
    breach_message: Optional[str] = Field(default=None, description="Breach check status message")


# ============================================================================
# 2. Secure Password Generator Models (CSPRNG)
# ============================================================================

class GenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=128, description="Desired password length (8-128)")
    uppercase: bool = Field(default=True, description="Include uppercase letters [A-Z]")
    lowercase: bool = Field(default=True, description="Include lowercase letters [a-z]")
    digits: bool = Field(default=True, description="Include numeric digits [0-9]")
    symbols: bool = Field(default=True, description="Include special symbols")
    exclude_ambiguous: bool = Field(
        default=False,
        description="Exclude easily confused characters like 0/O, 1/l/I"
    )


class GenerateResponse(BaseModel):
    password: str = Field(..., description="CSPRNG generated password")
    score: int = Field(..., description="Strength score (0-100)")
    entropy_bits: float = Field(..., description="Calculated entropy in bits")
    crack_time_display: Optional[str] = None


# ============================================================================
# 3. Passphrase Generator Models (Diceware)
# ============================================================================

class PassphraseRequest(BaseModel):
    num_words: int = Field(default=5, ge=3, le=10, description="Number of words (3-10)")
    separator: str = Field(default="-", description="Separator between words")
    capitalize: Literal["title", "upper", "lower", "none"] = Field(
        default="title",
        description="Capitalization style: title, upper, lower, none"
    )
    include_number: bool = Field(default=True, description="Include a random numeric digit")
    number_position: Literal["end", "start", "random"] = Field(
        default="end",
        description="Position of number if included"
    )


class PassphraseResponse(BaseModel):
    passphrase: str = Field(..., description="High-entropy human-memorable passphrase")
    words: List[str] = Field(..., description="Selected Diceware words")
    word_count: int = Field(..., description="Number of words")
    separator: str = Field(..., description="Word delimiter")
    entropy_bits: float = Field(..., description="Calculated entropy in bits")
    score: int = Field(..., description="Strength score 0-100")
    label: str = Field(..., description="Complexity classification")
    crack_time_display: str = Field(..., description="Estimated brute-force crack time")
    method: str = Field(..., description="Generation method / wordlist")


# ============================================================================
# 4. Two-Factor Authentication Models (TOTP / RFC 6238)
# ============================================================================

class TotpSetupRequest(BaseModel):
    account_name: str = Field(default="student@univ-ouargla.dz", description="User or account identifier")
    issuer: str = Field(default="PasswordSecurityApp", description="Application or organization name")


class TotpSetupResponse(BaseModel):
    secret: str = Field(..., description="Base32-encoded secret key")
    provisioning_uri: str = Field(..., description="Standard otpauth:// URI for authenticator apps")
    qr_code_base64: Optional[str] = Field(default=None, description="PNG QR code as Data URI (data:image/png;base64,...)")
    issuer: str
    account_name: str
    digits: int = 6
    period: int = 30


class TotpVerifyRequest(BaseModel):
    secret: str = Field(..., description="Base32 secret key")
    token: str = Field(..., min_length=6, max_length=8, description="User submitted 6-digit TOTP code")
    window: int = Field(default=1, ge=0, le=5, description="Allowed time drift steps (default 1 = ±30s)")


class TotpVerifyResponse(BaseModel):
    valid: bool = Field(..., description="Whether the token is currently valid")
    drift_step: int = Field(..., description="Drift offset (-1, 0, +1) if valid, 0 otherwise")
    message: str = Field(..., description="Verification explanation")


class TotpGenerateRequest(BaseModel):
    secret: str = Field(..., description="Base32 secret key")


class TotpGenerateResponse(BaseModel):
    token: str = Field(..., description="Current 6-digit TOTP token")
    remaining_seconds: int = Field(..., description="Seconds remaining in current 30-second window")
    period: int = 30


# ============================================================================
# 5. Breached Passwords Analysis Models (HIBP)
# ============================================================================

class BreachCheckRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Password to verify against breach records")


class BreachCheckResponse(BaseModel):
    breached: Optional[bool] = Field(..., description="True if leaked, False if safe, None if query failed")
    breach_count: Optional[int] = Field(..., description="Number of times found in leaked databases")
    sha1_prefix: str = Field(..., description="First 5 hexadecimal characters of SHA-1 hash (k-anonymity)")
    k_anonymity: bool = Field(default=True, description="Indicates k-anonymity protocol was used")
    message: str = Field(..., description="Detailed status message")


# ============================================================================
# Health & Status Models
# ============================================================================

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    modules: List[str] = [
        "password_strength_verifier",
        "secure_password_generator_csprng",
        "diceware_passphrase_generator",
        "totp_two_factor_authentication",
        "breached_passwords_analysis_hibp",
    ]
