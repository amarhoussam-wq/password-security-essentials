"""
Password Protection and Authentication Lifecycle Microservice
Exposes RESTful endpoints for:
1. Password Strength Verifier (entropy, length, character diversity, pattern heuristics)
2. Secure Password Generator (CSPRNG)
3. Passphrase Generator (Diceware method / EFF wordlist)
4. Two-Factor Authentication (TOTP protocol / RFC 6238)
5. Breached Passwords Analysis (Have I Been Pwned k-anonymity API)

Supervisor: Dr. Brahim Ferik
Institution: University of Ouargla
"""

import os
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.models import (
    AnalyzeRequest, AnalyzeResponse,
    GenerateRequest, GenerateResponse,
    PassphraseRequest, PassphraseResponse,
    TotpSetupRequest, TotpSetupResponse,
    TotpVerifyRequest, TotpVerifyResponse,
    TotpGenerateRequest, TotpGenerateResponse,
    BreachCheckRequest, BreachCheckResponse,
    HealthResponse,
)
from app.analyzer import analyze_password
from app.breach_check import check_breach
from app.generator import generate_password
from app.passphrase import generate_passphrase
from app.totp import (
    generate_secret,
    get_provisioning_uri,
    generate_qr_code_base64,
    generate_totp,
    verify_totp,
    get_remaining_seconds,
)

app = FastAPI(
    title="Password Security Essentials Microservice",
    description=(
        "Comprehensive API module for password protection and authentication lifecycle: "
        "Strength Verification, CSPRNG Password Generation, Diceware Passphrases, "
        "TOTP Two-Factor Authentication, and Have I Been Pwned Breached Analysis."
    ),
    version="1.0.0",
    contact={
        "name": "Applied Programming Tasks - Password Security Essentials",
        "email": "ferik.brahim@univ-ouargla.dz",
    },
)

# CORS configuration: Allow localhost and web applications
_allowed_origins = os.environ.get("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.get("/health", response_model=HealthResponse, tags=["Health"])
def health():
    """Service health check and list of active security modules."""
    return HealthResponse()


# ============================================================================
# 1. Password Strength Verifier Endpoint
# ============================================================================

@app.post("/analyze", response_model=AnalyzeResponse, tags=["Strength Verifier"])
def analyze(req: AnalyzeRequest):
    """
    Evaluate password complexity based on:
    - Shannon search-space entropy
    - Character diversity (lowercase, uppercase, digits, symbols)
    - Length thresholds
    - Structural patterns (common leaked passwords, keyboard walks, sequential repetitions)
    - Optional Have I Been Pwned breach detection
    """
    result = analyze_password(req.password)

    if req.check_breach:
        breach_result = check_breach(req.password)
        result["breached"] = breach_result.get("breached")
        result["breach_count"] = breach_result.get("breach_count")
        result["breach_message"] = breach_result.get("message")

    return AnalyzeResponse(**result)


# ============================================================================
# 2. Secure Password Generator Endpoints (CSPRNG)
# ============================================================================

@app.post("/generate/password", response_model=GenerateResponse, tags=["Password Generator"])
@app.post("/generate", response_model=GenerateResponse, tags=["Password Generator"], include_in_schema=False)
def generate(req: GenerateRequest):
    """
    Generate a cryptographically secure random password using Python's CSPRNG (secrets module).
    Guarantees at least one character from each enabled character category.
    """
    password = generate_password(
        length=req.length,
        uppercase=req.uppercase,
        lowercase=req.lowercase,
        digits=req.digits,
        symbols=req.symbols,
        exclude_ambiguous=req.exclude_ambiguous,
    )

    analysis = analyze_password(password)

    return GenerateResponse(
        password=password,
        score=analysis["score"],
        entropy_bits=analysis["entropy_bits"],
        crack_time_display=analysis["crack_time_display"],
    )


# ============================================================================
# 3. Passphrase Generator Endpoint (Diceware)
# ============================================================================

@app.post("/generate/passphrase", response_model=PassphraseResponse, tags=["Passphrase Generator"])
def passphrase_endpoint(req: PassphraseRequest):
    """
    Generate a high-entropy, human-memorable passphrase using the Diceware method
    and the EFF Large Wordlist (7,776 words).
    """
    result = generate_passphrase(
        num_words=req.num_words,
        separator=req.separator,
        capitalize=req.capitalize,
        include_number=req.include_number,
        number_position=req.number_position,
    )
    return PassphraseResponse(**result)


# ============================================================================
# 4. Two-Factor Authentication Endpoints (TOTP / RFC 6238)
# ============================================================================

@app.post("/2fa/setup", response_model=TotpSetupResponse, tags=["Two-Factor Authentication"])
def totp_setup(req: TotpSetupRequest):
    """
    Initialize a new 2FA setup:
    1. Generates a cryptographically secure Base32 secret key.
    2. Builds standard otpauth:// provisioning URI.
    3. Produces a scannable PNG QR code encoded as a base64 Data URI.
    """
    secret = generate_secret(byte_length=20)
    uri = get_provisioning_uri(
        secret=secret,
        account_name=req.account_name,
        issuer=req.issuer,
        digits=6,
        period=30,
    )
    qr_base64 = generate_qr_code_base64(uri)

    return TotpSetupResponse(
        secret=secret,
        provisioning_uri=uri,
        qr_code_base64=qr_base64,
        issuer=req.issuer,
        account_name=req.account_name,
        digits=6,
        period=30,
    )


@app.post("/2fa/verify", response_model=TotpVerifyResponse, tags=["Two-Factor Authentication"])
def totp_verify(req: TotpVerifyRequest):
    """
    Verify a user-submitted 6-digit TOTP code against the Base32 secret.
    Allows clock skew window (default window=1 allows ±30s drift).
    """
    is_valid, drift = verify_totp(
        token=req.token,
        secret=req.secret,
        window=req.window,
        digits=6,
    )

    if is_valid:
        msg = "Token verified successfully."
        if drift != 0:
            msg += f" (Accepted with clock drift of {drift * 30} seconds)."
    else:
        msg = "Invalid or expired token. Please verify your system clock or try again."

    return TotpVerifyResponse(
        valid=is_valid,
        drift_step=drift,
        message=msg,
    )


@app.post("/2fa/generate", response_model=TotpGenerateResponse, tags=["Two-Factor Authentication"])
def totp_generate(req: TotpGenerateRequest):
    """
    Generate current 6-digit TOTP token for a given secret key and return remaining seconds in the cycle.
    Useful for testing, simulations, and automated integration.
    """
    try:
        token = generate_totp(req.secret)
        rem = get_remaining_seconds()
        return TotpGenerateResponse(
            token=token,
            remaining_seconds=rem,
            period=30,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Base32 secret key: {str(exc)}",
        )


# ============================================================================
# 5. Breached Passwords Analysis Endpoint (HIBP)
# ============================================================================

@app.post("/breach/check", response_model=BreachCheckResponse, tags=["Breached Passwords Analysis"])
def breach_check_endpoint(req: BreachCheckRequest):
    """
    Check if a password has been compromised in known data breaches via
    Have I Been Pwned (HIBP) using k-anonymity (transmits only 5 hex chars of SHA-1).
    """
    result = check_breach(req.password)
    return BreachCheckResponse(**result)


# ============================================================================
# Frontend and Static Assets
# ============================================================================

static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", tags=["UI"])
def root():
    """Serve the interactive web demonstration interface."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Password Security API - explore endpoints at /docs"}
