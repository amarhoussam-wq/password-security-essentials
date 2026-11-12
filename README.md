# Password Security Essentials Microservice

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-61%20Passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

An independent, comprehensive software module dedicated to password protection and management within the authentication lifecycle, architected as a high-performance RESTful microservice.

Designed for the **Practical Work Assignment**: *Applied Programming Tasks: Exploring Password Security Essentials*  
**Supervisor:** Dr. Brahim Ferik (`ferik.brahim@univ-ouargla.dz`)  
**Institution:** University of Ouargla

---

## Technical Tasks Implemented

1. **Password Strength Verifier (`POST /analyze`):**
   - Evaluates complexity based on Shannon search-space entropy: $E = L \cdot \log_2(R)$.
   - Character diversity analysis (lowercase, uppercase, digits, symbols).
   - Defensive heuristic pattern detection (common leaked dictionaries, spatial keyboard walks, sequential runs, repetitions).
   - Real-world GPU brute-force crack time estimation.
   - Actionable remediation suggestions.

2. **Secure Password Generator (`POST /generate/password`):**
   - Strict cryptographically secure pseudo-random number generator (CSPRNG) via Python's `secrets` module (backed by OS kernel entropy).
   - Guaranteed character class inclusion invariant.
   - Configurable character sets and visual ambiguity filtering (`0/O`, `1/l/I`).

3. **Diceware Passphrase Generator (`POST /generate/passphrase`):**
   - Implements Arnold Reinhold's Diceware method using the official **EFF Large Wordlist** (7,776 words).
   - Generates high-entropy, human-memorable passphrases ($\log_2(7776) \approx 12.92$ bits of entropy per word).
   - Configurable word counts, separators, capitalization styles, and optional numeric digits.

4. **Two-Factor Authentication / 2FA (`POST /2fa/setup`, `POST /2fa/verify`, `POST /2fa/generate`):**
   - Full implementation of **RFC 6238 (TOTP)** and **RFC 4226 (HOTP)**.
   - Cryptographically secure Base32 secret key generation (160 bits).
   - Standard `otpauth://totp/...` provisioning URI generation.
   - Scannable PNG QR code generation (Base64 Data URI) compatible with Google Authenticator, Authy, Apple Passwords, etc.
   - Constant-time verification (`hmac.compare_digest`) with configurable clock drift window tolerance ($\pm 30$ seconds).

5. **Breached Passwords Analysis (`POST /breach/check`):**
   - Integration with Troy Hunt's **Have I Been Pwned (HIBP)** API v3.
   - Strictly implements the mathematical **k-anonymity** model: transmits only 5 hex characters of the SHA-1 hash prefix.
   - Matching is executed locally, guaranteeing zero-knowledge privacy for the user.

---

## Interactive Web Dashboard

The microservice includes a modern, responsive single-page web dashboard served directly at `http://localhost:8000/`:

- **Strength Verifier Tab:** Real-time entropy meter, score bar, character diversity pills, suggestions, and one-click breach check.
- **Password Generator Tab:** Interactive sliders, character toggles, instant strength score, and clipboard copy.
- **Passphrase Generator Tab:** Diceware word count, separator controls, entropy calculations, and crack time estimates.
- **Two-Factor Authentication Tab:** Instant 2FA setup, scannable QR code display, live 30-second animated countdown bar, live token display, and interactive code verification tester.
- **Breach Checker Tab:** Interactive visual k-anonymity step-by-step explainer with real-time API query.

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Vikrant892/password-strength-api.git
cd password-strength-api-main

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Microservice

```bash
uvicorn app.main:app --reload --port 8000
```

- Access the Interactive Web Dashboard: **`http://localhost:8000`**
- Interactive Swagger API Documentation: **`http://localhost:8000/docs`**
- Interactive ReDoc Specification: **`http://localhost:8000/redoc`**
- Health Check Endpoint: **`http://localhost:8000/health`**

---

## Running Automated Tests

The codebase includes **61 automated test cases** covering 100% of the functional tasks, including verification against the official **RFC 6238 Appendix B test vectors**:

```bash
# Run full pytest suite
pytest tests/ -v

# Or run the standalone test runner
python test_runner.py
```

---

## Project Structure

```
password-strength-api-main/
│
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application & RESTful routing
│   ├── models.py            # Pydantic schemas for all 5 technical tasks
│   ├── analyzer.py          # Password Strength Verifier (entropy & heuristics)
│   ├── generator.py         # Secure Password Generator (CSPRNG)
│   ├── passphrase.py        # Diceware Passphrase Generator (EFF wordlist)
│   ├── eff_wordlist.json    # Official 7,776-word EFF Large Wordlist
│   ├── totp.py              # RFC 6238 TOTP 2FA & QR code engine
│   └── breach_check.py      # Have I Been Pwned k-anonymity breach analyzer
│
├── static/
│   └── index.html           # Interactive demonstration web dashboard
├── frontend/
│   └── index.html           # Mirror of web dashboard
│
├── tests/
│   ├── __init__.py
│   ├── test_analyzer.py     # 21 tests for strength evaluation & entropy
│   ├── test_generator.py    # 8 tests for CSPRNG generation & uniqueness
│   ├── test_passphrase.py   # 9 tests for Diceware & wordlist integrity
│   ├── test_totp.py         # 8 tests for RFC 6238 vectors & drift tolerance
│   ├── test_breach.py       # 5 tests for k-anonymity & hash range parsing
│   └── test_api.py          # 10 integration tests for RESTful API endpoints
│
├── REPORT.md                # Comprehensive Technical Report for Dr. Brahim Ferik
├── test_runner.py           # Unified test execution script
├── requirements.txt         # Production dependencies
├── Dockerfile               # Container definition
└── README.md                # Project documentation
```

---

## Technical Documentation

For complete mathematical derivations, architectural decisions, and defense session talking points, refer to the [Technical Report (REPORT.md)](REPORT.md).
