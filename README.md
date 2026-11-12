# Password Security Suite

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Tests-61%20Passed-brightgreen.svg)]()
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)
[![PWA](https://img.shields.io/badge/PWA-Installable-purple.svg)](static/manifest.json)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

An independent, enterprise-grade software module and mobile-ready web application dedicated to password protection, cryptographic generation, and two-factor authentication lifecycle management.

Architected as a high-performance RESTful microservice with an interactive Progressive Web App (PWA) and Android-ready interface.

---

## Features

1. **Password Strength Verifier (`POST /analyze`):**
   - Evaluates complexity based on Shannon search-space entropy: $E = L \cdot \log_2(R)$.
   - Character diversity analysis (lowercase, uppercase, digits, symbols).
   - Defensive heuristic pattern detection (common leaked dictionaries, spatial keyboard walks, sequential runs, repetitions).
   - Real-world GPU brute-force crack time estimation ($10^{10}$ guesses/sec).
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

## Mobile Application & PWA Installation

The application includes full **Progressive Web App (PWA)** and mobile device support:

### 📱 Installing on Android / iPhone:
1. Open the application URL in Google Chrome (or Safari on iOS) on your phone.
2. An **"Install App" / "تثبيت التطبيق"** banner or button will appear automatically.
3. Tap **Install** — the app installs directly to your home screen with a native icon, launches full-screen with offline support, and functions identically to a native Android app without requiring third-party app stores!

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/amarhoussam-wq/password-security-essentials.git
cd password-security-essentials

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

## Docker & Coolify Deployment

The repository includes a production-ready `Dockerfile` and `docker-compose.yml`:

```bash
# Run with Docker
docker build -t password-security-suite .
docker run -p 8000:8000 password-security-suite

# Or run with Docker Compose
docker compose up -d
```

### Deploying to Coolify:
1. In Coolify, click **+ New Resource** ➔ **Public Repository** (or Private).
2. Enter the repository URL: `https://github.com/amarhoussam-wq/password-security-essentials.git`
3. Set Port to **`8000`** and Healthcheck Path to **`/health`**.
4. Click **Deploy** — Coolify builds and runs the container with automatic SSL/HTTPS.

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
password-security-essentials/
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
│   ├── index.html           # Interactive web & mobile PWA dashboard
│   ├── manifest.json        # Web App Manifest for Android installation
│   ├── sw.js                # Service Worker for offline mobile capability
│   ├── icon-192.png         # Mobile application icon (192x192)
│   └── icon-512.png         # Mobile application icon (512x512)
│
├── tests/
│   ├── test_analyzer.py     # 21 tests for strength evaluation & entropy
│   ├── test_generator.py    # 8 tests for CSPRNG generation & uniqueness
│   ├── test_passphrase.py   # 9 tests for Diceware & wordlist integrity
│   ├── test_totp.py         # 8 tests for RFC 6238 vectors & drift tolerance
│   ├── test_breach.py       # 5 tests for k-anonymity & hash range parsing
│   └── test_api.py          # 10 integration tests for RESTful API endpoints
│
├── REPORT.md                # Comprehensive Software Architecture & Cryptography Report
├── Dockerfile               # Production Docker container
├── docker-compose.yml       # Docker Compose service definition
├── requirements.txt         # Production dependencies
└── README.md                # Project documentation
```
