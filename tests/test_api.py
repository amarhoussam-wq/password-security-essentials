import pytest
from unittest.mock import patch, MagicMock
from app.main import (
    health, analyze, generate, passphrase_endpoint,
    totp_setup, totp_verify, totp_generate, breach_check_endpoint
)
from app.models import (
    AnalyzeRequest, GenerateRequest, PassphraseRequest,
    TotpSetupRequest, TotpVerifyRequest, TotpGenerateRequest,
    BreachCheckRequest
)


class TestApiEndpoints:
    """RESTful API endpoint integration tests."""

    def test_health_endpoint(self):
        res = health()
        assert res.status == "ok"
        assert res.version == "1.0.0"
        assert len(res.modules) == 5
        assert "password_strength_verifier" in res.modules
        assert "secure_password_generator_csprng" in res.modules
        assert "diceware_passphrase_generator" in res.modules
        assert "totp_two_factor_authentication" in res.modules
        assert "breached_passwords_analysis_hibp" in res.modules

    def test_analyze_endpoint_strong_password(self):
        req = AnalyzeRequest(password="Tr0ub4dor&3!xK9m#", check_breach=False)
        res = analyze(req)
        assert res.score >= 70
        assert res.label in ("strong", "very strong")
        assert res.entropy_bits > 50
        assert res.character_diversity.has_uppercase is True
        assert res.character_diversity.has_lowercase is True
        assert res.character_diversity.has_digits is True
        assert res.character_diversity.has_symbols is True

    def test_analyze_endpoint_weak_password(self):
        req = AnalyzeRequest(password="123456", check_breach=False)
        res = analyze(req)
        assert res.score <= 10
        assert res.label == "very weak"
        assert len(res.suggestions) > 0

    def test_analyze_with_breach_check_mock(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "00000000000000000000000000000000000:1\n"

        with patch("httpx.get", return_value=mock_response):
            req = AnalyzeRequest(password="password", check_breach=True)
            res = analyze(req)
            assert res.breached is not None

    def test_generate_password_endpoint(self):
        req = GenerateRequest(length=22, uppercase=True, lowercase=True, digits=True, symbols=True)
        res = generate(req)
        assert len(res.password) == 22
        assert res.score >= 60
        assert res.entropy_bits > 40
        assert res.crack_time_display is not None

    def test_generate_passphrase_endpoint(self):
        req = PassphraseRequest(num_words=5, separator="-", capitalize="title", include_number=True)
        res = passphrase_endpoint(req)
        assert res.word_count == 5
        assert len(res.words) == 5
        assert res.entropy_bits >= 60.0
        assert res.score >= 70
        assert "Diceware" in res.method

    def test_totp_setup_endpoint(self):
        req = TotpSetupRequest(account_name="student@univ-ouargla.dz", issuer="SecurityApp")
        res = totp_setup(req)
        assert len(res.secret) >= 16
        assert "otpauth://" in res.provisioning_uri
        assert "SecurityApp" in res.provisioning_uri
        assert res.qr_code_base64.startswith("data:image/png;base64,")

    def test_totp_verify_valid_token(self):
        # 1. Setup secret
        setup_res = totp_setup(TotpSetupRequest(account_name="user@test.dz"))
        secret = setup_res.secret

        # 2. Generate current token
        gen_res = totp_generate(TotpGenerateRequest(secret=secret))
        token = gen_res.token

        # 3. Verify
        verify_res = totp_verify(TotpVerifyRequest(secret=secret, token=token))
        assert verify_res.valid is True
        assert verify_res.drift_step == 0
        assert "successfully" in verify_res.message

    def test_totp_verify_invalid_token(self):
        setup_res = totp_setup(TotpSetupRequest(account_name="user@test.dz"))
        secret = setup_res.secret
        verify_res = totp_verify(TotpVerifyRequest(secret=secret, token="000000"))
        # Unless 000000 is coincidentally the current OTP
        gen_res = totp_generate(TotpGenerateRequest(secret=secret))
        if gen_res.token != "000000":
            assert verify_res.valid is False

    def test_breach_check_endpoint(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "ABCDE123456789012345678901234567890:99\n"

        with patch("httpx.get", return_value=mock_response):
            req = BreachCheckRequest(password="secret123")
            res = breach_check_endpoint(req)
            assert len(res.sha1_prefix) == 5
            assert res.k_anonymity is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
