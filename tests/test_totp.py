import base64
import time
import pytest
from app.totp import (
    generate_secret,
    get_provisioning_uri,
    generate_hotp,
    generate_totp,
    verify_totp,
    generate_qr_code_base64,
    get_remaining_seconds,
)


class TestTOTP:
    """Tests for Two-Factor Authentication (RFC 6238 TOTP / RFC 4226 HOTP)."""

    def test_rfc6238_official_test_vectors(self):
        """
        Verify our implementation matches the exact test vectors in RFC 6238 Appendix B.
        Secret is ASCII '12345678901234567890' (20 bytes).
        """
        secret_ascii = b"12345678901234567890"
        secret_b32 = base64.b32encode(secret_ascii).decode("ascii")

        # Vector 1: T = 59s -> counter = 1 -> HOTP = 287082
        assert generate_totp(secret_b32, timestamp=59) == "287082"

        # Vector 2: T = 1111111109s -> counter = 37037036 -> HOTP = 081804
        assert generate_totp(secret_b32, timestamp=1111111109) == "081804"

        # Vector 3: T = 1111111111s -> counter = 37037037 -> HOTP = 050471
        assert generate_totp(secret_b32, timestamp=1111111111) == "050471"

        # Vector 4: T = 1234567890s -> counter = 41152263 -> HOTP = 005924
        assert generate_totp(secret_b32, timestamp=1234567890) == "005924"

        # Vector 5: T = 2000000000s -> counter = 66666666 -> HOTP = 279037
        assert generate_totp(secret_b32, timestamp=2000000000) == "279037"

    def test_generate_secret(self):
        secret = generate_secret(byte_length=20)
        assert len(secret) == 32  # 20 bytes in Base32 = 32 chars without padding
        # Ensure all chars are valid Base32
        valid_b32 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        assert set(secret).issubset(valid_b32)

    def test_provisioning_uri(self):
        secret = "JBSWY3DPEHPK3PXP"
        uri = get_provisioning_uri(
            secret=secret,
            account_name="student@univ-ouargla.dz",
            issuer="SecurityMicroservice",
        )
        assert uri.startswith("otpauth://totp/")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=SecurityMicroservice" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_qr_code_generation(self):
        uri = "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"
        qr = generate_qr_code_base64(uri)
        assert qr is not None
        assert qr.startswith("data:image/png;base64,")

    def test_verify_totp_current_timestamp(self):
        secret = generate_secret()
        now = time.time()
        token = generate_totp(secret, timestamp=now)
        is_valid, drift = verify_totp(token, secret, timestamp=now)
        assert is_valid is True
        assert drift == 0

    def test_verify_totp_drift_tolerance(self):
        secret = generate_secret()
        now = 1700000000.0  # fixed timestamp

        # Token generated 30 seconds ago (1 step back)
        past_token = generate_totp(secret, timestamp=now - 30)
        is_valid, drift = verify_totp(past_token, secret, timestamp=now, window=1)
        assert is_valid is True
        assert drift == -1

        # Token generated 30 seconds in the future (1 step forward)
        future_token = generate_totp(secret, timestamp=now + 30)
        is_valid, drift = verify_totp(future_token, secret, timestamp=now, window=1)
        assert is_valid is True
        assert drift == 1

        # Token 2 steps back should fail when window=1
        old_token = generate_totp(secret, timestamp=now - 60)
        is_valid, drift = verify_totp(old_token, secret, timestamp=now, window=1)
        assert is_valid is False

    def test_verify_invalid_token(self):
        secret = generate_secret()
        is_valid, _ = verify_totp("000000", secret)
        current = generate_totp(secret)
        if current != "000000":
            assert is_valid is False

        # Malformed input
        assert verify_totp("123", secret)[0] is False
        assert verify_totp("abcdef", secret)[0] is False

    def test_remaining_seconds(self):
        rem = get_remaining_seconds(time_step=30)
        assert 0 < rem <= 30


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
