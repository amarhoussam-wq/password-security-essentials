import hashlib
import unittest
from unittest.mock import patch, MagicMock
import pytest
from app.breach_check import check_breach


class TestBreachCheck:
    """Tests for Breached Passwords Analysis (HIBP k-anonymity API)."""

    def test_sha1_prefix_calculation(self):
        """Verify that the prefix sent to HIBP is exactly 5 hex characters."""
        password = "test_password_123"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        expected_prefix = sha1[:5]

        # Use mock so test does not rely on active internet connection
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "0018A45C4D637E418A4F1D775DE7E565D5E:3\n"

        with patch("httpx.get", return_value=mock_response):
            result = check_breach(password)
            assert result["sha1_prefix"] == expected_prefix
            assert len(result["sha1_prefix"]) == 5
            assert result["k_anonymity"] is True

    def test_breached_match_found(self):
        """Test detection when HIBP returns the matching hash suffix."""
        password = "known_leaked_password"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        # Mock API returning the exact matching suffix with 42 breaches
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\n{suffix}:42\n"

        with patch("httpx.get", return_value=mock_response):
            result = check_breach(password)
            assert result["breached"] is True
            assert result["breach_count"] == 42
            assert result["sha1_prefix"] == prefix
            assert "Compromised" in result["message"]

    def test_breached_no_match(self):
        """Test safe password where suffix is absent from HIBP range response."""
        password = "highly_unique_unbreached_pw_99!"
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "11111111111111111111111111111111111:5\n22222222222222222222222222222222222:10\n"

        with patch("httpx.get", return_value=mock_response):
            result = check_breach(password)
            assert result["breached"] is False
            assert result["breach_count"] == 0
            assert "Safe" in result["message"]

    def test_empty_password_handled(self):
        result = check_breach("")
        assert result["breached"] is False
        assert result["breach_count"] == 0

    def test_network_failure_gracefully_handled(self):
        """Simulate network timeout / DNS failure."""
        import httpx
        with patch("httpx.get", side_effect=httpx.ConnectTimeout("Connection timed out")):
            result = check_breach("any_password")
            assert result["breached"] is None
            assert result["breach_count"] is None
            assert "External breach check skipped" in result["message"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
