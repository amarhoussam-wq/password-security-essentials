import pytest
from app.generator import generate_password, AMBIGUOUS_CHARS
from app.analyzer import analyze_password


class TestCSPRNGGenerator:
    """Tests for the Cryptographically Secure Random Number Generator (secrets module)."""

    def test_default_generation(self):
        pw = generate_password()
        assert len(pw) == 16
        # Default should include all 4 character classes
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(not c.isalnum() for c in pw)

    def test_custom_lengths(self):
        for length in [8, 12, 20, 32, 64, 128]:
            pw = generate_password(length=length)
            assert len(pw) == length

    def test_length_bounds(self):
        # Minimum 8
        assert len(generate_password(length=4)) == 8
        # Maximum 128
        assert len(generate_password(length=200)) == 128

    def test_exclude_ambiguous(self):
        for _ in range(25):
            pw = generate_password(length=32, exclude_ambiguous=True)
            for amb in AMBIGUOUS_CHARS:
                assert amb not in pw

    def test_digits_only(self):
        pw = generate_password(
            length=14,
            uppercase=False,
            lowercase=False,
            digits=True,
            symbols=False,
        )
        assert len(pw) == 14
        assert pw.isdigit()

    def test_letters_only(self):
        pw = generate_password(
            length=16,
            uppercase=True,
            lowercase=True,
            digits=False,
            symbols=False,
        )
        assert len(pw) == 16
        assert pw.isalpha()
        assert any(c.islower() for c in pw)
        assert any(c.isupper() for c in pw)

    def test_generated_passwords_are_unique(self):
        passwords = {generate_password(length=16) for _ in range(50)}
        # CSPRNG should never produce duplicate 16-char passwords
        assert len(passwords) == 50

    def test_generated_password_high_score(self):
        pw = generate_password(length=20)
        analysis = analyze_password(pw)
        assert analysis["score"] >= 70
        assert analysis["label"] in ("strong", "very strong")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
