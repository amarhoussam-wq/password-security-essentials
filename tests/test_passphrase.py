import pytest
from app.passphrase import generate_passphrase, EFF_WORDS, WORDLIST_SIZE, ENTROPY_PER_WORD


class TestPassphraseGenerator:
    """Tests for the Diceware Passphrase Generator (EFF Long Wordlist)."""

    def test_wordlist_size(self):
        """Ensure the full 7,776-word EFF wordlist is loaded."""
        assert WORDLIST_SIZE == 7776
        assert len(EFF_WORDS) == 7776
        assert "abacus" in EFF_WORDS
        assert "zoom" in EFF_WORDS

    def test_default_generation(self):
        result = generate_passphrase()
        assert result["word_count"] == 5
        assert len(result["words"]) == 5
        assert result["entropy_bits"] >= 60.0
        assert result["score"] >= 70
        assert result["label"] in ("strong", "very strong")

    def test_custom_word_count(self):
        for count in [3, 4, 6, 8]:
            result = generate_passphrase(num_words=count)
            assert result["word_count"] == count
            assert len(result["words"]) == count

    def test_word_count_clamped(self):
        # Enforce range [3, 10]
        res_min = generate_passphrase(num_words=1)
        assert res_min["word_count"] == 3

        res_max = generate_passphrase(num_words=20)
        assert res_max["word_count"] == 10

    def test_custom_separator(self):
        for sep in ["-", "_", ".", " "]:
            res = generate_passphrase(num_words=4, separator=sep, include_number=False)
            assert sep in res["passphrase"]
            parts = res["passphrase"].split(sep)
            assert len(parts) == 4

    def test_capitalization_styles(self):
        # TitleCase
        res_title = generate_passphrase(num_words=4, capitalize="title", include_number=False, separator="-")
        for word in res_title["passphrase"].split("-"):
            assert word[0].isupper()

        # UPPERCASE
        res_upper = generate_passphrase(num_words=4, capitalize="upper", include_number=False, separator="-")
        for word in res_upper["passphrase"].split("-"):
            assert word.isupper()

        # lowercase
        res_lower = generate_passphrase(num_words=4, capitalize="lower", include_number=False, separator="-")
        for word in res_lower["passphrase"].split("-"):
            assert word.islower()

    def test_include_number(self):
        res_end = generate_passphrase(num_words=4, include_number=True, number_position="end")
        assert any(c.isdigit() for c in res_end["passphrase"])

        res_start = generate_passphrase(num_words=4, include_number=True, number_position="start")
        assert res_start["passphrase"][0].isdigit()

    def test_entropy_scaling(self):
        res_3 = generate_passphrase(num_words=3, include_number=False)
        res_6 = generate_passphrase(num_words=6, include_number=False)
        assert res_6["entropy_bits"] > res_3["entropy_bits"]
        # Each word adds ~12.92 bits
        assert pytest.approx(res_6["entropy_bits"] - res_3["entropy_bits"], 0.1) == 3 * ENTROPY_PER_WORD

    def test_crack_time_provided(self):
        res = generate_passphrase(num_words=5)
        assert "crack_time_display" in res
        assert len(res["crack_time_display"]) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
