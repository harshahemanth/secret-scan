# tests/test_redact.py

from secret_scanner.redact import redact_match, redact_matches


# ── redact_match ────────────────────────────────────────────────────


class TestRedactMatch:
    def test_empty_string(self):
        assert redact_match("") == "****"

    def test_short_string_1_char(self):
        assert redact_match("x") == "****"

    def test_short_string_8_chars(self):
        assert redact_match("12345678") == "****"

    def test_medium_string_9_chars(self):
        result = redact_match("123456789")
        assert result == "12****89"

    def test_medium_string_11_chars(self):
        result = redact_match("12345678901")
        assert result == "12****01"

    def test_long_string_12_chars(self):
        result = redact_match("123456789012")
        assert result == "1234****9012"

    def test_long_string_20_chars(self):
        text = "AKIA1234567890ABCDEF"
        result = redact_match(text)
        assert result == "AKIA****CDEF"

    def test_preserves_prefix_suffix(self):
        text = "sk_live_abcdefghijklmnop"
        result = redact_match(text)
        assert result.startswith("sk_l")
        assert result.endswith("mnop")
        assert "****" in result


# ── redact_matches ──────────────────────────────────────────────────


class TestRedactMatches:
    def test_returns_new_list(self):
        original = [{"match": "AKIA1234567890ABCDEF", "file": "test.py"}]
        result = redact_matches(original)
        assert result is not original
        assert result[0] is not original[0]

    def test_original_unchanged(self):
        original = [{"match": "AKIA1234567890ABCDEF", "file": "test.py"}]
        redact_matches(original)
        assert original[0]["match"] == "AKIA1234567890ABCDEF"

    def test_match_field_redacted(self):
        original = [{"match": "AKIA1234567890ABCDEF", "file": "test.py"}]
        result = redact_matches(original)
        assert result[0]["match"] == "AKIA****CDEF"
        assert result[0]["file"] == "test.py"

    def test_empty_list(self):
        assert redact_matches([]) == []
