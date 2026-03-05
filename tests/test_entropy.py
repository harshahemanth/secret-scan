# tests/test_entropy.py

import json
import pytest
from pathlib import Path

from secret_scanner.entropy import (
    shannon_entropy,
    scan_line_entropy,
    MIN_STRING_LENGTH,
    HEX_ENTROPY_THRESHOLD,
    BASE64_ENTROPY_THRESHOLD,
)
from secret_scanner.cli import run, parse_args


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ── Shannon entropy ─────────────────────────────────────────────────


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        # "ab" -> H = 1.0
        assert abs(shannon_entropy("ab") - 1.0) < 0.001

    def test_high_entropy_random(self):
        # A string with many distinct chars should have high entropy
        s = "a1b2c3d4e5f6g7h8i9j0"
        assert shannon_entropy(s) > 3.5

    def test_low_entropy_repeated(self):
        s = "aaaaaabbbbbb"
        assert shannon_entropy(s) < 1.5


# ── Token classification and scanning ───────────────────────────────


class TestScanLineEntropy:
    def test_detects_high_entropy_hex(self):
        # 40-char hex string with high entropy
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        line = f"key={token}"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 1
        assert results[0]["rule_id"] == "high-entropy-hex"
        assert results[0]["match"] == token
        assert results[0]["severity"] == "warning"
        assert results[0]["line"] == 1

    def test_detects_high_entropy_base64(self):
        # High-entropy base64 string
        token = "dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWUK"
        line = f"secret={token}"
        results = scan_line_entropy(line, "test.py", 1)
        hex_or_b64 = [r for r in results if r["rule_id"] in ("high-entropy-hex", "high-entropy-base64")]
        assert len(hex_or_b64) >= 1

    def test_ignores_short_strings(self):
        line = "key=abc123"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 0

    def test_ignores_low_entropy_hex(self):
        # All same chars -> zero entropy
        token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        line = f"key={token}"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 0

    def test_ignores_uuid(self):
        line = "id=550e8400-e29b-41d4-a716-446655440000"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 0

    def test_ignores_css_color(self):
        line = "color: #1a2b3c4d5e6f7a8b"
        results = scan_line_entropy(line, "test.py", 1)
        # CSS colors with # prefix are filtered
        css_matches = [r for r in results if r["match"].startswith("#")]
        assert len(css_matches) == 0

    def test_ignores_version_string(self):
        line = "version=v1.2.3.4.5.6.7.8.9.0.1.2"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 0

    def test_ignores_lockfile_hash_prefix(self):
        line = "sha256-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 0

    def test_ignores_repeated_chars(self):
        token = "aabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        line = f"key={token}"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 0

    def test_skips_lockfile(self):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        line = f"hash={token}"
        results = scan_line_entropy(line, "package-lock.json", 1)
        assert len(results) == 0

    def test_skips_yarn_lock(self):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        line = f"hash={token}"
        results = scan_line_entropy(line, "yarn.lock", 1)
        assert len(results) == 0

    def test_match_dict_shape(self):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        line = f"key={token}"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 1
        record = results[0]
        assert set(record.keys()) == {
            "file", "line", "match", "rule_id", "rule_name",
            "severity", "column", "end_column",
        }

    def test_column_positions(self):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        prefix = "mykey="
        line = f"{prefix}{token}"
        results = scan_line_entropy(line, "test.py", 1)
        assert len(results) == 1
        assert results[0]["column"] == len(prefix)
        assert results[0]["end_column"] == len(prefix) + len(token)


# ── Integration with scanner ────────────────────────────────────────


class TestEntropyIntegration:
    def test_entropy_flag_produces_findings(self, tmp_path, capsys):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        _write_text(tmp_path / "config.txt", f"secret_key={token}")
        code = run([str(tmp_path), "--json", "--entropy", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        entropy_matches = [m for m in data if m["rule_id"].startswith("high-entropy-")]
        assert len(entropy_matches) >= 1

    def test_no_entropy_flag_no_entropy_findings(self, tmp_path, capsys):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        _write_text(tmp_path / "config.txt", f"hex_value={token}")
        run([str(tmp_path), "--json", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        entropy_matches = [m for m in data if m["rule_id"].startswith("high-entropy-")]
        assert len(entropy_matches) == 0

    def test_entropy_respects_nosecret(self, tmp_path, capsys):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        _write_text(tmp_path / "config.txt", f"key={token}  # nosecret")
        run([str(tmp_path), "--json", "--entropy", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 0

    def test_entropy_respects_secretscanignore(self, tmp_path, capsys):
        token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        _write_text(tmp_path / "config.txt", f"key={token}")
        _write_text(tmp_path / ".secretscanignore", "config.txt")
        run([str(tmp_path), "--json", "--entropy", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 0

    def test_entropy_skips_regex_matched_spans(self, tmp_path, capsys):
        # AKIA key is already matched by regex, entropy should not duplicate it
        _write_text(tmp_path / "config.txt", "AKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--entropy", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        rule_ids = [m["rule_id"] for m in data]
        # Should have the regex match, not an entropy duplicate
        assert "aws-access-key-id" in rule_ids
        entropy_dupes = [r for r in rule_ids if r.startswith("high-entropy-")]
        # The AKIA key is only 20 chars of hex, which is exactly at MIN_STRING_LENGTH
        # but the span dedup should prevent double-reporting regardless
        assert len(entropy_dupes) == 0


# ── CLI flag parsing ────────────────────────────────────────────────


class TestEntropyCliFlag:
    def test_entropy_flag_parsed(self):
        args = parse_args(["/some/path", "--entropy"])
        assert args.entropy

    def test_entropy_flag_default_false(self):
        args = parse_args(["/some/path"])
        assert not args.entropy
