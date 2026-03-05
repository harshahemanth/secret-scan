# tests/test_baseline.py

import json
from pathlib import Path

from secret_scanner.baseline import (
    compute_fingerprint,
    load_baseline,
    save_baseline,
    filter_by_baseline,
)


# ── compute_fingerprint ────────────────────────────────────────────


class TestComputeFingerprint:
    def test_returns_16_hex_chars(self):
        match = {"rule_id": "aws-access-key-id", "match": "AKIA1234567890ABCDEF"}
        fp = compute_fingerprint(match)
        assert len(fp) == 16
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self):
        match = {"rule_id": "aws-access-key-id", "match": "AKIA1234567890ABCDEF"}
        assert compute_fingerprint(match) == compute_fingerprint(match)

    def test_different_match_different_fingerprint(self):
        m1 = {"rule_id": "aws-access-key-id", "match": "AKIA1234567890ABCDEF"}
        m2 = {"rule_id": "aws-access-key-id", "match": "AKIA0000000000XXXXXX"}
        assert compute_fingerprint(m1) != compute_fingerprint(m2)

    def test_different_rule_different_fingerprint(self):
        m1 = {"rule_id": "aws-access-key-id", "match": "AKIA1234567890ABCDEF"}
        m2 = {"rule_id": "generic-secret", "match": "AKIA1234567890ABCDEF"}
        assert compute_fingerprint(m1) != compute_fingerprint(m2)

    def test_position_independent(self):
        """Same rule_id + match text should produce the same fingerprint regardless of file/line."""
        m1 = {"rule_id": "test", "match": "secret123", "file": "a.py", "line": 1}
        m2 = {"rule_id": "test", "match": "secret123", "file": "b.py", "line": 99}
        assert compute_fingerprint(m1) == compute_fingerprint(m2)


# ── load_baseline ──────────────────────────────────────────────────


class TestLoadBaseline:
    def test_load_valid_baseline(self, tmp_path):
        baseline = {
            "version": "1.0",
            "findings": {
                "abc123": {"rule_id": "test"},
                "def456": {"rule_id": "test2"},
            },
        }
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(baseline))
        fps = load_baseline(p)
        assert fps == {"abc123", "def456"}

    def test_missing_file_returns_empty(self, tmp_path):
        fps = load_baseline(tmp_path / "nonexistent.json")
        assert fps == set()

    def test_invalid_json_returns_empty(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("not json")
        fps = load_baseline(p)
        assert fps == set()


# ── save_baseline ──────────────────────────────────────────────────


class TestSaveBaseline:
    def test_creates_file(self, tmp_path):
        matches = [
            {"rule_id": "test", "match": "secret123", "rule_name": "Test", "file": "a.py"},
        ]
        p = tmp_path / "baseline.json"
        save_baseline(matches, p, "0.4.0")
        assert p.exists()

        data = json.loads(p.read_text())
        assert data["version"] == "1.0"
        assert data["tool_version"] == "0.4.0"
        assert len(data["findings"]) == 1

    def test_roundtrip(self, tmp_path):
        """Saved baseline can be loaded and used to filter the same matches."""
        matches = [
            {"rule_id": "test", "match": "secret123", "rule_name": "Test", "file": "a.py"},
        ]
        p = tmp_path / "baseline.json"
        save_baseline(matches, p, "0.4.0")

        fps = load_baseline(p)
        filtered = filter_by_baseline(matches, fps)
        assert filtered == []


# ── filter_by_baseline ─────────────────────────────────────────────


class TestFilterByBaseline:
    def test_removes_known_findings(self):
        matches = [
            {"rule_id": "test", "match": "secret123"},
            {"rule_id": "test", "match": "newsecret"},
        ]
        known_fp = compute_fingerprint(matches[0])
        result = filter_by_baseline(matches, {known_fp})
        assert len(result) == 1
        assert result[0]["match"] == "newsecret"

    def test_empty_baseline_keeps_all(self):
        matches = [{"rule_id": "test", "match": "secret123"}]
        result = filter_by_baseline(matches, set())
        assert len(result) == 1
