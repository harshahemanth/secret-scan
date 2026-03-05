# tests/test_ignore.py

from pathlib import Path

from secret_scanner.ignore import parse_ignorefile, line_has_nosecret_marker, IgnoreRules
from secret_scanner.scanner import scan_directory


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ── parse_ignorefile ─────────────────────────────────────────────────


class TestParseIgnoreFile:
    def test_no_ignorefile_returns_empty(self, tmp_path):
        rules = parse_ignorefile(tmp_path)
        assert rules.file_patterns == []
        assert rules.rule_suppressions == []
        assert rules.match_suppressions == []

    def test_empty_file(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("")
        rules = parse_ignorefile(tmp_path)
        assert rules.file_patterns == []

    def test_comments_and_blanks_ignored(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("# comment\n\n# another\n")
        rules = parse_ignorefile(tmp_path)
        assert rules.file_patterns == []
        assert rules.rule_suppressions == []

    def test_file_pattern(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("tests/fixtures/*.json\n")
        rules = parse_ignorefile(tmp_path)
        assert "tests/fixtures/*.json" in rules.file_patterns

    def test_rule_suppression(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("config/settings.py:generic-secret\n")
        rules = parse_ignorefile(tmp_path)
        assert ("config/settings.py", "generic-secret") in rules.rule_suppressions

    def test_match_suppression(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("!match:EXAMPLE_KEY\n")
        rules = parse_ignorefile(tmp_path)
        assert "EXAMPLE_KEY" in rules.match_suppressions

    def test_multiple_rules(self, tmp_path):
        content = (
            "# Ignore test fixtures\n"
            "tests/fixtures/*.json\n"
            "config/settings.py:generic-secret\n"
            "!match:FAKE_TOKEN\n"
            "docs/**\n"
        )
        (tmp_path / ".secretscanignore").write_text(content)
        rules = parse_ignorefile(tmp_path)
        assert len(rules.file_patterns) == 2
        assert len(rules.rule_suppressions) == 1
        assert len(rules.match_suppressions) == 1


# ── should_ignore_file ───────────────────────────────────────────────


class TestShouldIgnoreFile:
    def test_exact_match(self):
        rules = IgnoreRules(file_patterns=["config/keys.py"])
        assert rules.should_ignore_file("config/keys.py")
        assert not rules.should_ignore_file("config/other.py")

    def test_glob_match(self):
        rules = IgnoreRules(file_patterns=["tests/fixtures/*.json"])
        assert rules.should_ignore_file("tests/fixtures/data.json")
        assert not rules.should_ignore_file("tests/fixtures/data.txt")

    def test_no_patterns_no_match(self):
        rules = IgnoreRules()
        assert not rules.should_ignore_file("anything.py")


# ── should_ignore_match ──────────────────────────────────────────────


class TestShouldIgnoreMatch:
    def test_rule_suppression(self):
        rules = IgnoreRules(rule_suppressions=[("config/*.py", "generic-secret")])
        assert rules.should_ignore_match("config/settings.py", "generic-secret", "secret=foo")
        assert not rules.should_ignore_match("config/settings.py", "aws-access-key-id", "AKIA...")
        assert not rules.should_ignore_match("src/main.py", "generic-secret", "secret=foo")

    def test_match_text_suppression(self):
        rules = IgnoreRules(match_suppressions=["EXAMPLE_KEY"])
        assert rules.should_ignore_match("any.py", "any-rule", "key=EXAMPLE_KEY_123")
        assert not rules.should_ignore_match("any.py", "any-rule", "key=REAL_KEY_123")


# ── line_has_nosecret_marker ─────────────────────────────────────────


class TestNosecretMarker:
    def test_nosecret_with_space(self):
        assert line_has_nosecret_marker("password=test123  # nosecret")

    def test_nosecret_no_space(self):
        assert line_has_nosecret_marker("password=test123  #nosecret")

    def test_no_marker(self):
        assert not line_has_nosecret_marker("password=test123")

    def test_nosecret_in_string_before_comment(self):
        # "nosecret" not in a comment position should not match
        assert not line_has_nosecret_marker('msg = "nosecret"')

    def test_nosecret_case_insensitive(self):
        assert line_has_nosecret_marker("password=test123  # NOSECRET")


# ── Integration: scanner + ignore ────────────────────────────────────


class TestIgnoreIntegration:
    def test_ignored_file_not_scanned(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("secret_config.py\n")
        _write_text(tmp_path / "secret_config.py", "password=shouldbeignored1")
        _write_text(tmp_path / "other.py", "password=shouldbefound12")
        matches = scan_directory(tmp_path, output_path=None)
        assert not any("shouldbeignored" in m["match"] for m in matches)
        assert any("shouldbefound12" in m["match"] for m in matches)

    def test_nosecret_inline_suppression(self, tmp_path):
        _write_text(
            tmp_path / "config.py",
            "password=realpassword123\n"
            "password=fakesecret123  # nosecret\n",
        )
        matches = scan_directory(tmp_path, output_path=None)
        assert any("realpassword" in m["match"] for m in matches)
        assert not any("fakesecret" in m["match"] for m in matches)

    def test_match_text_suppression(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("!match:EXAMPLE_DO_NOT_USE\n")
        _write_text(tmp_path / "config.py", "api_key=EXAMPLE_DO_NOT_USE_12345")
        matches = scan_directory(tmp_path, output_path=None)
        assert not any("EXAMPLE_DO_NOT_USE" in m["match"] for m in matches)

    def test_no_ignore_rules_scans_everything(self, tmp_path):
        (tmp_path / ".secretscanignore").write_text("secret_config.py\n")
        _write_text(tmp_path / "secret_config.py", "password=shouldbefound1")
        # Pass empty rules to disable ignore
        matches = scan_directory(tmp_path, output_path=None, ignore_rules=IgnoreRules())
        assert any("shouldbefound1" in m["match"] for m in matches)
