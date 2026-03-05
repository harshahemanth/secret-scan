# tests/test_cli.py

import json
import pytest
from pathlib import Path

from secret_scanner.cli import run, parse_args


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ── Exit codes ───────────────────────────────────────────────────────


class TestExitCodes:
    def test_exit_code_1_when_secrets_found(self, tmp_path):
        _write_text(tmp_path / "test.txt", "password=supersecret123")
        code = run([str(tmp_path), "--output", str(tmp_path / "out.txt")])
        assert code == 1

    def test_exit_code_0_when_no_secrets(self, tmp_path):
        _write_text(tmp_path / "test.txt", "nothing suspicious here")
        code = run([str(tmp_path), "--output", str(tmp_path / "out.txt")])
        assert code == 0

    def test_no_fail_always_returns_0(self, tmp_path):
        _write_text(tmp_path / "test.txt", "password=supersecret123")
        code = run([str(tmp_path), "--output", str(tmp_path / "out.txt"), "--no-fail"])
        assert code == 0


# ── JSON output ──────────────────────────────────────────────────────


class TestJsonOutput:
    def test_json_output_includes_rule_id(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "AKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) >= 1
        assert "rule_id" in data[0]
        assert "severity" in data[0]

    def test_json_output_has_enriched_fields(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "password=mysuperpassword1")
        run([str(tmp_path), "--json", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        record = data[0]
        assert "file" in record
        assert "line" in record
        assert "match" in record
        assert "rule_id" in record
        assert "rule_name" in record
        assert "severity" in record
        assert "column" in record
        assert "end_column" in record
        assert "fingerprint" in record
        assert len(record["fingerprint"]) == 16


# ── SARIF output ─────────────────────────────────────────────────────


class TestSarifOutput:
    def test_sarif_output_structure(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "AKIA1234567890ABCDEF")
        run([str(tmp_path), "--sarif", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        sarif = json.loads(captured.out)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "secret-scan"

    def test_sarif_and_json_mutually_exclusive(self):
        with pytest.raises(SystemExit):
            parse_args(["/some/path", "--sarif", "--json"])


# ── Argument parsing ─────────────────────────────────────────────────


class TestParseArgs:
    def test_default_args(self):
        args = parse_args(["/some/path"])
        assert args.path == "/some/path"
        assert args.output == "docsCred.txt"
        assert not args.json
        assert not args.sarif

    def test_no_fail_flag(self):
        args = parse_args(["/some/path", "--no-fail"])
        assert args.no_fail

    def test_no_ignore_flag(self):
        args = parse_args(["/some/path", "--no-ignore"])
        assert args.no_ignore

    def test_skip_dir_multiple(self):
        args = parse_args(["/some/path", "--skip-dir", "logs", "--skip-dir", "tmp"])
        assert "logs" in args.skip_dir
        assert "tmp" in args.skip_dir

    def test_skip_ext_multiple(self):
        args = parse_args(["/some/path", "--skip-ext", ".log", "--skip-ext", ".tmp"])
        assert ".log" in args.skip_ext
        assert ".tmp" in args.skip_ext

    def test_severity_flag(self):
        args = parse_args(["/some/path", "--severity", "error"])
        assert args.severity == "error"

    def test_severity_default_none(self):
        args = parse_args(["/some/path"])
        assert args.severity is None

    def test_version_flag(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--version"])
        assert exc_info.value.code == 0


# ── Severity filter ─────────────────────────────────────────────────


class TestSeverityFilter:
    def test_severity_error_filters_warnings(self, tmp_path, capsys):
        # password= is "warning", AKIA is "error"
        _write_text(tmp_path / "test.txt", "password=supersecret123\nAKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--severity", "error", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        for record in data:
            assert record["severity"] == "error"

    def test_severity_warning_includes_warnings_and_errors(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "password=supersecret123\nAKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--severity", "warning", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        severities = {r["severity"] for r in data}
        assert "note" not in severities

    def test_no_severity_returns_all(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "password=supersecret123\nAKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) >= 2


# ── Redaction ──────────────────────────────────────────────────────


class TestRedaction:
    def test_json_output_redacted_by_default(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "AKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) >= 1
        # Must not contain the full key
        assert "AKIA1234567890ABCDEF" not in data[0]["match"]
        assert "****" in data[0]["match"]

    def test_no_redact_shows_full_value(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "AKIA1234567890ABCDEF")
        run([str(tmp_path), "--json", "--no-redact", "--output", str(tmp_path / "out.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "AKIA1234567890ABCDEF" in data[0]["match"]

    def test_no_redact_flag_parsed(self):
        args = parse_args(["/some/path", "--no-redact"])
        assert args.no_redact

    def test_redact_default_false(self):
        args = parse_args(["/some/path"])
        assert not args.no_redact


# ── Baseline ───────────────────────────────────────────────────────


class TestBaselineCLI:
    def test_save_baseline_creates_file(self, tmp_path):
        _write_text(tmp_path / "test.txt", "AKIA1234567890ABCDEF")
        baseline_path = tmp_path / "baseline.json"
        run([str(tmp_path), "--save-baseline", str(baseline_path), "--output", str(tmp_path / "out.txt")])
        assert baseline_path.exists()
        data = json.loads(baseline_path.read_text())
        assert "findings" in data
        assert len(data["findings"]) >= 1

    def test_baseline_suppresses_known(self, tmp_path, capsys):
        _write_text(tmp_path / "test.txt", "AKIA1234567890ABCDEF")
        baseline_path = tmp_path / "baseline.json"
        # Save baseline
        run([str(tmp_path), "--save-baseline", str(baseline_path), "--output", str(tmp_path / "out.txt")])
        # Scan with baseline — known finding suppressed
        code = run([str(tmp_path), "--json", "--baseline", str(baseline_path), "--output", str(tmp_path / "out2.txt")])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 0
        assert code == 0

    def test_baseline_flag_parsed(self):
        args = parse_args(["/some/path", "--baseline", "file.json"])
        assert args.baseline == "file.json"

    def test_save_baseline_flag_parsed(self):
        args = parse_args(["/some/path", "--save-baseline", "file.json"])
        assert args.save_baseline == "file.json"


# ── Diff mode ──────────────────────────────────────────────────────


class TestDiffCLI:
    def test_diff_flag_parsed(self):
        args = parse_args(["/some/path", "--diff", "main"])
        assert args.diff == "main"

    def test_diff_default_none(self):
        args = parse_args(["/some/path"])
        assert args.diff is None

    def test_diff_git_error_returns_2(self, tmp_path):
        """Diff mode in a non-git directory should return exit code 2."""
        _write_text(tmp_path / "test.txt", "nothing here")
        code = run([str(tmp_path), "--diff", "main", "--output", str(tmp_path / "out.txt")])
        assert code == 2
