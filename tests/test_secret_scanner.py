# tests/test_secret_scanner.py

from pathlib import Path

from secret_scanner.scanner import scan_directory, DEFAULT_SKIP_DIRS
from secret_scanner.patterns import build_pattern


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_binary(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(content)


def test_skips_default_junk_dirs(tmp_path: Path):
    """
    Files under junk dirs like node_modules should be skipped,
    but regular app files should be scanned.
    """
    # Junk dir with a "secret"
    junk_dir = tmp_path / "node_modules"
    junk_file = junk_dir / "secret.js"
    _write_text(junk_file, "password=supersecretjunk")

    # Normal app file with a "secret"
    app_dir = tmp_path / "app"
    app_file = app_dir / "config.py"
    _write_text(app_file, "password=mygoodsecret")

    output_file = tmp_path / "out.txt"
    matches = scan_directory(tmp_path, output_file)

    # Should find the secret in app/config.py
    assert any("mygoodsecret" in m["match"] for m in matches)

    # Should NOT report the one under node_modules
    assert not any("supersecretjunk" in m["match"] for m in matches)


def test_skips_binary_files(tmp_path: Path):
    """
    Binary files (with null bytes) should be skipped even if they contain
    credential-looking strings.
    """
    text_file = tmp_path / "config.txt"
    _write_text(text_file, "password=plaintextsecret")

    bin_file = tmp_path / "binary.dat"
    # Contains a null byte and a password-looking string
    _write_binary(bin_file, b"\x00\x01\x02password=binarysecret")

    output_file = tmp_path / "out.txt"
    matches = scan_directory(tmp_path, output_file)

    # Should detect the secret in the text file
    assert any("plaintextsecret" in m["match"] for m in matches)

    # Should NOT detect the binarysecret
    assert not any("binarysecret" in m["match"] for m in matches)


def test_respects_extra_skip_ext(tmp_path: Path):
    """
    Additional skip extensions passed to scan_directory should be honored.
    """
    # .log file with secret
    log_file = tmp_path / "app.log"
    _write_text(log_file, "password=logsecret")

    # .txt file with secret
    txt_file = tmp_path / "config.txt"
    _write_text(txt_file, "password=txtsecret")

    # First scan: default behavior, .log is NOT skipped
    output_file1 = tmp_path / "out1.txt"
    matches1 = scan_directory(tmp_path, output_file1)
    assert any("logsecret" in m["match"] and m["file"] == str(log_file) for m in matches1)
    assert any("txtsecret" in m["match"] and m["file"] == str(txt_file) for m in matches1)

    # Second scan: explicitly skip .log files
    output_file2 = tmp_path / "out2.txt"
    matches2 = scan_directory(tmp_path, output_file2, skip_exts={".log"})

    # Should still see txtsecret from config.txt
    assert any("txtsecret" in m["match"] and m["file"] == str(txt_file) for m in matches2)

    # Should NOT see logsecret coming from app.log
    assert not any("logsecret" in m["match"] and m["file"] == str(log_file) for m in matches2)


def test_uses_default_regex_pattern(tmp_path: Path):
    """
    Sanity check that the default regex pattern is actually used and
    recognizes a common password pattern.
    """
    file_path = tmp_path / "test.txt"
    _write_text(file_path, "password=mydefaultpatternsecret")

    output_file = tmp_path / "out.txt"
    matches = scan_directory(tmp_path, output_file, pattern=build_pattern())

    assert any("mydefaultpatternsecret" in m["match"] for m in matches)


def test_detects_aws_access_key(tmp_path: Path):
    """
    Ensure AWS access key IDs are detected.
    AWS Access Key ID: AKIA + 16 uppercase alnum chars (total 20).
    """
    file_path = tmp_path / "aws.txt"
    fake_key = "AKIA1234567890ABCD12"  # 4 + 16 = 20 chars
    _write_text(file_path, f"AWS_ACCESS_KEY_ID={fake_key}")

    output_file = tmp_path / "out.txt"
    matches = scan_directory(tmp_path, output_file)

    assert any(fake_key in m["match"] for m in matches)


def test_detects_openai_key(tmp_path: Path):
    """
    Ensure OpenAI API keys (sk-...) are detected.
    """
    file_path = tmp_path / "openai.txt"
    fake_key = "sk-ABCDEFGHIJKLMNOPQRSTUV123456"
    _write_text(file_path, f'OPENAI_API_KEY="{fake_key}"')

    output_file = tmp_path / "out.txt"
    matches = scan_directory(tmp_path, output_file)

    assert any(fake_key in m["match"] for m in matches)

