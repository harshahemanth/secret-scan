# secret-scan

[![PyPI version](https://img.shields.io/pypi/v/secret-scan)](https://pypi.org/project/secret-scan/)
[![PyPI downloads](https://img.shields.io/pypi/dm/secret-scan)](https://pypi.org/project/secret-scan/)
[![CI](https://github.com/harshahemanth/secret-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/harshahemanth/secret-scan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/secret-scan)](https://pypi.org/project/secret-scan/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Secret%20Scan-blue?logo=github)](https://github.com/marketplace/actions/secret-scan-action)

A fast, lightweight CLI tool to detect secrets in source code. Zero dependencies — stdlib only.

<!-- TODO: Replace with actual recording
![demo](assets/demo.gif)
-->

`secret-scan` scans directories for sensitive data such as:

- AWS Access Keys and Secret Keys
- GitHub tokens (PAT, OAuth, App, fine-grained)
- Slack tokens (bot, user)
- Stripe keys (live and test)
- Google API keys
- OpenAI API keys
- npm and PyPI tokens
- Twilio and SendGrid API keys
- Heroku and HashiCorp Vault tokens
- Passwords, Bearer tokens, and JWTs
- SSH/RSA/PGP private keys
- Azure storage keys
- Database connection strings

It skips binary files, ignores common junk directories (node_modules, .git, venv, etc.), avoids scanning large files, and supports extensible detection rules.

## Installation

    pip install secret-scan

To upgrade:

    pip install --upgrade secret-scan

Check version:

    secret-scan --version

## Quick Start

```bash
# Scan current directory
secret-scan .

# Only show high-confidence findings
secret-scan . --severity error

# JSON output for scripting
secret-scan . --json

# SARIF output for GitHub/GitLab integration
secret-scan . --sarif > results.sarif

# Advisory mode (always exit 0)
secret-scan . --no-fail
```

## GitHub Action (Marketplace)

The easiest way to add secret scanning to your CI — no pip install needed:

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: harshahemanth/secret-scan@v1
```

### SARIF + Code Scanning

Upload results to GitHub's Security tab:

```yaml
name: Secret Scan

on: [push, pull_request]

permissions:
  security-events: write

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: harshahemanth/secret-scan@v1
        id: scan
        with:
          sarif: "true"
          no-fail: "true"

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` |
| `severity` | Minimum severity: error, warning, or note | (all) |
| `sarif` | Output SARIF format | `false` |
| `no-fail` | Always exit 0 (advisory mode) | `false` |
| `entropy` | Enable entropy-based detection | `false` |
| `no-redact` | Show full secret values in output | `false` |
| `baseline` | Path to baseline file to suppress known findings | |
| `save-baseline` | Save findings as a baseline file | |
| `diff` | Only scan files changed since this git ref | |
| `extra-args` | Additional CLI arguments | |

### Action Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to SARIF file (when `sarif=true`) |
| `exit-code` | Scanner exit code (0=clean, 1=secrets found, 2=git error) |

## CI/CD Integration

### GitHub Actions (manual install)

Add this to `.github/workflows/secret-scan.yml`:

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install secret-scan
        run: pip install secret-scan

      - name: Scan for secrets
        run: secret-scan . --output /dev/null
```

The scanner exits with code 1 if secrets are found, which will fail the workflow.

### GitHub Actions with SARIF (Code Scanning)

Upload results to GitHub's Security tab:

```yaml
name: Secret Scan

on: [push, pull_request]

permissions:
  security-events: write

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install secret-scan
        run: pip install secret-scan

      - name: Scan for secrets
        run: secret-scan . --sarif --no-fail --output /dev/null > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
secret-scan:
  image: python:3.12-slim
  script:
    - pip install secret-scan
    - secret-scan . --output /dev/null
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/harshahemanth/secret-scan
    rev: v0.4.1
    hooks:
      - id: secret-scan
```

Or use a local install:

```yaml
repos:
  - repo: local
    hooks:
      - id: secret-scan
        name: secret-scan
        entry: secret-scan
        args: ['.', '--output', '/dev/null']
        language: python
        additional_dependencies: ['secret-scan']
        pass_filenames: false
```

## Redaction

By default, secret values are masked in all output (JSON, SARIF, text file) to prevent credential leaks in CI logs. Use `--no-redact` to show full values:

```bash
# Default: secrets are redacted
secret-scan . --json
# Output: "match": "AKIA****CDEF"

# Show full values
secret-scan . --json --no-redact
# Output: "match": "AKIA1234567890ABCDEF"
```

Redaction rules:
- 8 chars or less: `****`
- 9-11 chars: first 2 + `****` + last 2
- 12+ chars: first 4 + `****` + last 4

## Baseline

Save known findings to a baseline file and suppress them in future scans. This enables incremental adoption — acknowledge existing secrets and only fail on new ones:

```bash
# Save current findings as baseline
secret-scan . --save-baseline .baseline.json

# Future scans suppress known findings
secret-scan . --baseline .baseline.json

# Combine with other flags
secret-scan . --baseline .baseline.json --severity error --json
```

The baseline uses position-independent fingerprints (rule ID + match text), so findings are still suppressed even if they move to different lines or files.

## Diff Mode

Only scan files changed since a git ref — ideal for fast CI on pull requests:

```bash
# Scan only files changed vs main
secret-scan . --diff main

# Scan changes in last 3 commits
secret-scan . --diff HEAD~3

# Combine with baseline for incremental PR scanning
secret-scan . --diff main --baseline .baseline.json --json
```

Exit code `2` indicates a git error (not a repo, invalid ref, git not installed).

## Exit Codes

| Exit Code | Meaning              |
|-----------|----------------------|
| 0         | No secrets found     |
| 1         | Secrets were found   |
| 2         | Git error (diff mode)|

Use `--no-fail` to always exit with 0 (advisory mode):

    secret-scan . --no-fail

## Severity Filter

Each finding has a severity: `error` (high confidence), `warning` (medium), or `note` (low).

Filter to only show high-confidence findings:

    secret-scan . --severity error

Show errors and warnings (exclude notes):

    secret-scan . --severity warning

## JSON Output

Generate JSON output (useful for CI pipelines):

    secret-scan . --json

Example output:

    [
      {
        "file": "config/settings.py",
        "line": 20,
        "match": "AWS_****CD12",
        "rule_id": "aws-access-key-assignment",
        "rule_name": "AWS Access Key Assignment",
        "severity": "error",
        "column": 0,
        "end_column": 42,
        "fingerprint": "a1b2c3d4e5f6a7b8"
      }
    ]

## SARIF Output

Generate SARIF v2.1.0 output for integration with GitHub Code Scanning, GitLab SAST, and other security tools:

    secret-scan . --sarif

## Suppressing False Positives

### .secretscanignore

Create a `.secretscanignore` file in your project root to suppress known false positives:

    # Ignore entire files or directories
    tests/fixtures/*.json
    docs/**

    # Ignore a specific rule for a specific file
    config/settings.py:generic-secret

    # Ignore matches containing specific text
    !match:EXAMPLE_KEY_DO_NOT_USE

### Inline suppression

Add `# nosecret` to any line to suppress detection on that line:

```python
DEFAULT_KEY = "sk-placeholder-not-real"  # nosecret
```

Use `--no-ignore` to bypass all suppression rules:

    secret-scan . --no-ignore

## Command-Line Options

| Flag                        | Description                                      |
|-----------------------------|--------------------------------------------------|
| -v, --version               | Show version and exit                            |
| -o, --output \<file\>       | Save text results (default: docsCred.txt)        |
| --skip-ext .log             | Skip specific file extensions                    |
| --skip-dir \<dir\>          | Skip specific directories                        |
| --max-size-mb N             | Scan only files smaller than N MB                |
| --severity \<level\>        | Minimum severity: error, warning, or note        |
| --json                      | Print JSON results to stdout                     |
| --sarif                     | Print SARIF v2.1.0 results to stdout             |
| --no-fail                   | Always exit 0 even if secrets are found          |
| --no-ignore                 | Do not read .secretscanignore file               |
| --entropy                   | Enable entropy-based detection (opt-in)          |
| --no-redact                 | Show full secret values in output                |
| --baseline \<file\>         | Suppress findings matching a baseline file       |
| --save-baseline \<file\>    | Save current findings as a baseline file         |
| --diff \<ref\>              | Only scan files changed since a git ref          |

## What It Detects

Each detection rule has a unique `rule_id` and a severity level (`error`, `warning`, or `note`).

### Cloud Providers
| Provider | What | Severity |
|----------|------|----------|
| AWS | Access Key IDs (AKIA...), Secret Access Keys | error |
| Azure | Storage account keys, Account keys | error |
| Google | API keys (AIza...) | error |
| Heroku | API key assignments | error |
| HashiCorp Vault | Service tokens (hvs.) | error |

### SaaS / API Platforms
| Provider | What | Severity |
|----------|------|----------|
| GitHub | PAT, OAuth, App, Refresh, Fine-grained tokens | error |
| Slack | Bot tokens (xoxb-), User tokens (xoxp-) | error |
| Stripe | Live secret/publishable/restricted keys | error/warning |
| Stripe | Test keys | note |
| OpenAI | API keys (sk-) | error |
| Twilio | API keys (SK...) | error |
| SendGrid | API keys (SG.) | error |
| npm | Access tokens | error |
| PyPI | API tokens | error |

### Generic Patterns
| What | Severity |
|------|----------|
| Password assignments (password=, passwd=, pwd=) | warning |
| Bearer tokens | error |
| JWT tokens | warning |
| API key/token assignments | warning |
| Private key blocks (PEM headers) | error |
| SSH RSA public keys | note |
| Database connection strings | warning |
| Generic secret assignments | warning |

## Entropy-Based Detection

Use `--entropy` to detect high-entropy hex and base64 strings that don't match any known pattern. This catches secrets that slip through regex-based rules.

```bash
secret-scan . --entropy
secret-scan . --entropy --json
```

This is **opt-in** to avoid false positive noise. When enabled, the scanner tokenizes each line and computes Shannon entropy for candidate strings.

**Thresholds:**

| Type | Min Length | Entropy Threshold |
|------|-----------|-------------------|
| Hex strings | 20 chars | 3.0 bits/char |
| Base64 strings | 20 chars | 4.5 bits/char |

**Automatically excluded (false positive filters):**

- UUIDs (`550e8400-e29b-41d4-a716-446655440000`)
- CSS hex colors (`#1a2b3c`)
- Version strings (`v1.2.3...`)
- Lockfile hashes (`sha256-...`, `sha512-...`)
- Repeated characters (`AAAAAA...`)
- Entire lockfiles (`package-lock.json`, `yarn.lock`, etc.)

Entropy findings use rule IDs `high-entropy-hex` and `high-entropy-base64`, both at severity `warning`. They respect `# nosecret` inline suppression and `.secretscanignore` rules.

## Automatic Skips

The scanner automatically ignores:

- .git, .hg, .svn
- node_modules
- Python virtual environments (venv, .venv, env)
- IDE directories (.idea, .vscode)
- Binary files (null-byte detection)
- Large files (over 5 MB by default)
- Common non-text extensions (images, archives, executables)

## Extending Detection Patterns

Detection patterns are defined as `SecretPattern` dataclass instances in:

    src/secret_scanner/patterns.py

Each pattern has a `rule_id`, `name`, `severity`, `pattern` (regex), and `description`. You can add new patterns by appending to the `PATTERNS` list.

## Programmatic Usage

```python
from pathlib import Path
from secret_scanner import scan_directory

matches = scan_directory(Path("."), output_path=None)
for m in matches:
    print(f"[{m['severity']}] {m['rule_name']}: {m['file']}:{m['line']}")
```

## Running Tests

    PYTHONPATH=src pytest tests/ -q

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Open a pull request

## License

This project is licensed under the MIT License. See the LICENSE file for full details.
