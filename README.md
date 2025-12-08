# secret-scan

A fast, lightweight CLI tool to detect secrets in source code.

`secret-scan` scans directories for sensitive data such as:

- AWS Access Keys and Secret Keys
- OpenAI API keys (sk-...)
- Password assignments
- Bearer tokens
- SSH private keys
- Azure storage keys
- Generic API keys and tokens
- JWT tokens

It skips binary files, ignores common junk directories (node_modules, .git, venv, etc.), avoids scanning large files, and supports extensible regular expressions.

## Installation

    pip install secret-scan

To upgrade:

    pip install --upgrade secret-scan

## Basic Usage

Scan the current directory:

    secret-scan .

Scan a specific directory:

    secret-scan ~/projects/my-repo

Write results to a file (default: docsCred.txt):

    secret-scan . --output secrets.txt

## JSON Output

Generate JSON output (useful for CI pipelines):

    secret-scan . --json

Example output:

    [
      {
        "file": "config/settings.py",
        "line": 20,
        "match": "AWS_ACCESS_KEY_ID=AKIA1234567890ABCD12"
      },
      {
        "file": "service/api.py",
        "line": 42,
        "match": "sk-ABCDEFGHIJKLMNOPQRSTUV123456"
      }
    ]

## Command-Line Options

| Flag              | Description                                |
|------------------|--------------------------------------------|
| --output <file>  | Save text results (default: docsCred.txt)   |
| --skip-ext .log  | Skip specific file extensions               |
| --skip-dir <dir> | Skip specific directories                   |
| --max-size-mb N  | Scan only files smaller than N MB           |
| --json           | Print JSON results to stdout                |

Example:

    secret-scan . --skip-ext .log --skip-dir build --json

## What It Detects

### AWS
- Access Key IDs (AKIA...)
- Secret Access Keys
- Environment variable forms such as AWS_ACCESS_KEY_ID=...

### OpenAI
- Keys beginning with sk-

### Passwords and Tokens
- password=...
- api_key=...
- Bearer tokens
- JWT tokens (xxx.yyy.zzz)

### Private Keys
- -----BEGIN PRIVATE KEY-----

### Cloud Provider Keys
- Azure storage account keys
- Redis/MySQL/Postgres/Mongo/FTP/SMTP connection strings

## Automatic Skips

The scanner automatically ignores:

- .git, .hg, .svn
- node_modules
- Python virtual environments (venv, .venv, env)
- Binary files (null-byte detection)
- Large files (over 5 MB by default)
- Common non-text extensions (images, archives, executables)

## Extending Detection Patterns

Detection patterns are defined in:

    src/secret_scanner/patterns.py

You may extend or modify these patterns to detect additional token types.

## Programmatic Usage

Example using the Python API:

    from pathlib import Path
    from secret_scanner import scan_directory

    matches = scan_directory(Path("."), output_path=None)
    for m in matches:
        print(m["file"], m["line"], m["match"])

## Running Tests

    pytest -q

## Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Open a pull request

## License

This project is licensed under the MIT License. See the LICENSE file for full details.

