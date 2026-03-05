# src/secret_scanner/entropy.py

"""Entropy-based secret detection for high-entropy hex and base64 strings."""

from __future__ import annotations

import math
import re
import os

MIN_STRING_LENGTH = 20
HEX_ENTROPY_THRESHOLD = 3.0
BASE64_ENTROPY_THRESHOLD = 4.5

# Tokenizer: split on whitespace, quotes, =, :, ;, commas, brackets, braces
_TOKEN_RE = re.compile(r"""[^\s"'=:;,\[\]\(\)\{\}<>]+""")

# Classification patterns
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')

# False positive patterns
_UUID_RE = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)
_CSS_COLOR_RE = re.compile(r'^#[0-9a-fA-F]{3,8}$')
_VERSION_RE = re.compile(r'^v?\d+\.\d+')
_LOCKFILE_HASH_PREFIX_RE = re.compile(r'^sha(?:1|256|384|512)-', re.IGNORECASE)

# Lockfile basenames where hashes are expected
_LOCKFILE_NAMES = frozenset({
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'Pipfile.lock',
    'poetry.lock',
    'composer.lock',
    'Gemfile.lock',
    'Cargo.lock',
})


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of a string."""
    if not s:
        return 0.0
    length = len(s)
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_repeated(s: str) -> bool:
    """Check if a string is just repeated characters (e.g. 'AAAAAA...')."""
    return len(set(s)) <= 2


def _is_false_positive(token: str) -> bool:
    """Return True if the token matches a known false positive pattern."""
    if _UUID_RE.match(token):
        return True
    if _CSS_COLOR_RE.match(token):
        return True
    if _VERSION_RE.match(token):
        return True
    if _LOCKFILE_HASH_PREFIX_RE.match(token):
        return True
    if _is_repeated(token):
        return True
    return False


def _is_lockfile(file_path: str) -> bool:
    """Check if the file is a known lockfile where hashes are expected."""
    basename = os.path.basename(file_path)
    return basename in _LOCKFILE_NAMES


def scan_line_entropy(
    line: str, file_path: str, lineno: int
) -> list[dict]:
    """Scan a single line for high-entropy hex/base64 tokens.

    Returns a list of match dicts with the same shape as the regex scanner.
    """
    if _is_lockfile(file_path):
        return []

    results: list[dict] = []

    for m in _TOKEN_RE.finditer(line):
        token = m.group(0)

        if len(token) < MIN_STRING_LENGTH:
            continue

        if _is_false_positive(token):
            continue

        column = m.start()
        end_column = m.end()

        # Classify and check entropy
        if _HEX_RE.match(token):
            entropy = shannon_entropy(token)
            if entropy >= HEX_ENTROPY_THRESHOLD:
                results.append({
                    "file": file_path,
                    "line": lineno,
                    "match": token,
                    "rule_id": "high-entropy-hex",
                    "rule_name": "High Entropy Hex String",
                    "severity": "warning",
                    "column": column,
                    "end_column": end_column,
                })
        elif _BASE64_RE.match(token):
            entropy = shannon_entropy(token)
            if entropy >= BASE64_ENTROPY_THRESHOLD:
                results.append({
                    "file": file_path,
                    "line": lineno,
                    "match": token,
                    "rule_id": "high-entropy-base64",
                    "rule_name": "High Entropy Base64 String",
                    "severity": "warning",
                    "column": column,
                    "end_column": end_column,
                })

    return results
