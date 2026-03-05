# src/secret_scanner/ignore.py

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

IGNORE_FILENAME = ".secretscanignore"
NOSECRET_MARKER = "nosecret"


@dataclass
class IgnoreRules:
    """Collection of ignore rules parsed from .secretscanignore."""

    file_patterns: list[str] = field(default_factory=list)
    rule_suppressions: list[tuple[str, str]] = field(default_factory=list)
    match_suppressions: list[str] = field(default_factory=list)

    def should_ignore_file(self, rel_path: str) -> bool:
        """Check if a file should be entirely skipped."""
        for pattern in self.file_patterns:
            if _match_path(rel_path, pattern):
                return True
        return False

    def should_ignore_match(self, rel_path: str, rule_id: str, match_text: str) -> bool:
        """Check if a specific match should be suppressed."""
        for file_pattern, suppressed_rule_id in self.rule_suppressions:
            if _match_path(rel_path, file_pattern) and rule_id == suppressed_rule_id:
                return True
        for suppressed_text in self.match_suppressions:
            if suppressed_text in match_text:
                return True
        return False


def _match_path(path: str, pattern: str) -> bool:
    """Match a relative path against a pattern, supporting ** for recursive dirs."""
    # Normalize separators
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")

    # fnmatch handles * and ? but not ** across directories.
    # For patterns with **, split and check component-wise.
    if "**" in pattern:
        # Use PurePosixPath.match which handles ** on Python 3.12+.
        # For older Python, fall back to a simple recursive check.
        try:
            from pathlib import PurePosixPath
            return PurePosixPath(path).match(pattern)
        except TypeError:
            # Fallback: replace ** with * and do a rough match
            return fnmatch.fnmatch(path, pattern.replace("**/", "*/"))

    return fnmatch.fnmatch(path, pattern)


def parse_ignorefile(root_path: Path) -> IgnoreRules:
    """Parse .secretscanignore from the scan root directory."""
    ignore_path = root_path / IGNORE_FILENAME
    rules = IgnoreRules()

    if not ignore_path.is_file():
        return rules

    try:
        text = ignore_path.read_text(encoding="utf-8")
    except OSError:
        return rules

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        # Match text suppression: !match:SOME_TEXT
        if line.startswith("!match:"):
            match_text = line[len("!match:"):]
            if match_text:
                rules.match_suppressions.append(match_text)
            continue

        # Rule-specific suppression: file_pattern:rule-id
        if ":" in line:
            file_pattern, _, candidate_rule_id = line.rpartition(":")
            if file_pattern and all(
                c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in candidate_rule_id
            ):
                rules.rule_suppressions.append((file_pattern, candidate_rule_id))
                continue

        # File/glob pattern
        rules.file_patterns.append(line)

    return rules


def line_has_nosecret_marker(line: str) -> bool:
    """Check if a source line contains a # nosecret inline suppression."""
    idx = line.find("#")
    while idx != -1:
        comment = line[idx + 1:].strip().lower()
        if comment.startswith(NOSECRET_MARKER):
            return True
        idx = line.find("#", idx + 1)
    return False
