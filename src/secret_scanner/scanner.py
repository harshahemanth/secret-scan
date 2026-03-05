# src/secret_scanner/scanner.py

import os
from pathlib import Path
import re
from typing import Optional, Set

from .patterns import build_pattern, compile_patterns
from .entropy import scan_line_entropy
from .ignore import parse_ignorefile, line_has_nosecret_marker, IgnoreRules
from .redact import redact_match

DEFAULT_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    ".idea", ".vscode",
    "node_modules",
    ".venv", "venv", "env",
    "__pycache__",
    "dist", "build",
}

DEFAULT_SKIP_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".pdf",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".class", ".jar",
}


def is_binary_file(path: Path, blocksize: int = 1024) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(blocksize)
        return b"\0" in chunk
    except OSError:
        return True


def scan_directory(
    root_path: Path,
    output_path: Optional[Path] = None,
    skip_dirs=None,
    skip_exts=None,
    max_file_size_bytes: Optional[int] = 5 * 1024 * 1024,
    pattern: Optional[re.Pattern] = None,
    ignore_rules: Optional[IgnoreRules] = None,
    entropy: bool = False,
    redact: bool = True,
    only_files: Optional[Set[str]] = None,
):
    """
    Walks root_path, skips junk dirs/exts/binary/large files,
    scans text files line-by-line, optionally writes to output_path,
    and returns a list of match dicts:
        { "file", "line", "match", "rule_id", "rule_name", "severity", "column", "end_column" }
    """
    if skip_dirs is None:
        effective_skip_dirs = set(DEFAULT_SKIP_DIRS)
    else:
        effective_skip_dirs = set(DEFAULT_SKIP_DIRS).union(skip_dirs)

    if skip_exts is None:
        effective_skip_exts = set(DEFAULT_SKIP_EXTS)
    else:
        extra = {
            e.lower() if e.startswith(".") else f".{e.lower()}"
            for e in skip_exts
        }
        effective_skip_exts = set(DEFAULT_SKIP_EXTS).union(extra)

    # Determine scanning mode: named patterns (new) or single regex (legacy)
    use_legacy = pattern is not None
    if use_legacy:
        compiled_patterns = None
    else:
        compiled_patterns = compile_patterns()

    root_path = root_path.resolve()

    # Auto-load ignore rules if not provided
    if ignore_rules is None:
        ignore_rules = parse_ignorefile(root_path)

    matches_found: list[dict] = []

    cred_file_ctx = (
        open(output_path, "w", encoding="utf-8")
        if output_path is not None
        else None
    )

    try:
        for current_root, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in effective_skip_dirs]

            for filename in filenames:
                file_path = Path(current_root) / filename

                # Diff-mode: only scan specified files
                if only_files is not None and str(file_path.resolve()) not in only_files:
                    continue

                ext = (
                    "." + file_path.name.split(".")[-1].lower()
                    if "." in file_path.name
                    else ""
                )
                if ext in effective_skip_exts:
                    continue

                if max_file_size_bytes is not None:
                    try:
                        if file_path.stat().st_size > max_file_size_bytes:
                            continue
                    except OSError:
                        continue

                if is_binary_file(file_path):
                    continue

                # Check file-level ignore rules
                try:
                    rel_path = str(file_path.relative_to(root_path))
                except ValueError:
                    rel_path = str(file_path)

                if ignore_rules.should_ignore_file(rel_path):
                    continue

                try:
                    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            # Check inline nosecret suppression
                            if line_has_nosecret_marker(line):
                                continue

                            if use_legacy:
                                # Legacy single-pattern mode
                                for m in pattern.finditer(line):
                                    record = {
                                        "file": str(file_path),
                                        "line": lineno,
                                        "match": m.group(0),
                                    }
                                    matches_found.append(record)
                                    if cred_file_ctx is not None:
                                        display = redact_match(m.group(0)) if redact else m.group(0)
                                        cred_file_ctx.write(
                                            f"{file_path}:{lineno} | {display}\n"
                                        )
                            else:
                                # Named-pattern mode with dedup
                                line_matches = []
                                for secret_pattern, compiled_re in compiled_patterns:
                                    for m in compiled_re.finditer(line):
                                        line_matches.append({
                                            "file": str(file_path),
                                            "line": lineno,
                                            "match": m.group(0),
                                            "rule_id": secret_pattern.rule_id,
                                            "rule_name": secret_pattern.name,
                                            "severity": secret_pattern.severity,
                                            "column": m.start(),
                                            "end_column": m.end(),
                                        })

                                # Deduplicate overlapping spans — keep more specific (first) rule
                                seen_spans = set()
                                for record in line_matches:
                                    span = (record["column"], record["end_column"])
                                    if span not in seen_spans:
                                        seen_spans.add(span)

                                        # Check match-level ignore rules
                                        if ignore_rules.should_ignore_match(
                                            rel_path, record["rule_id"], record["match"]
                                        ):
                                            continue

                                        matches_found.append(record)
                                        if cred_file_ctx is not None:
                                            display = redact_match(record['match']) if redact else record['match']
                                            cred_file_ctx.write(
                                                f"{file_path}:{lineno} | {display}\n"
                                            )

                                # Entropy-based detection (opt-in)
                                if entropy:
                                    for ent_record in scan_line_entropy(line, str(file_path), lineno):
                                        ent_span = (ent_record["column"], ent_record["end_column"])
                                        if ent_span in seen_spans:
                                            continue
                                        seen_spans.add(ent_span)
                                        if ignore_rules.should_ignore_match(
                                            rel_path, ent_record["rule_id"], ent_record["match"]
                                        ):
                                            continue
                                        matches_found.append(ent_record)
                                        if cred_file_ctx is not None:
                                            display = redact_match(ent_record['match']) if redact else ent_record['match']
                                            cred_file_ctx.write(
                                                f"{file_path}:{lineno} | {display}\n"
                                            )
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    finally:
        if cred_file_ctx is not None:
            cred_file_ctx.close()

    return matches_found
