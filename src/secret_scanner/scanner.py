# src/secret_scanner/scanner.py

import os
from pathlib import Path
import re

from .patterns import build_pattern

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
    output_path: Path | None = None,
    skip_dirs=None,
    skip_exts=None,
    max_file_size_bytes: int | None = 5 * 1024 * 1024,
    pattern: re.Pattern | None = None,
):
    """
    Walks root_path, skips junk dirs/exts/binary/large files,
    scans text files line-by-line, optionally writes to output_path,
    and returns a list of match dicts:
        { "file": str, "line": int, "match": str }
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

    if pattern is None:
        pattern = build_pattern()

    matches_found: list[dict] = []
    root_path = root_path.resolve()

    # If output_path is provided, open once and reuse
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

                try:
                    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            for m in pattern.finditer(line):
                                match_text = m.group(0)
                                record = {
                                    "file": str(file_path),
                                    "line": lineno,
                                    "match": match_text,
                                }
                                matches_found.append(record)
                                if cred_file_ctx is not None:
                                    cred_file_ctx.write(
                                        f"{file_path}:{lineno} | {match_text}\n"
                                    )
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    finally:
        if cred_file_ctx is not None:
            cred_file_ctx.close()

    return matches_found

