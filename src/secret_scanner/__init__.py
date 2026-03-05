# src/secret_scanner/__init__.py

from .scanner import scan_directory, DEFAULT_SKIP_DIRS, DEFAULT_SKIP_EXTS
from .patterns import build_pattern, get_patterns, compile_patterns, SecretPattern

__all__ = [
    "scan_directory",
    "DEFAULT_SKIP_DIRS",
    "DEFAULT_SKIP_EXTS",
    "build_pattern",
    "get_patterns",
    "compile_patterns",
    "SecretPattern",
]
