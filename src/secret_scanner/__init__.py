# src/secret_scanner/__init__.py

from .scanner import scan_directory, DEFAULT_SKIP_DIRS, DEFAULT_SKIP_EXTS
from .patterns import build_pattern, get_patterns, compile_patterns, SecretPattern
from .entropy import scan_line_entropy, shannon_entropy
from .redact import redact_match, redact_matches
from .baseline import compute_fingerprint, load_baseline, save_baseline, filter_by_baseline

__all__ = [
    "scan_directory",
    "DEFAULT_SKIP_DIRS",
    "DEFAULT_SKIP_EXTS",
    "build_pattern",
    "get_patterns",
    "compile_patterns",
    "SecretPattern",
    "scan_line_entropy",
    "shannon_entropy",
    "redact_match",
    "redact_matches",
    "compute_fingerprint",
    "load_baseline",
    "save_baseline",
    "filter_by_baseline",
]
