# src/secret_scanner/cli.py

import argparse
import json
import sys
from importlib.metadata import version as pkg_version
from pathlib import Path

from .scanner import scan_directory
from .ignore import IgnoreRules

SEVERITY_LEVELS = ("error", "warning", "note")


def _get_version() -> str:
    try:
        return pkg_version("secret-scan")
    except Exception:
        return "dev"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan a directory for potential credentials/secrets."
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"secret-scan {_get_version()}",
    )
    parser.add_argument(
        "path",
        help="Directory to scan.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="docsCred.txt",
        help="Output file path for text results (default: docsCred.txt)",
    )
    parser.add_argument(
        "--max-size-mb",
        type=int,
        default=5,
        help="Maximum file size in megabytes to scan (default: 5). "
             "Use 0 or a negative value to disable the size limit.",
    )
    parser.add_argument(
        "--skip-dir",
        action="append",
        default=[],
        help="Additional directory name to skip. Can be passed multiple times.",
    )
    parser.add_argument(
        "--skip-ext",
        action="append",
        default=[],
        help="Additional file extension to skip (e.g. .log). "
             "Can be passed multiple times.",
    )
    parser.add_argument(
        "--severity",
        choices=SEVERITY_LEVELS,
        default=None,
        help="Only report findings at this severity level or higher. "
             "Levels from highest to lowest: error, warning, note.",
    )

    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON to stdout.",
    )
    output_group.add_argument(
        "--sarif",
        action="store_true",
        help="Print results in SARIF v2.1.0 format to stdout (for CI integration).",
    )

    parser.add_argument(
        "--no-fail",
        action="store_true",
        help="Always exit with code 0 even if secrets are found (advisory mode).",
    )
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        help="Do not read .secretscanignore file.",
    )
    return parser.parse_args(argv)


def _filter_by_severity(matches: list, min_severity: str) -> list:
    """Filter matches to only include findings at or above the given severity."""
    threshold = SEVERITY_LEVELS.index(min_severity)
    return [m for m in matches if SEVERITY_LEVELS.index(m.get("severity", "warning")) <= threshold]


def run(argv=None) -> int:
    """Run the scanner and return an exit code (0 = clean, 1 = secrets found)."""
    args = parse_args(argv)

    root = Path(args.path).expanduser()
    output = Path(args.output).expanduser() if args.output else None

    if args.max_size_mb and args.max_size_mb > 0:
        max_bytes = args.max_size_mb * 1024 * 1024
    else:
        max_bytes = None

    extra_dirs = set(args.skip_dir) if args.skip_dir else None
    extra_exts = set(args.skip_ext) if args.skip_ext else None

    # If --no-ignore, pass empty rules to bypass auto-loading
    ignore_rules = IgnoreRules() if args.no_ignore else None

    print(f"Scanning directory: {root}", file=sys.stderr)
    if output is not None:
        print(f"Writing text results to: {output}", file=sys.stderr)

    matches = scan_directory(
        root_path=root,
        output_path=output,
        skip_dirs=extra_dirs,
        skip_exts=extra_exts,
        max_file_size_bytes=max_bytes,
        ignore_rules=ignore_rules,
    )

    # Apply severity filter if specified
    if args.severity:
        matches = _filter_by_severity(matches, args.severity)

    print(f"Scan complete. {len(matches)} potential secret(s) found.", file=sys.stderr)

    if args.sarif:
        from .sarif import generate_sarif, sarif_to_json
        sarif_doc = generate_sarif(matches, str(root.resolve()))
        sys.stdout.write(sarif_to_json(sarif_doc))
        print()
    elif args.json:
        json.dump(matches, sys.stdout, indent=2)
        print()

    if matches and not args.no_fail:
        return 1
    return 0


def main(argv=None):
    """Entry point that exits with appropriate code."""
    sys.exit(run(argv))


if __name__ == "__main__":
    main(sys.argv[1:])
