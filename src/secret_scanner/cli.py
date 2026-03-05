# src/secret_scanner/cli.py

import argparse
import json
import sys
from importlib.metadata import version as pkg_version
from pathlib import Path

from .scanner import scan_directory
from .ignore import IgnoreRules
from .redact import redact_matches
from .baseline import load_baseline, save_baseline, filter_by_baseline, compute_fingerprint

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
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Enable entropy-based detection for high-entropy hex/base64 strings.",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Show full secret values in output (by default, secrets are redacted).",
    )
    parser.add_argument(
        "--baseline",
        metavar="FILE",
        default=None,
        help="Path to a baseline file. Known findings are suppressed from results.",
    )
    parser.add_argument(
        "--save-baseline",
        metavar="FILE",
        default=None,
        help="Save current findings as a baseline file for future scans.",
    )
    parser.add_argument(
        "--diff",
        metavar="REF",
        default=None,
        help="Only scan files changed since the given git ref (e.g. main, HEAD~3).",
    )
    return parser.parse_args(argv)


def _filter_by_severity(matches: list, min_severity: str) -> list:
    """Filter matches to only include findings at or above the given severity."""
    threshold = SEVERITY_LEVELS.index(min_severity)
    return [m for m in matches if SEVERITY_LEVELS.index(m.get("severity", "warning")) <= threshold]


def run(argv=None) -> int:
    """Run the scanner and return an exit code (0 = clean, 1 = secrets found, 2 = git error)."""
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

    # Diff mode: resolve changed files
    only_files = None
    if args.diff is not None:
        from .git import get_changed_files, get_repo_root, GitError
        try:
            repo_root = get_repo_root(root)
            only_files = set(get_changed_files(args.diff, repo_root))
        except GitError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2

    redact = not args.no_redact

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
        entropy=args.entropy,
        redact=redact,
        only_files=only_files,
    )

    # Apply severity filter if specified
    if args.severity:
        matches = _filter_by_severity(matches, args.severity)

    # Baseline filter (uses raw match text for fingerprints)
    if args.baseline:
        baseline_fps = load_baseline(Path(args.baseline))
        matches = filter_by_baseline(matches, baseline_fps)

    # Save baseline (uses raw match text)
    if args.save_baseline:
        save_baseline(matches, Path(args.save_baseline), _get_version())

    # Add fingerprint hashes (uses raw match text, before redaction)
    for m in matches:
        m["fingerprint"] = compute_fingerprint(m)

    print(f"Scan complete. {len(matches)} potential secret(s) found.", file=sys.stderr)

    # Redaction + output (display layer)
    display_matches = matches if not redact else redact_matches(matches)

    if args.sarif:
        from .sarif import generate_sarif, sarif_to_json
        sarif_doc = generate_sarif(display_matches, str(root.resolve()))
        sys.stdout.write(sarif_to_json(sarif_doc))
        print()
    elif args.json:
        json.dump(display_matches, sys.stdout, indent=2)
        print()

    if matches and not args.no_fail:
        return 1
    return 0


def main(argv=None):
    """Entry point that exits with appropriate code."""
    sys.exit(run(argv))


if __name__ == "__main__":
    main(sys.argv[1:])
