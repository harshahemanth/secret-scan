# src/secret_scanner/cli.py

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_directory


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan a directory for potential credentials/secrets."
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
        "--json",
        action="store_true",
        help="Print results as JSON to stdout.",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    root = Path(args.path).expanduser()
    output = Path(args.output).expanduser() if args.output else None

    if args.max_size_mb and args.max_size_mb > 0:
        max_bytes = args.max_size_mb * 1024 * 1024
    else:
        max_bytes = None

    extra_dirs = set(args.skip_dir) if args.skip_dir else None
    extra_exts = set(args.skip_ext) if args.skip_ext else None

    print(f"Scanning directory: {root}", file=sys.stderr)
    if output is not None:
        print(f"Writing text results to: {output}", file=sys.stderr)

    matches = scan_directory(
        root_path=root,
        output_path=output,
        skip_dirs=extra_dirs,
        skip_exts=extra_exts,
        max_file_size_bytes=max_bytes,
    )

    print(f"Scan complete. {len(matches)} potential secret(s) found.", file=sys.stderr)

    if args.json:
        # Pretty JSON to stdout
        json.dump(matches, sys.stdout, indent=2)
        print()  # newline after JSON


if __name__ == "__main__":
    main(sys.argv[1:])

