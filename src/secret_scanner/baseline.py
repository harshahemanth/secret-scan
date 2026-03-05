# src/secret_scanner/baseline.py

"""Baseline file support for suppressing known findings."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def compute_fingerprint(match: dict) -> str:
    """Compute a position-independent fingerprint for a match.

    SHA-256 of "rule_id:match_text", truncated to 16 hex chars.
    """
    rule_id = match.get("rule_id", "unknown")
    match_text = match.get("match", "")
    data = f"{rule_id}:{match_text}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> set:
    """Load a baseline file and return a set of fingerprints.

    Returns empty set if the file is missing or invalid.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = data.get("findings", {})
        return set(findings.keys())
    except (OSError, json.JSONDecodeError, TypeError, AttributeError):
        return set()


def save_baseline(matches: list, path: Path, tool_version: str) -> None:
    """Save current findings as a baseline JSON file."""
    now = datetime.now(timezone.utc).isoformat()
    findings = {}
    for m in matches:
        fp = compute_fingerprint(m)
        if fp not in findings:
            findings[fp] = {
                "rule_id": m.get("rule_id", "unknown"),
                "rule_name": m.get("rule_name", "Unknown"),
                "file": m.get("file", ""),
                "first_seen": now,
            }

    baseline = {
        "version": "1.0",
        "created": now,
        "tool_version": tool_version,
        "findings": findings,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
        f.write("\n")


def filter_by_baseline(matches: list, baseline_fps: set) -> list:
    """Remove matches whose fingerprint is in the baseline set."""
    return [m for m in matches if compute_fingerprint(m) not in baseline_fps]
