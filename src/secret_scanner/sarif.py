# src/secret_scanner/sarif.py

from __future__ import annotations

import json
from typing import Any

from .patterns import get_patterns, SecretPattern

SEVERITY_TO_SARIF_LEVEL = {
    "error": "error",
    "warning": "warning",
    "note": "note",
}

SEVERITY_TO_SCORE = {
    "error": "9.0",
    "warning": "6.0",
    "note": "3.0",
}


def _build_rules(patterns: list[SecretPattern]) -> list[dict[str, Any]]:
    """Build SARIF rule descriptors from pattern definitions."""
    rules = []
    for sp in patterns:
        rule = {
            "id": sp.rule_id,
            "name": sp.name,
            "shortDescription": {"text": sp.name},
            "fullDescription": {"text": sp.description},
            "defaultConfiguration": {
                "level": SEVERITY_TO_SARIF_LEVEL.get(sp.severity, "warning"),
            },
            "properties": {
                "tags": ["security", "secret-detection"],
                "security-severity": SEVERITY_TO_SCORE.get(sp.severity, "6.0"),
            },
        }
        rules.append(rule)
    return rules


def _build_rule_index(patterns: list[SecretPattern]) -> dict[str, int]:
    """Map rule_id -> index for SARIF result references."""
    return {sp.rule_id: i for i, sp in enumerate(patterns)}


def generate_sarif(
    matches: list[dict[str, Any]],
    root_path: str,
    version: str = "0.4.1",
) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document from scan results."""
    patterns = get_patterns()
    rules = _build_rules(patterns)
    rule_index = _build_rule_index(patterns)

    results = []
    for match in matches:
        rule_id = match.get("rule_id", "unknown")
        idx = rule_index.get(rule_id, 0)

        file_path = match["file"]
        if file_path.startswith(root_path):
            rel_path = file_path[len(root_path):].lstrip("/").lstrip("\\")
        else:
            rel_path = file_path

        result = {
            "ruleId": rule_id,
            "ruleIndex": idx,
            "level": SEVERITY_TO_SARIF_LEVEL.get(
                match.get("severity", "warning"), "warning"
            ),
            "message": {
                "text": f"Potential secret detected: {match.get('rule_name', rule_id)}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": match["line"],
                            "startColumn": match.get("column", 0) + 1,
                            "endColumn": match.get("end_column", 0) + 1,
                        },
                    },
                },
            ],
            "fingerprints": {
                "primaryLocationLineHash": f"{rel_path}:{match['line']}:{rule_id}",
                "secret-scan/fingerprint": match.get("fingerprint", ""),
            },
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-scan",
                        "version": version,
                        "informationUri": "https://github.com/harshahemanth/secret-scan",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }
    return sarif


def sarif_to_json(sarif: dict[str, Any], indent: int = 2) -> str:
    """Serialize SARIF document to a JSON string."""
    return json.dumps(sarif, indent=indent)
