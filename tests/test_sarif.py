# tests/test_sarif.py

import json

from secret_scanner.sarif import generate_sarif, sarif_to_json
from secret_scanner.patterns import get_patterns


class TestSarifGeneration:
    def test_empty_results(self):
        sarif = generate_sarif([], "/root")
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) > 0

    def test_result_structure(self):
        match = {
            "file": "/root/src/config.py",
            "line": 10,
            "match": "AKIA1234567890ABCDEF",
            "rule_id": "aws-access-key-id",
            "rule_name": "AWS Access Key ID",
            "severity": "error",
            "column": 5,
            "end_column": 25,
        }
        sarif = generate_sarif([match], "/root")
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "aws-access-key-id"
        assert result["level"] == "error"
        loc = result["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 10
        assert loc["region"]["startColumn"] == 6  # 1-based
        assert loc["region"]["endColumn"] == 26  # 1-based
        assert loc["artifactLocation"]["uri"] == "src/config.py"

    def test_relative_path_computation(self):
        match = {
            "file": "/home/user/project/src/main.py",
            "line": 1,
            "match": "password=x12345678",
            "rule_id": "password-assignment",
            "rule_name": "Password Assignment",
            "severity": "warning",
            "column": 0,
            "end_column": 18,
        }
        sarif = generate_sarif([match], "/home/user/project")
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/main.py"

    def test_rules_include_all_patterns(self):
        sarif = generate_sarif([], "/root")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == len(get_patterns())
        for rule in rules:
            assert "id" in rule
            assert "shortDescription" in rule
            assert "defaultConfiguration" in rule

    def test_sarif_json_serializable(self):
        sarif = generate_sarif([], "/root")
        json_str = sarif_to_json(sarif)
        parsed = json.loads(json_str)
        assert parsed == sarif

    def test_security_severity_property(self):
        sarif = generate_sarif([], "/root")
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert "security-severity" in rule["properties"]

    def test_schema_reference(self):
        sarif = generate_sarif([], "/root")
        assert "$schema" in sarif
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_fingerprint_present(self):
        match = {
            "file": "/root/app.py",
            "line": 5,
            "match": "AKIA1234567890ABCDEF",
            "rule_id": "aws-access-key-id",
            "rule_name": "AWS Access Key ID",
            "severity": "error",
            "column": 0,
            "end_column": 20,
        }
        sarif = generate_sarif([match], "/root")
        result = sarif["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert "primaryLocationLineHash" in result["fingerprints"]

    def test_tool_info(self):
        sarif = generate_sarif([], "/root", version="0.2.0")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "secret-scan"
        assert driver["version"] == "0.2.0"
        assert "informationUri" in driver
