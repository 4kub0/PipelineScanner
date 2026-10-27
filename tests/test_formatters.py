"""Tests for JSON and SARIF formatters and CLI export functionality."""

import json
from pathlib import Path
from click.testing import CliRunner
from pipelineguard.cli import main
from pipelineguard.engine import ScanEngine
from pipelineguard.formatters import format_json, format_sarif, severity_to_sarif_level
from pipelineguard.models import Finding, ScanReport, Severity


def test_severity_to_sarif_level_mapping():
    assert severity_to_sarif_level(Severity.CRITICAL) == "error"
    assert severity_to_sarif_level(Severity.HIGH) == "error"
    assert severity_to_sarif_level(Severity.MEDIUM) == "warning"
    assert severity_to_sarif_level(Severity.LOW) == "note"
    assert severity_to_sarif_level(Severity.INFO) == "note"


def test_format_json_structure():
    report = ScanReport(
        scanned_files=1,
        findings=[
            Finding(
                rule_id="PG-001",
                title="PR Target Poisoning",
                severity=Severity.CRITICAL,
                message="Untrusted ref checked out in pull_request_target.",
                file_path=".github/workflows/vulnerable.yml",
                line=72,
                column=1,
                mitre_attack="T1195.002",
                remediation="Use pull_request instead.",
            )
        ],
    )
    json_str = format_json(report)
    data = json.loads(json_str)

    assert data["version"] == "0.1.0"
    assert data["scanned_files"] == 1
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 0
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "PG-001"
    assert data["findings"][0]["line"] == 72
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert data["findings"][0]["mitre_attack"] == "T1195.002"


def test_format_sarif_schema():
    report = ScanReport(
        scanned_files=2,
        findings=[
            Finding(
                rule_id="PG-001",
                title="PR Target Poisoning",
                severity=Severity.CRITICAL,
                message="Untrusted checkout",
                file_path=".github/workflows/vulnerable.yml",
                line=72,
                column=1,
                mitre_attack="T1195.002",
                remediation="Fix it",
            ),
            Finding(
                rule_id="PG-004",
                title="Unpinned Action",
                severity=Severity.MEDIUM,
                message="Mutable action tag used",
                file_path=".github/workflows/vulnerable.yml",
                line=71,
                column=1,
                mitre_attack="T1195.001",
                remediation="Pin SHA",
            ),
        ],
    )
    sarif_str = format_sarif(report)
    sarif = json.loads(sarif_str)

    assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PipelineGuard"
    assert driver["version"] == "0.1.0"

    rules = driver["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "PG-001" in rule_ids
    assert "PG-004" in rule_ids

    results = sarif["runs"][0]["results"]
    assert len(results) == 2

    # Check PG-001 result
    r1 = results[0]
    assert r1["ruleId"] == "PG-001"
    assert r1["level"] == "error"
    loc1 = r1["locations"][0]["physicalLocation"]
    assert loc1["artifactLocation"]["uri"] == ".github/workflows/vulnerable.yml"
    assert loc1["region"]["startLine"] == 72

    # Check PG-004 result
    r2 = results[1]
    assert r2["ruleId"] == "PG-004"
    assert r2["level"] == "warning"
    loc2 = r2["locations"][0]["physicalLocation"]
    assert loc2["region"]["startLine"] == 71


def test_cli_scan_json_stdout():
    runner = CliRunner()
    fixture = Path("tests/fixtures/vulnerable/v1_pull_request_target.yml")
    result = runner.invoke(main, ["scan", str(fixture), "--format", "json"])

    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["summary"]["total_findings"] >= 1
    assert any(f["rule_id"] == "PG-001" for f in data["findings"])


def test_cli_scan_sarif_file_export(tmp_path):
    runner = CliRunner()
    fixture = Path("tests/fixtures/vulnerable/v1_pull_request_target.yml")
    out_file = tmp_path / "scan_output.sarif"

    result = runner.invoke(
        main, ["scan", str(fixture), "--format", "sarif", "--output", str(out_file)]
    )

    assert result.exit_code == 1
    assert out_file.exists()
    sarif = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "PipelineGuard"


def test_cli_scan_secure_passes_cleanly():
    runner = CliRunner()
    fixture = Path("tests/fixtures/secure/s1_safe_pr_review.yml")
    result = runner.invoke(main, ["scan", str(fixture), "--format", "json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["summary"]["total_findings"] == 0
    assert len(data["findings"]) == 0
