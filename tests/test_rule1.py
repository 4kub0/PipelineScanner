"""Unit tests for Rule 1: pull_request_target untrusted checkout detection."""

from pathlib import Path
import pytest
from pipelineguard.engine import ScanEngine
from pipelineguard.models import Severity
from pipelineguard.rules.rule1_pr_target import PullRequestTargetPoisoningRule


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def test_vulnerable_pull_request_target_detected(fixtures_dir: Path):
    """Verify that Rule 1 detects dangerous pull_request_target workflows."""
    vuln_file = fixtures_dir / "vulnerable" / "v1_pull_request_target.yml"
    assert vuln_file.exists(), f"Missing fixture file: {vuln_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(vuln_file) if f.rule_id == "PG-001"]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "PG-001"
    assert finding.severity == Severity.CRITICAL
    assert finding.mitre_attack == "T1195.002"
    assert "pull_request_target" in finding.message
    # Line number must accurately point to the checkout/with block (line 12 or 13)
    assert finding.line in [10, 11, 12, 13, 14]


def test_secure_workflow_produces_no_findings(fixtures_dir: Path):
    """Verify that a properly hardened workflow passes with 0 findings."""
    safe_file = fixtures_dir / "secure" / "s1_safe_pr_review.yml"
    assert safe_file.exists(), f"Missing fixture file: {safe_file}"

    engine = ScanEngine()
    findings = engine.scan_file(safe_file)

    assert len(findings) == 0


def test_rule1_ignores_safe_pr_target():
    """Verify Rule 1 does not flag pull_request_target if it doesn't checkout untrusted PR head."""
    safe_ast = {
        "name": "PR Labeler",
        "on": "pull_request_target",
        "jobs": {
            "label": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Label PR",
                        "uses": "actions/github-script@v7",
                        "with": {"script": "console.log('labeling');"},
                    }
                ],
            }
        },
    }

    rule = PullRequestTargetPoisoningRule()
    findings = rule.check(safe_ast, "labeler.yml")
    assert len(findings) == 0
