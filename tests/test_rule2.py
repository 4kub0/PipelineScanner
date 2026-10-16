"""Unit tests for Rule 2: Script injection via untrusted context expressions in run blocks."""

from pathlib import Path
import pytest
from pipelineguard.engine import ScanEngine
from pipelineguard.models import Severity
from pipelineguard.rules.rule2_script_injection import ScriptInjectionRule


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def test_vulnerable_script_injection_detected(fixtures_dir: Path):
    """Verify Rule 2 catches untrusted PR title and issue body in inline run blocks."""
    vuln_file = fixtures_dir / "vulnerable" / "v2_script_injection.yml"
    assert vuln_file.exists(), f"Missing fixture file: {vuln_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(vuln_file) if f.rule_id == "PG-002"]

    assert len(findings) == 2, f"Expected 2 script injection findings, got {len(findings)}"
    for finding in findings:
        assert finding.rule_id == "PG-002"
        assert finding.severity == Severity.HIGH
        assert finding.mitre_attack == "T1059"
        assert finding.line > 0


def test_secure_env_parameterized_workflow_clean(fixtures_dir: Path):
    """Verify that passing untrusted fields via env: does not trigger false positives."""
    safe_file = fixtures_dir / "secure" / "s2_env_parameterized.yml"
    assert safe_file.exists(), f"Missing fixture file: {safe_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(safe_file) if f.rule_id == "PG-002"]

    assert len(findings) == 0, f"Expected 0 findings on secure fixture, got {findings}"


def test_trusted_context_not_flagged():
    """Verify that trusted immutable context fields (e.g. github.repository) are not flagged."""
    trusted_ast = {
        "name": "Build and Tag",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "name": "Echo Repo and Run ID",
                        "run": 'echo "Repo: ${{ github.repository }} Run: ${{ github.run_id }}"',
                    }
                ],
            }
        },
    }

    rule = ScriptInjectionRule()
    findings = rule.check(trusted_ast, "build.yml")
    assert len(findings) == 0
