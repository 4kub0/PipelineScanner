"""Unit tests for Rule 4: Unpinned 3rd-party action detection."""

from pathlib import Path
import pytest
from pipelineguard.engine import ScanEngine
from pipelineguard.models import Severity
from pipelineguard.rules.rule4_unpinned_actions import UnpinnedActionRule


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def test_vulnerable_unpinned_actions_detected(fixtures_dir: Path):
    """Verify Rule 4 catches mutable tags like @v4 and @v3."""
    vuln_file = fixtures_dir / "vulnerable" / "v4_unpinned_action.yml"
    assert vuln_file.exists(), f"Missing fixture file: {vuln_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(vuln_file) if f.rule_id == "PG-004"]

    assert len(findings) == 2, f"Expected 2 unpinned action findings, got {len(findings)}"
    for f in findings:
        assert f.rule_id == "PG-004"
        assert f.severity == Severity.MEDIUM
        assert f.mitre_attack == "T1195.001"
        assert f.line in [13, 14, 15, 16]


def test_secure_pinned_actions_clean(fixtures_dir: Path):
    """Verify Rule 4 passes when 40-character commit SHAs and local actions are used."""
    safe_file = fixtures_dir / "secure" / "s4_pinned_action.yml"
    assert safe_file.exists(), f"Missing fixture file: {safe_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(safe_file) if f.rule_id == "PG-004"]

    assert len(findings) == 0, f"Expected 0 findings on secure fixture, got {findings}"


def test_docker_and_local_actions_ignored():
    """Verify Rule 4 does not flag docker:// or local relative actions."""
    ast = {
        "name": "Docker & Local",
        "on": "push",
        "permissions": {"contents": "read"},
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [
                    {"name": "Docker Action", "uses": "docker://alpine:latest"},
                    {"name": "Local Action", "uses": "./.github/actions/custom"},
                ],
            }
        },
    }

    rule = UnpinnedActionRule()
    findings = rule.check(ast, "test.yml")

    assert len(findings) == 0
