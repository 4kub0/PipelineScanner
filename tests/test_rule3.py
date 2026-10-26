"""Unit tests for Rule 3: Over-privileged GITHUB_TOKEN permissions detection."""

from pathlib import Path
import pytest
from pipelineguard.engine import ScanEngine
from pipelineguard.models import Severity
from pipelineguard.rules.rule3_permissions import OverprivilegedPermissionsRule


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


def test_vulnerable_write_all_detected(fixtures_dir: Path):
    """Verify Rule 3 catches global 'permissions: write-all'."""
    vuln_file = fixtures_dir / "vulnerable" / "v3_permissions.yml"
    assert vuln_file.exists(), f"Missing fixture file: {vuln_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(vuln_file) if f.rule_id == "PG-003"]

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "PG-003"
    assert finding.severity == Severity.HIGH
    assert finding.mitre_attack == "T1078"
    assert "write-all" in finding.title.lower() or "write-all" in finding.message.lower()
    assert finding.line == 6  # Line where permissions: write-all is declared in v3_permissions.yml


def test_missing_permissions_block_detected():
    """Verify Rule 3 detects workflows with no explicit permissions declared."""
    ast_without_perms = {
        "name": "Unconfigured Permissions",
        "on": "push",
        "jobs": {
            "build": {
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "echo 'building'"}]
            }
        }
    }

    rule = OverprivilegedPermissionsRule()
    findings = rule.check(ast_without_perms, "test.yml")

    assert len(findings) == 1
    assert findings[0].rule_id == "PG-003"
    assert findings[0].severity == Severity.MEDIUM
    assert "missing" in findings[0].title.lower()


def test_secure_least_privilege_workflow_clean(fixtures_dir: Path):
    """Verify Rule 3 produces 0 findings when permissions: contents: read is configured."""
    safe_file = fixtures_dir / "secure" / "s3_least_privilege.yml"
    assert safe_file.exists(), f"Missing fixture file: {safe_file}"

    engine = ScanEngine()
    findings = [f for f in engine.scan_file(safe_file) if f.rule_id == "PG-003"]

    assert len(findings) == 0, f"Expected 0 findings on secure fixture, got {findings}"


def test_job_level_write_all_detected():
    """Verify Rule 3 flags job-level 'write-all' declaration."""
    ast_job_write = {
        "name": "Scoped Workflow",
        "on": "push",
        "permissions": {
            "contents": "read"
        },
        "jobs": {
            "deploy": {
                "permissions": "write-all",
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "echo 'deploying'"}]
            }
        }
    }

    rule = OverprivilegedPermissionsRule()
    findings = rule.check(ast_job_write, "deploy.yml")

    assert len(findings) == 1
    assert findings[0].rule_id == "PG-003"
    assert "job-level" in findings[0].title.lower()
    assert findings[0].severity == Severity.HIGH


def test_read_all_is_clean():
    """Verify Rule 3 does not flag permissions: read-all."""
    ast_read_all = {
        "name": "Read Only",
        "on": "push",
        "permissions": "read-all",
        "jobs": {
            "test": {
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "echo 'testing'"}]
            }
        }
    }

    rule = OverprivilegedPermissionsRule()
    findings = rule.check(ast_read_all, "read.yml")

    assert len(findings) == 0

