"""Data models for PipelineGuard static analysis findings and reports."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels matching CVSS/SARIF standards."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Finding(BaseModel):
    """Represents a single security vulnerability detected in a workflow."""
    rule_id: str = Field(..., description="Unique rule identifier (e.g., PG-001)")
    title: str = Field(..., description="Short descriptive title of the vulnerability")
    severity: Severity = Field(..., description="Vulnerability severity level")
    message: str = Field(..., description="Detailed explanation of the flaw found")
    file_path: str = Field(..., description="Path to the scanned workflow YAML file")
    line: int = Field(..., description="1-indexed line number in the source file")
    column: int = Field(1, description="1-indexed column number in the source file")
    mitre_attack: str = Field("", description="Mapped MITRE ATT&CK technique ID (e.g., T1195.002)")
    remediation: str = Field("", description="Clear, actionable guidance to fix the issue")


class ScanReport(BaseModel):
    """Aggregated report of all findings across scanned files."""
    scanned_files: int = 0
    findings: List[Finding] = Field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
