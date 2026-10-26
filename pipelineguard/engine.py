"""Scan engine coordinating parsers and security rules across workflow files."""

from pathlib import Path
from typing import List, Union
from pipelineguard.models import Finding, ScanReport
from pipelineguard.parser import WorkflowParser
from pipelineguard.rules import (
    BaseRule,
    PullRequestTargetPoisoningRule,
    ScriptInjectionRule,
    OverprivilegedPermissionsRule,
    UnpinnedActionRule,
)


class ScanEngine:
    """Dispatches registered AST rules against discovered workflow YAML files."""

    def __init__(self, rules: List[BaseRule] = None) -> None:
        self.parser = WorkflowParser()
        self.rules: List[BaseRule] = rules or [
            PullRequestTargetPoisoningRule(),
            ScriptInjectionRule(),
            OverprivilegedPermissionsRule(),
            UnpinnedActionRule(),
        ]

    def scan_file(self, file_path: Union[str, Path]) -> List[Finding]:
        """Scan a single workflow file against all registered rules."""
        path = Path(file_path)
        if not path.is_file():
            return []

        try:
            ast, raw_content = self.parser.parse_file(path)
        except Exception:
            # Handle invalid YAML or non-YAML files gracefully
            return []

        findings: List[Finding] = []
        for rule in self.rules:
            detected = rule.check(ast, str(path), raw_content)
            findings.extend(detected)

        return findings

    def scan_path(self, target_path: Union[str, Path]) -> ScanReport:
        """Scan a file or directory of workflow YAML files and return an aggregated report."""
        path = Path(target_path)
        report = ScanReport()

        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = list(path.glob("**/*.yml")) + list(path.glob("**/*.yaml"))
        else:
            return report

        for f in files:
            report.scanned_files += 1
            findings = self.scan_file(f)
            report.findings.extend(findings)

        return report
