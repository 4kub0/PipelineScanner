"""Abstract Base Class for all PipelineGuard security rules."""

from abc import ABC, abstractmethod
from typing import Any, List
from pipelineguard.models import Finding, Severity


class BaseRule(ABC):
    """Base class that every detection rule inherits from."""

    rule_id: str = "PG-000"
    title: str = "Base Rule"
    severity: Severity = Severity.MEDIUM
    mitre_attack: str = ""
    remediation: str = ""

    @abstractmethod
    def check(self, ast: Any, file_path: str, raw_content: str = "") -> List[Finding]:
        """Inspect the parsed workflow AST and return any security findings.
        
        Args:
            ast: ruamel.yaml CommentedMap representation of the workflow.
            file_path: Relative or absolute path to the workflow file.
            raw_content: Raw text content of the file.
            
        Returns:
            List of Finding instances detected in this workflow.
        """
        pass
