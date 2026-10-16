"""Rule 2: Detect script injection via untrusted GitHub context expressions in run blocks."""

import re
from typing import Any, List
from pipelineguard.models import Finding, Severity
from pipelineguard.parser import WorkflowParser
from pipelineguard.rules.base import BaseRule


class ScriptInjectionRule(BaseRule):
    """Flags workflows that interpolate untrusted GitHub context expressions directly into inline run scripts.

    MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
    CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    """

    rule_id = "PG-002"
    title = "Potential Script Injection via Untrusted Context Expression"
    severity = Severity.HIGH
    mitre_attack = "T1059"
    remediation = (
        "Do not interpolate untrusted context directly into inline 'run:' scripts. "
        "Instead, pass the context variable through an intermediate environment variable ('env:') "
        "and reference it inside the shell as a quoted environment variable (e.g., \"$PR_TITLE\")."
    )

    # Known attacker-controlled fields in GitHub Actions context
    UNTRUSTED_CONTEXT_PATTERNS = [
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.event.head_commit.message",
        "github.event.head_commit.author.name",
        "github.event.head_commit.author.email",
        "github.head_ref",
    ]

    # Regex matching ${{ ... }} interpolation
    EXPRESSION_REGEX = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

    def check(self, ast: Any, file_path: str, raw_content: str = "") -> List[Finding]:
        findings: List[Finding] = []

        if not isinstance(ast, dict):
            return findings

        jobs = ast.get("jobs", {})
        if not isinstance(jobs, dict):
            return findings

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue

            steps = job.get("steps", [])
            if not isinstance(steps, list):
                continue

            for step in steps:
                if not isinstance(step, dict):
                    continue

                run_content = step.get("run")
                if not isinstance(run_content, str):
                    continue

                # Search for all ${{ ... }} expressions within the inline script
                matches = self.EXPRESSION_REGEX.findall(run_content)
                for expr in matches:
                    expr_clean = expr.strip()

                    # Check if the expression contains any untrusted pattern
                    matched_pattern = next(
                        (pattern for pattern in self.UNTRUSTED_CONTEXT_PATTERNS if pattern in expr_clean),
                        None,
                    )

                    if matched_pattern:
                        base_line = WorkflowParser.get_line(step, "run", default=1)
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=self.title,
                                severity=self.severity,
                                message=(
                                    f"Job '{job_id}' directly interpolates untrusted context expression "
                                    f"'${{{{ {expr_clean} }}}}' inside an inline 'run:' shell block. "
                                    "Adversaries can inject arbitrary shell metacharacters (e.g., quotes, "
                                    "semicolons, backticks) to execute malicious commands on the runner."
                                ),
                                file_path=str(file_path),
                                line=base_line,
                                column=1,
                                mitre_attack=self.mitre_attack,
                                remediation=self.remediation,
                            )
                        )

        return findings
