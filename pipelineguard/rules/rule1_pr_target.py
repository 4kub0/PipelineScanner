"""Rule 1: Detect dangerous pull_request_target triggers checking out untrusted PR head."""

from typing import Any, List
from pipelineguard.models import Finding, Severity
from pipelineguard.parser import WorkflowParser
from pipelineguard.rules.base import BaseRule


class PullRequestTargetPoisoningRule(BaseRule):
    """Flags workflows that use 'pull_request_target' and checkout untrusted pull request code.
    
    MITRE ATT&CK: T1195.002 (Supply Chain Compromise: Compromise Software Dependencies)
    CWE-829: Inclusion of Functionality from Untrusted Control Sphere
    """

    rule_id = "PG-001"
    title = "Dangerous pull_request_target with Untrusted Code Checkout"
    severity = Severity.CRITICAL
    mitre_attack = "T1195.002"
    remediation = (
        "Replace 'pull_request_target' with standard 'pull_request' if building untrusted code, "
        "or avoid checking out 'github.event.pull_request.head.sha'. If PR head checkout is strictly "
        "necessary, do not execute build scripts (npm test, make, etc.) and drop token permissions."
    )

    def check(self, ast: Any, file_path: str, raw_content: str = "") -> List[Finding]:
        findings: List[Finding] = []

        if not isinstance(ast, dict):
            return findings

        # In YAML, 'on' can sometimes be parsed as string 'on' or boolean True
        on_trigger = ast.get("on")
        if on_trigger is None:
            on_trigger = ast.get(True)

        if not on_trigger:
            return findings

        # Determine if pull_request_target is an active trigger
        has_pr_target = False
        if isinstance(on_trigger, str) and on_trigger == "pull_request_target":
            has_pr_target = True
        elif isinstance(on_trigger, list) and "pull_request_target" in on_trigger:
            has_pr_target = True
        elif isinstance(on_trigger, dict) and "pull_request_target" in on_trigger:
            has_pr_target = True

        if not has_pr_target:
            return findings

        # Inspect jobs and steps for checkout of untrusted PR head
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

                uses = str(step.get("uses", "")).strip()
                if "actions/checkout" not in uses:
                    continue

                step_with = step.get("with", {})
                if not isinstance(step_with, dict):
                    continue

                ref_val = str(step_with.get("ref", "")).strip()

                # Indicators of checking out untrusted external PR code
                dangerous_refs = [
                    "github.event.pull_request.head.sha",
                    "github.event.pull_request.head.ref",
                    "github.head_ref",
                ]

                if any(ind in ref_val for ind in dangerous_refs):
                    line_num = WorkflowParser.get_line(step, "with", default=1)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            message=(
                                f"Job '{job_id}' triggers on 'pull_request_target' (elevated privileges) "
                                f"and checks out untrusted PR head ref '{ref_val}'. External pull requests "
                                "can execute arbitrary malicious code with access to repository secrets."
                            ),
                            file_path=str(file_path),
                            line=line_num,
                            column=1,
                            mitre_attack=self.mitre_attack,
                            remediation=self.remediation,
                        )
                    )

        return findings
