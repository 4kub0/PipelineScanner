"""Rule 3: Detect over-privileged GITHUB_TOKEN permissions (write-all or missing permissions)."""

from typing import Any, List
from pipelineguard.models import Finding, Severity
from pipelineguard.parser import WorkflowParser
from pipelineguard.rules.base import BaseRule


class OverprivilegedPermissionsRule(BaseRule):
    """Flags workflows that declare over-privileged 'write-all' permissions or omit permissions entirely.

    MITRE ATT&CK: T1078 (Valid Accounts)
    OWASP Top 10 CI/CD: CICD-SEC-2 (Inadequate Identity and Access Management)
    CWE-250: Execution with Unnecessary Privileges
    """

    rule_id = "PG-003"
    title = "Over-privileged GITHUB_TOKEN Permissions"
    severity = Severity.HIGH
    mitre_attack = "T1078"
    remediation = (
        "Follow the Principle of Least Privilege. Avoid declaring 'permissions: write-all' "
        "or omitting the 'permissions:' block. Explicitly define minimal required scopes "
        "(e.g., 'permissions: contents: read' or 'permissions: { contents: read, pull-requests: read }')."
    )

    def check(self, ast: Any, file_path: str, raw_content: str = "") -> List[Finding]:
        findings: List[Finding] = []

        if not isinstance(ast, dict):
            return findings

        # 1. Check top-level permissions
        top_perms = ast.get("permissions")
        has_top_perms = "permissions" in ast

        if has_top_perms:
            if isinstance(top_perms, str) and top_perms.strip().lower() == "write-all":
                line_num = WorkflowParser.get_line(ast, "permissions")
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file_path=file_path,
                        line=line_num,
                        severity=Severity.HIGH,
                        title="Global 'write-all' Permissions Declared",
                        message=(
                            "Workflow declares global 'permissions: write-all', granting GITHUB_TOKEN "
                            "write privileges across all 13 GitHub API scopes. Any compromised step or dependency "
                            "can push code, overwrite releases, or alter repository state."
                        ),
                        remediation=self.remediation,
                        mitre_attack=self.mitre_attack,
                    )
                )
            elif isinstance(top_perms, dict):
                # Check for explicit write-all key or wildcard
                for key, val in top_perms.items():
                    if str(key).strip().lower() == "write-all" or str(val).strip().lower() == "write-all":
                        line_num = WorkflowParser.get_line(top_perms, key)
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                file_path=file_path,
                                line=line_num,
                                severity=Severity.HIGH,
                                title="Over-privileged Permission Scope Declared",
                                message=f"Permission scope '{key}: {val}' grants excessive write access.",
                                remediation=self.remediation,
                                mitre_attack=self.mitre_attack,
                            )
                        )
        else:
            # Missing top-level permissions block
            jobs = ast.get("jobs", {})
            # Check if all jobs define their own permissions
            all_jobs_define_perms = False
            if isinstance(jobs, dict) and jobs:
                all_jobs_define_perms = all(
                    isinstance(job, dict) and "permissions" in job
                    for job in jobs.values()
                )

            if not all_jobs_define_perms:
                # Flag missing permissions at root
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        file_path=file_path,
                        line=1,
                        severity=Severity.MEDIUM,
                        title="Missing Explicit Workflow Permissions Block",
                        message=(
                            "Workflow does not declare an explicit 'permissions:' block at the root or job level. "
                            "Without an explicit block, GITHUB_TOKEN inherits repository default permissions, "
                            "which default to read-and-write in many repositories."
                        ),
                        remediation=self.remediation,
                        mitre_attack=self.mitre_attack,
                    )
                )

        # 2. Check per-job level permissions for write-all
        jobs = ast.get("jobs", {})
        if isinstance(jobs, dict):
            for job_id, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                job_perms = job.get("permissions")
                if isinstance(job_perms, str) and job_perms.strip().lower() == "write-all":
                    line_num = WorkflowParser.get_line(job, "permissions")
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            file_path=file_path,
                            line=line_num,
                            severity=Severity.HIGH,
                            title=f"Job-Level 'write-all' Permissions Declared in '{job_id}'",
                            message=(
                                f"Job '{job_id}' explicitly grants 'permissions: write-all'. "
                                "Steps executing in this job run with elevated write access across all scopes."
                            ),
                            remediation=self.remediation,
                            mitre_attack=self.mitre_attack,
                        )
                    )

        return findings
