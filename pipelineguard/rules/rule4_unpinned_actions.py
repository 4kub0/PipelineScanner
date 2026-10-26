"""Rule 4: Detect unpinned third-party actions using mutable tags or branch names."""

import re
from typing import Any, List
from pipelineguard.models import Finding, Severity
from pipelineguard.parser import WorkflowParser
from pipelineguard.rules.base import BaseRule


class UnpinnedActionRule(BaseRule):
    """Flags third-party actions that use mutable tags (e.g. @v4, @main) instead of full 40-character commit SHAs.

    MITRE ATT&CK: T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)
    OpenSSF Scorecard: Maintained Dependencies / Pinned Dependencies
    CWE-829: Inclusion of Functionality from Untrusted Control Sphere
    """

    rule_id = "PG-004"
    title = "Unpinned 3rd-Party Action Reference"
    severity = Severity.MEDIUM
    mitre_attack = "T1195.001"
    remediation = (
        "Pin third-party actions to an immutable 40-character commit SHA instead of a mutable tag "
        "(e.g., 'uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1')."
    )

    # 40-character hexadecimal regex for Git commit SHAs
    SHA1_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")

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

                uses = step.get("uses")
                if not isinstance(uses, str):
                    continue

                uses = uses.strip()

                # Ignore local actions and docker image references
                if uses.startswith(("./", "../", ".github/")) or uses.startswith("docker://"):
                    continue

                # Parse action reference: owner/repo@ref
                if "@" in uses:
                    action_name, ref = uses.split("@", 1)
                    ref = ref.strip()

                    # Check if the ref is a full 40-character commit SHA
                    if not self.SHA1_REGEX.match(ref):
                        line_num = WorkflowParser.get_line(step, "uses")
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                file_path=file_path,
                                line=line_num,
                                severity=self.severity,
                                title=self.title,
                                message=(
                                    f"Action '{action_name}' is pinned to mutable reference '@{ref}'. "
                                    "Tags and branches can be modified or hijacked upstream by adversaries. "
                                    "Pin to a full 40-character commit SHA to guarantee immutable execution."
                                ),
                                remediation=self.remediation,
                                mitre_attack=self.mitre_attack,
                            )
                        )

        return findings
