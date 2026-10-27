"""Formatters for serializing ScanReport into JSON and OASIS SARIF v2.1.0."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pipelineguard.models import Finding, ScanReport, Severity


def severity_to_sarif_level(severity: Severity) -> str:
    """Map internal PipelineGuard severity enums to OASIS SARIF level strings."""
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    return mapping.get(severity, "warning")


def normalize_file_uri(file_path: str) -> str:
    """Normalize file path to a POSIX-compliant URI string with forward slashes."""
    p = Path(file_path)
    try:
        rel = p.resolve().relative_to(Path.cwd().resolve())
        return rel.as_posix()
    except (ValueError, RuntimeError):
        return p.as_posix()


def format_json(report: ScanReport, indent: int = 2) -> str:
    """Serialize a ScanReport into a clean, machine-readable JSON string."""
    data = {
        "version": "0.1.0",
        "scanned_files": report.scanned_files,
        "summary": {
            "total_findings": len(report.findings),
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "message": f.message,
                "file_path": normalize_file_uri(f.file_path),
                "line": f.line,
                "column": f.column,
                "mitre_attack": f.mitre_attack,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=indent)


def format_sarif(report: ScanReport, indent: int = 2) -> str:
    """Serialize a ScanReport into an OASIS SARIF v2.1.0 compliant JSON string."""
    # Known rule catalogue for rule metadata indexing
    known_rules: Dict[str, Dict[str, Any]] = {
        "PG-001": {
            "name": "PullRequestTargetPoisoning",
            "shortDescription": "PR Target Poisoning with Fork Code Checkout",
            "fullDescription": (
                "Workflows triggered by pull_request_target run in an elevated context with access to repository secrets. "
                "Checking out untrusted pull request HEAD code allows adversaries to execute malicious code with access to secrets."
            ),
            "remediation": "Replace pull_request_target with pull_request, or remove ref pointing to the untrusted head commit.",
            "defaultLevel": "error",
            "mitre": "T1195.002",
        },
        "PG-002": {
            "name": "ScriptInjection",
            "shortDescription": "Potential Script Injection via Untrusted Context Expression",
            "fullDescription": (
                "Untrusted GitHub context expressions interpolated directly inside run blocks allow command injection. "
                "Adversaries can break out of shell commands via unescaped shell metacharacters."
            ),
            "remediation": "Pass untrusted expressions through intermediate environment variables (env:) instead of inline evaluation.",
            "defaultLevel": "error",
            "mitre": "T1059",
        },
        "PG-003": {
            "name": "OverprivilegedPermissions",
            "shortDescription": "Over-privileged GITHUB_TOKEN Permissions",
            "fullDescription": (
                "Declaring permissions: write-all or omitting permissions blocks grants write privileges across all repository scopes. "
                "Compromised build dependencies can abuse this token to push backdoors or trojan releases."
            ),
            "remediation": "Declare explicit least-privilege permissions (e.g. permissions: contents: read).",
            "defaultLevel": "error",
            "mitre": "T1078",
        },
        "PG-004": {
            "name": "UnpinnedAction",
            "shortDescription": "Unpinned 3rd-Party Action Reference",
            "fullDescription": (
                "Referencing third-party actions via mutable tags (such as @v4 or @main) exposes pipelines to supply chain attacks. "
                "Adversaries compromising an action repository can repoint mutable tags to malicious code."
            ),
            "remediation": "Pin external actions to immutable 40-character commit SHAs (e.g., uses: actions/checkout@b4ffde65f...).",
            "defaultLevel": "warning",
            "mitre": "T1195.001",
        },
    }

    # Collect rule IDs present in findings
    seen_rule_ids = set()
    for f in report.findings:
        seen_rule_ids.add(f.rule_id)

    # Ensure all 4 core rules are registered in SARIF driver rules for catalog completeness
    rule_ids = sorted(list(seen_rule_ids.union(known_rules.keys())))

    sarif_rules = []
    for rid in rule_ids:
        meta = known_rules.get(
            rid,
            {
                "name": rid,
                "shortDescription": rid,
                "fullDescription": rid,
                "remediation": "",
                "defaultLevel": "warning",
                "mitre": "",
            },
        )
        rule_obj = {
            "id": rid,
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": meta["fullDescription"]},
            "help": {"text": f"Remediation: {meta['remediation']}"},
            "defaultConfiguration": {"level": meta["defaultLevel"]},
            "properties": {
                "tags": ["security", "cicd", "github-actions", "supply-chain"],
            },
        }
        if meta.get("mitre"):
            rule_obj["properties"]["mitreAttack"] = meta["mitre"]
        sarif_rules.append(rule_obj)

    sarif_results = []
    for f in report.findings:
        uri = normalize_file_uri(f.file_path)
        level = severity_to_sarif_level(f.severity)

        result_obj = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {
                "text": f"{f.title}: {f.message}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, f.line),
                            "startColumn": max(1, f.column),
                        },
                    }
                }
            ],
            "properties": {
                "severity": f.severity.value,
                "remediation": f.remediation,
            },
        }
        if f.mitre_attack:
            result_obj["properties"]["mitreAttack"] = f.mitre_attack

        sarif_results.append(result_obj)

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PipelineGuard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/shyamalpandey019-beep/vulnerable-cicd-range",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=indent)
