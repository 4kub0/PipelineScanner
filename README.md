# 🛡️ PipelineGuard

> **Empirical CI/CD Security Scanner**: Research-grounded static analysis and linter for GitHub Actions workflows.

PipelineGuard parses GitHub Actions workflow YAML files into line-preserving Abstract Syntax Trees (ASTs), checks them against modular supply-chain security rules, and reports vulnerabilities with precise source file coordinates and actionable remediation advice.

---

## 🚀 Features (Prototype 1)
* **AST-Based Parser**: Retains exact line and column coordinates using `ruamel.yaml` in round-trip mode (zero false positives from comments or text strings).
* **Rule 1 (`PG-001`)**: Detects dangerous `pull_request_target` workflows checking out untrusted PR head commits (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`), mapped to **MITRE ATT&CK T1195.002**.
* **Rich Terminal Diagnostics**: Colored terminal reporting with file location, CWE/MITRE references, and immediate remediation steps.
* **Deterministic Exit Codes**: Exits with code `1` on security findings and code `0` on clean files, suitable for CI/CD gates.

---

## 📦 Installation

```bash
# Clone the repository
git clone <repo-url>
cd PipelineScanner

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install package in editable mode
pip install -e .
```

---

## 🔍 Usage

```bash
# Scan a directory of workflows
pipelineguard scan .github/workflows/

# Scan a specific workflow file
pipelineguard scan tests/fixtures/vulnerable/v1_pull_request_target.yml
```

---

## 🧪 Testing

Run the automated test suite with pytest:

```bash
pytest
```
