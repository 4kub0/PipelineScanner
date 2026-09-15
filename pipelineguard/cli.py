"""Command-line interface for PipelineGuard with Rich terminal diagnostics."""

import sys
from pathlib import Path

# Ensure UTF-8 encoding on Windows legacy consoles
if sys.platform == "win32":
    try:
        if sys.stdout.encoding != "utf-8":
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr.encoding != "utf-8":
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pipelineguard.engine import ScanEngine
from pipelineguard.models import Severity

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="pipelineguard")
def main() -> None:
    """PipelineGuard: Static Security Analyzer for GitHub Actions CI/CD Workflows."""
    pass


@main.command(name="scan")
@click.argument("path", default=".github/workflows", type=click.Path(exists=True))
def scan_command(path: str) -> None:
    """Scan GitHub Actions workflow YAML files for security vulnerabilities."""
    target = Path(path)
    engine = ScanEngine()

    console.print(
        Panel.fit(
            "[bold cyan]🛡️  PipelineGuard Static Security Engine[/bold cyan]\n"
            "[dim]AST-based CI/CD Supply-Chain Vulnerability Linter[/dim]",
            border_style="cyan",
        )
    )

    console.print(f"[bold]Target:[/bold] [yellow]{target.resolve()}[/yellow]\n")

    with console.status("[bold green]Scanning workflow AST nodes...[/bold green]"):
        report = engine.scan_path(target)

    if not report.has_findings:
        console.print(
            Panel(
                f"[bold green]✓ Scan Passed: No vulnerabilities detected![/bold green]\n"
                f"[dim]Scanned {report.scanned_files} workflow file(s). All security checks passed.[/dim]",
                border_style="green",
            )
        )
        sys.exit(0)

    # Render findings table
    table = Table(
        title="[bold red]🚨 Detected Security Vulnerabilities[/bold red]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Rule ID", width=10)
    table.add_column("Location", width=35)
    table.add_column("Details & Remediation")

    for f in report.findings:
        sev_color = "red" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "yellow"
        location = f"{Path(f.file_path).name}:{f.line}"

        detail_text = (
            f"[bold]{f.title}[/bold]\n"
            f"[dim]{f.message}[/dim]\n"
            f"[italic green]Fix: {f.remediation}[/italic green]"
        )
        if f.mitre_attack:
            detail_text += f"\n[dim cyan]MITRE ATT&CK: {f.mitre_attack}[/dim cyan]"

        table.add_row(
            f"[{sev_color}]{f.severity.value}[/{sev_color}]",
            f.rule_id,
            location,
            detail_text,
        )

    console.print(table)
    console.print()

    # Summary Panel
    console.print(
        Panel(
            f"[bold red]Scan Failed:[/bold red] Found [bold]{len(report.findings)}[/bold] issue(s) "
            f"across {report.scanned_files} file(s).\n"
            f"  • Critical: [red]{report.critical_count}[/red]\n"
            f"  • High:     [bright_red]{report.high_count}[/bright_red]\n"
            f"  • Medium:   [yellow]{report.medium_count}[/yellow]\n"
            f"  • Low:      [blue]{report.low_count}[/blue]",
            border_style="red",
        )
    )

    sys.exit(1)


if __name__ == "__main__":
    main()
