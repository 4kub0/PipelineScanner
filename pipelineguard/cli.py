"""Command-line interface for PipelineGuard with Rich terminal diagnostics."""

import sys
from pathlib import Path
from typing import Optional

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
from pipelineguard.formatters import format_json, format_sarif

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="pipelineguard")
def main() -> None:
    """PipelineGuard: Static Security Analyzer for GitHub Actions CI/CD Workflows."""
    pass


@main.command(name="scan")
@click.argument("path", default=".github/workflows", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["table", "json", "sarif"], case_sensitive=False),
    default="table",
    help="Output format: table (default), json, or sarif.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Output file path (defaults to stdout).",
)
def scan_command(path: str, output_format: str, output_file: Optional[str]) -> None:
    """Scan GitHub Actions workflow YAML files for security vulnerabilities."""
    target = Path(path)
    engine = ScanEngine()
    fmt = output_format.lower()

    # In table mode without file output, display interactive spinner and banners
    if fmt == "table" and not output_file:
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
    else:
        report = engine.scan_path(target)

    # Handle structured machine-readable formats (JSON and SARIF)
    if fmt in ("json", "sarif"):
        content = format_json(report) if fmt == "json" else format_sarif(report)
        if output_file:
            Path(output_file).write_text(content, encoding="utf-8")
            console.print(f"[bold green]✓ Report exported successfully to {output_file}[/bold green]")
        else:
            click.echo(content)

        sys.exit(1 if report.has_findings else 0)

    # Handle Table format
    if not report.has_findings:
        if output_file:
            Path(output_file).write_text("Scan Passed: No vulnerabilities detected.\n", encoding="utf-8")
            console.print(f"[bold green]✓ Scan Passed: Report saved to {output_file}[/bold green]")
        else:
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

    if output_file:
        file_console = Console(record=True, width=120)
        file_console.print(table)
        file_console.print(
            f"Scan Failed: Found {len(report.findings)} issue(s) across {report.scanned_files} file(s)."
        )
        Path(output_file).write_text(file_console.export_text(), encoding="utf-8")
        console.print(f"[bold red]Scan Failed: Report saved to {output_file}[/bold red]")
    else:
        console.print(table)
        console.print()
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
