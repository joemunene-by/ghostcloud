"""Rendering scan results to console, JSON, and SARIF 2.1.0."""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from ghostcloud import __version__
from ghostcloud.models import Severity
from ghostcloud.scanner import ScanResult

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

# SARIF security-severity numeric scores (0.0-10.0) per CVSS-style banding.
SARIF_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}

# SARIF only defines error/warning/note/none. Map our levels onto those.
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_console(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    if not result.findings:
        console.print(
            f"[green]No findings.[/green] Scanned {result.resources_scanned} "
            f"resource(s) with {result.checks_run} check(s)."
        )
        _render_errors(result, console)
        return

    table = Table(title="ghostcloud findings", show_lines=False, header_style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Provider", no_wrap=True)
    table.add_column("Resource")
    table.add_column("Title")

    for f in result.findings:
        style = SEVERITY_STYLE.get(f.severity, "")
        table.add_row(
            f"[{style}]{f.severity.label}[/{style}]",
            f.check_id,
            f.provider,
            f"{f.resource_id}\n[dim]{f.region}[/dim]" if f.region else f.resource_id,
            f.title,
        )

    console.print(table)

    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity.label] = counts.get(f.severity.label, 0) + 1
    summary = ", ".join(f"{v} {k.lower()}" for k, v in counts.items())
    console.print(
        f"\n[bold]{len(result.findings)} finding(s)[/bold] ({summary}) across "
        f"{result.resources_scanned} resource(s)."
    )
    _render_errors(result, console)


def _render_errors(result: ScanResult, console: Console) -> None:
    if not result.errors:
        return
    console.print(
        f"\n[yellow]{len(result.errors)} check error(s) (isolated, scan continued):[/yellow]"
    )
    for e in result.errors:
        console.print(f"  [dim]{e.check_id} on {e.resource_id}: {e.message}[/dim]")


def to_json(result: ScanResult, indent: int = 2) -> str:
    payload = {
        "tool": "ghostcloud",
        "version": __version__,
        "summary": {
            "resources_scanned": result.resources_scanned,
            "checks_run": result.checks_run,
            "findings": len(result.findings),
            "errors": len(result.errors),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": [
            {"check_id": e.check_id, "resource_id": e.resource_id, "message": e.message}
            for e in result.errors
        ],
    }
    return json.dumps(payload, indent=indent, sort_keys=False)


def to_sarif(result: ScanResult) -> str:
    """Render findings as a SARIF 2.1.0 log."""

    rules_by_id: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for f in result.findings:
        if f.check_id not in rules_by_id:
            rules_by_id[f.check_id] = {
                "id": f.check_id,
                "name": f.check_id.replace("-", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": (
                    "https://github.com/joemunene-by/ghostcloud/blob/main/README.md"
                ),
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
                "properties": {
                    "security-severity": SARIF_SECURITY_SEVERITY[f.severity],
                    "provider": f.provider,
                    "service": f.service,
                    "tags": ["security", "cspm", f.provider],
                },
            }

        sarif_results.append(
            {
                "ruleId": f.check_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": f.resource_id,
                                "kind": "resource",
                            }
                        ],
                        "physicalLocation": {
                            "artifactLocation": {"uri": _resource_uri(f.resource_id)},
                        },
                    }
                ],
                "properties": {
                    "resourceId": f.resource_id,
                    "region": f.region,
                    "severity": f.severity.label,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                },
            }
        )

    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ghostcloud",
                        "informationUri": "https://github.com/joemunene-by/ghostcloud",
                        "version": __version__,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(log, indent=2, sort_keys=False)


def _resource_uri(resource_id: str) -> str:
    """Produce a stable, URI-safe location for a resource id."""

    safe = resource_id.replace("://", "/").lstrip("/")
    return f"resource/{safe}"
