"""ghostcloud command-line interface."""

from __future__ import annotations

import logging
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ghostcloud import __version__
from ghostcloud.checks import default_registry
from ghostcloud.models import PROVIDERS, Severity
from ghostcloud.report import render_console, to_json, to_sarif
from ghostcloud.scanner import scan as run_scan
from ghostcloud.snapshot import SnapshotError, load_snapshot

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Multi-cloud security posture management and misconfiguration scanner.",
)

console = Console()
err_console = Console(stderr=True)


class ProviderChoice(str, Enum):
    aws = "aws"
    gcp = "gcp"
    azure = "azure"
    all = "all"


class FormatChoice(str, Enum):
    console = "console"
    json = "json"
    sarif = "sarif"


class SeverityChoice(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    def to_severity(self) -> Severity:
        return Severity.from_str(self.value)


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


@app.command()
def version() -> None:
    """Print the ghostcloud version."""

    console.print(f"ghostcloud {__version__}")


@app.command()
def checks(
    provider: ProviderChoice = typer.Option(
        ProviderChoice.all, "--provider", "-p", help="Filter checks by provider."
    ),
) -> None:
    """List the available security checks."""

    registry = default_registry()
    selected = registry.for_provider(provider.value)
    selected.sort(key=lambda c: (c.provider, c.service, c.id))

    table = Table(title=f"ghostcloud checks ({len(selected)})", header_style="bold")
    table.add_column("ID", no_wrap=True)
    table.add_column("Provider", no_wrap=True)
    table.add_column("Service", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Title")

    for c in selected:
        table.add_row(c.id, c.provider, c.service, c.severity.label, c.title)

    console.print(table)


@app.command()
def scan(  # noqa: C901 - top-level command wiring is intentionally linear
    input: Path = typer.Option(  # noqa: A002 - matches documented flag name
        ...,
        "--input",
        "-i",
        help="Path to a normalized resource snapshot JSON file.",
        exists=False,
    ),
    provider: ProviderChoice = typer.Option(
        ProviderChoice.all, "--provider", "-p", help="Provider scope to scan."
    ),
    output_format: FormatChoice = typer.Option(
        FormatChoice.console, "--format", "-f", help="Output format."
    ),
    min_severity: SeverityChoice = typer.Option(
        SeverityChoice.info,
        "--min-severity",
        help="Only report findings at or above this severity.",
    ),
    fail_on: SeverityChoice | None = typer.Option(
        None,
        "--fail-on",
        help="Exit non-zero if any reported finding is at or above this severity.",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the report to this file instead of stdout."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Scan a resource snapshot and report misconfigurations."""

    _configure_logging(verbose)

    try:
        snapshot = load_snapshot(input)
    except SnapshotError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    registry = default_registry()
    result = run_scan(snapshot, registry, provider=provider.value)
    result = result.filter_severity(min_severity.to_severity())

    if output_format is FormatChoice.console and output is None:
        render_console(result, console)
    else:
        if output_format is FormatChoice.json:
            text = to_json(result)
        elif output_format is FormatChoice.sarif:
            text = to_sarif(result)
        else:
            # console format written to a file: render plain text without color.
            file_console = Console(record=True, file=None)
            render_console(result, file_console)
            text = file_console.export_text()
        if output is not None:
            output.write_text(text + "\n", encoding="utf-8")
            console.print(f"[green]wrote[/green] {len(result.findings)} finding(s) to {output}")
        else:
            # Emit machine-readable output verbatim. Using a plain print avoids
            # rich reflowing or styling the JSON/SARIF payload.
            print(text)

    if fail_on is not None and result.has_at_or_above(fail_on.to_severity()):
        raise typer.Exit(code=1)


def main() -> None:  # pragma: no cover - thin wrapper for console_scripts parity
    app()


# Reference PROVIDERS so the import is meaningful for downstream tooling/tests.
assert set(PROVIDERS) == {"aws", "gcp", "azure"}


if __name__ == "__main__":  # pragma: no cover
    app()
