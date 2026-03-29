"""PurpleForge CLI — primary user interface."""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table

from purpleforge import __version__

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="purpleforge")
def cli() -> None:
    """PurpleForge: Evidence-driven purple team pipeline."""


@cli.command()
@click.option("--source", required=True, type=click.Path(exists=True), help="Path to threat report PDF")
@click.option("--detection-wait", default=120, type=int, help="Seconds to wait for detection propagation")
@click.option("--caldera-timeout", default=300, type=int, help="Caldera operation timeout in seconds")
@click.option("--skip-advise", is_flag=True, help="Skip advisory rule generation")
def run(source: str, detection_wait: int, caldera_timeout: int, skip_advise: bool) -> None:
    """Start a new pipeline run. Ingests PDF and extracts TTPs."""
    console.print(f"[bold]PurpleForge v{__version__}[/bold]")
    console.print(f"Source: {source}")
    console.print("[yellow]Pipeline not yet implemented. Coming in Phase 2.[/yellow]")


@cli.command()
@click.option("--run-id", required=True, help="Run ID to confirm")
@click.option("--ttps-file", default=None, type=click.Path(exists=True), help="Override TTPs file path")
def confirm(run_id: str, ttps_file: str | None) -> None:
    """Confirm extracted TTPs and proceed with emulation, validation, and reporting."""
    console.print(f"Confirming run [bold]{run_id}[/bold]")
    console.print("[yellow]Pipeline not yet implemented. Coming in Phase 3.[/yellow]")


@cli.command()
@click.option("--run-id", required=True, help="Run ID to check")
def status(run_id: str) -> None:
    """Show current pipeline state for a run."""
    from purpleforge.pipeline.run_store import RunStore

    try:
        from purpleforge.config import PurpleForgeSettings

        settings = PurpleForgeSettings()  # type: ignore[call-arg]
        store = RunStore(settings.run_base_dir)
    except Exception:
        store = RunStore("./data/runs")

    try:
        pipeline_run = store.load_run(run_id)
    except FileNotFoundError:
        console.print(f"[red]Run {run_id} not found.[/red]")
        raise SystemExit(1)

    console.print(f"[bold]Run {pipeline_run.run_id}[/bold]")
    console.print(f"  Status: {pipeline_run.status.value}")
    console.print(f"  Source: {pipeline_run.source_path}")
    console.print(f"  Created: {pipeline_run.created_at}")

    if pipeline_run.steps:
        table = Table(title="Steps")
        table.add_column("Step")
        table.add_column("Status")
        table.add_column("Started")
        table.add_column("Completed")
        for step in pipeline_run.steps:
            table.add_row(
                step.step_name,
                step.status.value,
                str(step.started_at or ""),
                str(step.completed_at or ""),
            )
        console.print(table)

    if pipeline_run.error:
        console.print(f"  [red]Error: {pipeline_run.error}[/red]")


@cli.command()
@click.option("--run-id", required=True, help="Run ID")
@click.option("--format", "fmt", type=click.Choice(["json", "html", "navigator", "all"]), default="all")
def report(run_id: str, fmt: str) -> None:
    """Regenerate reports from existing evidence data."""
    console.print(f"Regenerating {fmt} report(s) for run [bold]{run_id}[/bold]")
    console.print("[yellow]Report generation not yet implemented. Coming in Phase 4.[/yellow]")


@cli.command("deploy-draft")
@click.option("--run-id", required=True, help="Run ID")
@click.option("--technique", required=True, help="Technique ID to deploy draft for")
@click.option("--target", type=click.Choice(["github", "stdout"]), default="stdout")
def deploy_draft(run_id: str, technique: str, target: str) -> None:
    """Deploy an advisory detection rule draft."""
    console.print(f"Deploying draft for {technique} from run [bold]{run_id}[/bold] to {target}")
    console.print("[yellow]Advisory deployment not yet implemented. Coming in Phase 5.[/yellow]")


@cli.command("list")
def list_runs() -> None:
    """List all pipeline runs."""
    from purpleforge.pipeline.run_store import RunStore

    try:
        from purpleforge.config import PurpleForgeSettings

        settings = PurpleForgeSettings()  # type: ignore[call-arg]
        store = RunStore(settings.run_base_dir)
    except Exception:
        store = RunStore("./data/runs")

    runs = store.list_runs()
    if not runs:
        console.print("[dim]No runs found.[/dim]")
        return

    table = Table(title="Pipeline Runs")
    table.add_column("Run ID")
    table.add_column("Source")
    table.add_column("Status")
    table.add_column("Created")
    for r in runs:
        table.add_row(r.run_id, r.source_path, r.status.value, str(r.created_at))
    console.print(table)
