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

    try:
        from purpleforge.config import PurpleForgeSettings

        settings = PurpleForgeSettings()  # type: ignore[call-arg]
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        console.print("Ensure all required environment variables are set. See .env.example")
        raise SystemExit(2)

    # Apply CLI overrides
    settings.detection_wait_seconds = detection_wait
    settings.caldera_operation_timeout = caldera_timeout

    from purpleforge.pipeline.orchestrator import PipelineOrchestrator

    orchestrator = PipelineOrchestrator(settings)

    try:
        with console.status("[bold green]Ingesting and extracting TTPs..."):
            run_id = orchestrator.start_run(source)
    except Exception as e:
        console.print(f"[red]Pipeline error: {e}[/red]")
        raise SystemExit(1)

    # Load the extracted TTPs to display
    ttps = orchestrator.store.read_artifact(run_id, "extracted_ttps.yaml")
    techniques = ttps.get("techniques", [])

    console.print(f"\nRun ID: [bold]{run_id}[/bold]")
    console.print()

    if techniques:
        table = Table(title=f"Extracted {len(techniques)} techniques")
        table.add_column("Technique", style="cyan")
        table.add_column("Name")
        table.add_column("Tactic")
        table.add_column("Confidence")
        for t in techniques:
            conf = t.get("confidence", t.get("confidence", ""))
            style = {"high": "green", "medium": "yellow", "low": "red"}.get(conf, "")
            table.add_row(t["technique_id"], t["technique_name"], t["tactic"], f"[{style}]{conf}[/{style}]")
        console.print(table)

    run_dir = f"{settings.run_base_dir}/{run_id}"
    console.print("\nReview extracted TTPs at:")
    console.print(f"  [bold]{run_dir}/extracted_ttps.yaml[/bold]")
    console.print(f"\nWhen ready: [bold]purpleforge confirm --run-id {run_id}[/bold]")


@cli.command()
@click.option("--run-id", required=True, help="Run ID to confirm")
@click.option("--ttps-file", default=None, type=click.Path(exists=True), help="Override TTPs file path")
def confirm(run_id: str, ttps_file: str | None) -> None:
    """Confirm extracted TTPs and proceed with emulation, validation, and reporting."""
    try:
        from purpleforge.config import PurpleForgeSettings

        settings = PurpleForgeSettings()  # type: ignore[call-arg]
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        raise SystemExit(2)

    from purpleforge.pipeline.orchestrator import PipelineError, PipelineOrchestrator

    orchestrator = PipelineOrchestrator(settings)

    try:
        console.print(f"Confirming run [bold]{run_id}[/bold]")
        orchestrator.confirm_run(run_id, ttps_file)
        console.print(f"[green]Run {run_id} confirmed and processing complete.[/green]")
    except PipelineError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Pipeline error: {e}[/red]")
        raise SystemExit(1)


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
