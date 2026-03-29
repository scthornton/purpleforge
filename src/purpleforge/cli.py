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
    if skip_advise:
        orchestrator._skip_advise = True

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

        # Show results summary
        try:

            report_data = orchestrator.store.read_artifact(run_id, "coverage_report.json")
            pct = report_data.get("coverage_pct", 0)
            d = report_data.get("detected_count", 0)
            p = report_data.get("partial_count", 0)
            m = report_data.get("missed_count", 0)
            s = report_data.get("skipped_count", 0)
            console.print()
            console.print(f"[bold green]Run {run_id} complete.[/bold green]")
            console.print(f"  Coverage: [bold]{pct}%[/bold]")
            console.print(
                f"  Detected: [green]{d}[/green] | Partial: [yellow]{p}[/yellow] "
                f"| Missed: [red]{m}[/red] | Skipped: {s}"
            )
            run_dir = f"{settings.run_base_dir}/{run_id}"
            console.print(f"  Reports at: [bold]{run_dir}/[/bold]")
        except Exception:
            console.print(f"[green]Run {run_id} complete.[/green]")

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
    from purpleforge.pipeline.run_store import RunStore

    try:
        from purpleforge.config import PurpleForgeSettings

        settings = PurpleForgeSettings()  # type: ignore[call-arg]
        store = RunStore(settings.run_base_dir)
    except Exception:
        store = RunStore("./data/runs")

    try:
        store.load_run(run_id)
    except FileNotFoundError:
        console.print(f"[red]Run {run_id} not found.[/red]")
        raise SystemExit(1)

    run_dir = f"{store.base_dir}/{run_id}"
    if fmt in ("json", "all"):
        console.print(f"  coverage_report.json at {run_dir}/")
    if fmt in ("html", "all"):
        console.print(f"  coverage_report.html at {run_dir}/")
    if fmt in ("navigator", "all"):
        console.print(f"  navigator_layer.json at {run_dir}/")


@cli.command("deploy-draft")
@click.option("--run-id", required=True, help="Run ID")
@click.option("--technique", required=True, help="Technique ID to deploy draft for")
@click.option("--target", type=click.Choice(["github", "stdout"]), default="stdout")
def deploy_draft(run_id: str, technique: str, target: str) -> None:
    """Deploy an advisory detection rule draft."""
    from purpleforge.pipeline.run_store import RunStore

    try:
        from purpleforge.config import PurpleForgeSettings

        settings = PurpleForgeSettings()  # type: ignore[call-arg]
        store = RunStore(settings.run_base_dir)
    except Exception:
        store = RunStore("./data/runs")

    # Read the draft
    try:
        advisory = store.read_artifact(run_id, f"drafts/{technique}_advisory.json")
    except FileNotFoundError:
        console.print(f"[red]No advisory draft found for {technique} in run {run_id}[/red]")
        raise SystemExit(1)

    rule_yaml = advisory.get("rule_yaml", "")

    if target == "stdout":
        console.print(f"\n[bold]Sigma Rule Draft — {technique}[/bold]")
        console.print(f"Confidence: {advisory.get('confidence', 'unknown')}")
        console.print()
        console.print(rule_yaml)
    elif target == "github":
        try:
            settings = PurpleForgeSettings()  # type: ignore[call-arg]
        except Exception as e:
            console.print(f"[red]Configuration error: {e}[/red]")
            raise SystemExit(2)

        if not settings.github_token or not settings.detection_repo:
            console.print("[red]GITHUB_TOKEN and DETECTION_REPO must be set for GitHub deployment[/red]")
            raise SystemExit(2)

        from purpleforge.clients.github_client import GitHubClient

        gh = GitHubClient(
            token=settings.github_token.get_secret_value(),
            repo=settings.detection_repo,
        )
        branch = f"purpleforge/{run_id}/{technique}"
        gh.create_branch(branch)
        gh.commit_file(
            branch=branch,
            path=f"sigma/{technique}.yaml",
            content=rule_yaml,
            message=f"Add draft Sigma rule for {technique} (PurpleForge {run_id})",
        )
        pr_url = gh.create_pull_request(
            branch=branch,
            title=f"Draft detection: {technique}",
            body=(
                f"**PurpleForge Advisory Draft**\n\n"
                f"- Run: {run_id}\n"
                f"- Technique: {technique}\n"
                f"- Confidence: {advisory.get('confidence', 'unknown')}\n\n"
                f"**Explanation:** {advisory.get('explanation', '')}\n\n"
                f"**Limitations:** {advisory.get('limitations', '')}\n\n"
                f"**False Positives:** {advisory.get('false_positive_notes', '')}"
            ),
        )
        console.print(f"[green]PR created: {pr_url}[/green]")


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
