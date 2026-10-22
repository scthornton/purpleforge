"""PurpleForge CLI: primary user interface."""

from __future__ import annotations

from typing import TYPE_CHECKING

import click
from rich.console import Console
from rich.table import Table

from purpleforge import __version__
from purpleforge.validation import validate_run_id, validate_technique_id

if TYPE_CHECKING:
    from purpleforge.config import PurpleForgeSettings
    from purpleforge.pipeline.orchestrator import PipelineOrchestrator
    from purpleforge.pipeline.run_store import RunStore

console = Console()


def _load_settings() -> PurpleForgeSettings:
    """Load settings once. Exit non-zero on a malformed .env; never fall back silently."""
    from purpleforge.config import PurpleForgeSettings

    try:
        return PurpleForgeSettings()
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        console.print("Check your environment variables and .env file. See .env.example.")
        raise SystemExit(2)


def _load_store() -> RunStore:
    """Open the run store at the configured base directory."""
    from purpleforge.pipeline.run_store import RunStore

    return RunStore(_load_settings().run_base_dir)


def _print_run_summary(orchestrator: PipelineOrchestrator, settings: PurpleForgeSettings, run_id: str) -> float | None:
    """Print the coverage summary for a finished run. Returns the lenient coverage percent."""
    try:
        report_data = orchestrator.store.read_artifact(run_id, "coverage_report.json")
    except Exception:
        console.print(f"[green]Run {run_id} complete.[/green]")
        return None

    pct = report_data.get("coverage_pct", 0)
    d = report_data.get("detected_count", 0)
    p = report_data.get("partial_count", 0)
    m = report_data.get("missed_count", 0)
    s = report_data.get("skipped_count", 0)
    console.print()
    console.print(f"[bold green]Run {run_id} complete.[/bold green]")
    console.print(f"  Coverage: [bold]{pct}%[/bold]")
    console.print(
        f"  Detected: [green]{d}[/green] | Partial: [yellow]{p}[/yellow] | Missed: [red]{m}[/red] | Skipped: {s}"
    )
    console.print(f"  Reports at: [bold]{settings.run_base_dir}/{run_id}/[/bold]")
    return float(pct) if pct is not None else None


@click.group()
@click.version_option(version=__version__, prog_name="purpleforge")
def cli() -> None:
    """PurpleForge: Evidence-driven purple team pipeline."""


@cli.command()
@click.option("--source", default=None, type=click.Path(exists=True), help="Path to threat report PDF")
@click.option(
    "--ttps",
    "ttps_path",
    default=None,
    type=click.Path(exists=True),
    help="Path to a YAML technique list (bring your own TTPs, skips LLM extraction)",
)
@click.option("--detection-wait", default=120, type=int, help="Seconds to wait for detection propagation")
@click.option("--caldera-timeout", default=300, type=int, help="Caldera operation timeout in seconds")
@click.option("--skip-advise", is_flag=True, help="Skip advisory rule generation")
def run(
    source: str | None,
    ttps_path: str | None,
    detection_wait: int,
    caldera_timeout: int,
    skip_advise: bool,
) -> None:
    """Start a new pipeline run from a threat report PDF or a technique list."""
    console.print(f"[bold]PurpleForge v{__version__}[/bold]")

    if bool(source) == bool(ttps_path):
        raise click.UsageError("Provide exactly one of --source or --ttps.")

    from purpleforge.config import ConfigError

    settings = _load_settings()
    if source:
        try:
            settings.require_openai()
        except ConfigError as e:
            console.print(f"[red]{e}[/red]")
            raise SystemExit(2)

    # Apply CLI overrides
    settings.detection_wait_seconds = detection_wait
    settings.caldera_operation_timeout = caldera_timeout

    from purpleforge.pipeline.orchestrator import PipelineOrchestrator

    orchestrator = PipelineOrchestrator(settings, skip_advise=skip_advise)

    try:
        if source:
            with console.status("[bold green]Ingesting and extracting TTPs..."):
                run_id = orchestrator.start_run(source)
        else:
            assert ttps_path is not None
            run_id = orchestrator.start_run_from_ttps(ttps_path)
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
        table.add_column("Source excerpt", style="dim")
        for t in techniques:
            conf = t.get("confidence", "")
            style = {"high": "green", "medium": "yellow", "low": "red"}.get(conf, "")
            excerpt = " ".join((t.get("source_chunk") or "").split())[:60]
            table.add_row(
                t["technique_id"],
                t["technique_name"],
                t["tactic"],
                f"[{style}]{conf}[/{style}]" if conf else "",
                excerpt,
            )
        console.print(table)

    run_dir = f"{settings.run_base_dir}/{run_id}"
    console.print("\nReview extracted TTPs at:")
    console.print(f"  [bold]{run_dir}/extracted_ttps.yaml[/bold]")
    console.print(f"\nWhen ready: [bold]purpleforge confirm --run-id {run_id}[/bold]")


@cli.command()
@click.option("--run-id", required=True, help="Run ID to confirm")
@click.option("--ttps-file", default=None, type=click.Path(exists=True), help="Override TTPs file path")
@click.option(
    "--min-coverage",
    default=None,
    type=float,
    help="Fail with a non-zero exit if lenient coverage falls below this percentage",
)
def confirm(run_id: str, ttps_file: str | None, min_coverage: float | None) -> None:
    """Confirm extracted TTPs and proceed with emulation, validation, and reporting."""
    validate_run_id(run_id)

    from purpleforge.config import ConfigError

    settings = _load_settings()
    try:
        settings.require_caldera()
        settings.require_limacharlie()
        settings.require_winrm()
    except ConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(2)

    from purpleforge.pipeline.orchestrator import PipelineError, PipelineOrchestrator

    orchestrator = PipelineOrchestrator(settings)

    try:
        console.print(f"Confirming run [bold]{run_id}[/bold]")
        orchestrator.confirm_run(run_id, ttps_file)
    except PipelineError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Pipeline error: {e}[/red]")
        raise SystemExit(1)

    pct = _print_run_summary(orchestrator, settings, run_id)

    if min_coverage is not None and pct is not None and pct < min_coverage:
        console.print(f"[red]Coverage {pct}% is below the required {min_coverage}%.[/red]")
        raise SystemExit(3)


@cli.command()
@click.option("--run-id", required=True, help="Run ID to resume")
def resume(run_id: str) -> None:
    """Resume a failed or interrupted run from its first incomplete step."""
    validate_run_id(run_id)

    from purpleforge.config import ConfigError

    settings = _load_settings()
    try:
        settings.require_caldera()
        settings.require_limacharlie()
        settings.require_winrm()
    except ConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(2)

    from purpleforge.pipeline.orchestrator import PipelineError, PipelineOrchestrator
    from purpleforge.pipeline.run_store import RunLockedError

    orchestrator = PipelineOrchestrator(settings)

    try:
        console.print(f"Resuming run [bold]{run_id}[/bold]")
        orchestrator.resume_run(run_id)
    except RunLockedError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    except PipelineError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Pipeline error: {e}[/red]")
        raise SystemExit(1)

    _print_run_summary(orchestrator, settings, run_id)


@cli.command()
@click.option("--run-id", required=True, help="Run ID to check")
@click.option("--json", "as_json", is_flag=True, help="Emit the run state as JSON")
def status(run_id: str, as_json: bool) -> None:
    """Show current pipeline state for a run."""
    validate_run_id(run_id)
    store = _load_store()

    try:
        pipeline_run = store.load_run(run_id)
    except FileNotFoundError:
        if as_json:
            import json as json_mod

            click.echo(json_mod.dumps({"error": "not_found", "run_id": run_id}))
        else:
            console.print(f"[red]Run {run_id} not found.[/red]")
        raise SystemExit(1)

    if as_json:
        import json as json_mod

        click.echo(json_mod.dumps(pipeline_run.model_dump(mode="json")))
        return

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
    validate_run_id(run_id)

    import json as json_mod
    from pathlib import Path

    from purpleforge.models.evidence import EvidenceChain
    from purpleforge.report.coverage_analyzer import CoverageAnalyzer
    from purpleforge.report.heatmap_generator import HeatmapGenerator
    from purpleforge.report.html_renderer import HtmlRenderer

    store = _load_store()

    try:
        store.load_run(run_id)
    except FileNotFoundError:
        console.print(f"[red]Run {run_id} not found.[/red]")
        raise SystemExit(1)

    # Load evidence chains
    try:
        chains_data = store.read_artifact(run_id, "evidence_chains.json")
    except FileNotFoundError:
        console.print(
            f"[red]No evidence_chains.json found for run {run_id}. "
            "Run must complete validation before reports can be generated.[/red]"
        )
        raise SystemExit(1)

    chains = [EvidenceChain.model_validate(c) for c in chains_data]

    # Load skipped techniques from execution plan
    skipped: list[str] = []
    try:
        plan_data = store.read_artifact(run_id, "execution_plan.yaml")
        skipped = [t["technique_id"] for t in plan_data.get("techniques", []) if t.get("method") == "skip"]
    except FileNotFoundError:
        pass

    # Run coverage analysis
    analyzer = CoverageAnalyzer()
    result = analyzer.analyze(chains, run_id, skipped_techniques=skipped)

    run_dir = Path(str(store.base_dir)) / run_id

    if fmt in ("json", "all"):
        store.write_artifact(
            run_id,
            "coverage_report.json",
            json_mod.loads(result.model_dump_json()),
        )
        console.print(f"  [green]Wrote[/green] coverage_report.json at {run_dir}/")

    if fmt in ("html", "all"):
        renderer = HtmlRenderer()
        html = renderer.render(result)
        (run_dir / "coverage_report.html").write_text(html)
        console.print(f"  [green]Wrote[/green] coverage_report.html at {run_dir}/")

    if fmt in ("navigator", "all"):
        heatmap = HeatmapGenerator()
        layer = heatmap.generate(result)
        store.write_artifact(run_id, "navigator_layer.json", layer)
        console.print(f"  [green]Wrote[/green] navigator_layer.json at {run_dir}/")

    console.print(f"\n[bold green]Reports regenerated for run {run_id}.[/bold green]")


@cli.command("deploy-draft")
@click.option("--run-id", required=True, help="Run ID")
@click.option("--technique", required=True, help="Technique ID to deploy draft for")
@click.option("--target", type=click.Choice(["github", "stdout"]), default="stdout")
def deploy_draft(run_id: str, technique: str, target: str) -> None:
    """Deploy an advisory detection rule draft."""
    validate_run_id(run_id)
    validate_technique_id(technique)

    from purpleforge.config import ConfigError

    settings = _load_settings()
    store = _load_store()

    # Read the draft
    try:
        advisory = store.read_artifact(run_id, f"drafts/{technique}_advisory.json")
    except FileNotFoundError:
        console.print(f"[red]No advisory draft found for {technique} in run {run_id}[/red]")
        raise SystemExit(1)

    rule_yaml = advisory.get("rule_yaml", "")

    if target == "stdout":
        console.print(f"\n[bold]Sigma Rule Draft: {technique}[/bold]")
        console.print(f"Confidence: {advisory.get('confidence', 'unknown')}")
        console.print()
        console.print(rule_yaml)
    elif target == "github":
        try:
            settings.require_github()
        except ConfigError as e:
            console.print(f"[red]{e}[/red]")
            raise SystemExit(2)

        from purpleforge.clients.github_client import GitHubClient

        gh = GitHubClient(
            token=settings.github_token_value(),
            repo=settings.detection_repo_value(),
            base_url=settings.github_base_url,
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
@click.option("--json", "as_json", is_flag=True, help="Emit the run list as JSON")
def list_runs(as_json: bool) -> None:
    """List all pipeline runs."""
    store = _load_store()

    runs = store.list_runs()

    if as_json:
        import json as json_mod

        summaries = [
            {
                "run_id": r.run_id,
                "source_path": r.source_path,
                "status": r.status.value,
                "created_at": r.created_at.isoformat(),
            }
            for r in runs
        ]
        click.echo(json_mod.dumps(summaries))
        return

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


@cli.command()
def doctor() -> None:
    """Check connectivity and credentials for each integration. Read-only."""
    from purpleforge.config import ConfigError

    settings = _load_settings()
    rows: list[tuple[str, str, str]] = []
    any_failed = False

    def record(name: str, status: str, detail: str) -> None:
        nonlocal any_failed
        if status == "failed":
            any_failed = True
        rows.append((name, status, detail))

    # OpenAI
    try:
        settings.require_openai()
    except ConfigError:
        record("OpenAI", "not configured", "OPENAI_API_KEY not set")
    else:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=settings.openai_key(), base_url=settings.openai_base_url, timeout=10)
            client.models.list()
            record("OpenAI", "ok", settings.openai_base_url or "api.openai.com")
        except Exception as e:
            record("OpenAI", "failed", str(e)[:80])

    # Caldera
    try:
        settings.require_caldera()
    except ConfigError:
        record("Caldera", "not configured", "CALDERA_API_KEY not set")
    else:
        try:
            from purpleforge.clients.caldera_client import CalderaClient

            caldera = CalderaClient(base_url=settings.caldera_url, api_key=settings.caldera_key())
            agents = caldera.get_agents()
            caldera.close()
            record("Caldera", "ok", f"{len(agents)} agent(s), group '{settings.caldera_group}'")
        except Exception as e:
            record("Caldera", "failed", str(e)[:80])

    # LimaCharlie
    try:
        settings.require_limacharlie()
    except ConfigError:
        record("LimaCharlie", "not configured", "LC_API_KEY or LC_ORG_ID not set")
    else:
        try:
            from purpleforge.clients.limacharlie_client import LimaCharlieClient

            lc = LimaCharlieClient(api_key=settings.lc_key(), org_id=settings.lc_org())
            lc._token(force_refresh=True)  # force the JWT exchange as a connectivity probe
            lc.close()
            record("LimaCharlie", "ok", f"org {settings.lc_org()}")
        except Exception as e:
            record("LimaCharlie", "failed", str(e)[:80])

    # WinRM
    try:
        settings.require_winrm()
    except ConfigError:
        record("WinRM", "not configured", "WINRM_HOST or WINRM_PASSWORD not set")
    else:
        try:
            from purpleforge.clients.atomic_runner import AtomicRunner

            runner = AtomicRunner(
                host=settings.winrm_host_value(),
                user=settings.winrm_user,
                password=settings.winrm_pass(),
                port=settings.winrm_port,
                transport=settings.winrm_transport,
                use_https=settings.winrm_use_https,
                server_cert_validation=settings.winrm_cert_validation,
                ca_trust_path=settings.winrm_ca_trust_path,
            )
            runner.check_connection()
            record("WinRM", "ok", settings.winrm_host_value())
        except Exception as e:
            record("WinRM", "failed", str(e)[:80])

    table = Table(title="PurpleForge doctor")
    table.add_column("Integration")
    table.add_column("Status")
    table.add_column("Detail", style="dim")
    status_style = {"ok": "green", "failed": "red", "not configured": "yellow"}
    for name, status, detail in rows:
        style = status_style.get(status, "")
        table.add_row(name, f"[{style}]{status}[/{style}]" if style else status, detail)
    console.print(table)

    if any_failed:
        raise SystemExit(1)


@cli.command("install-atomic")
def install_atomic() -> None:
    """Install Atomic Red Team on the configured WinRM target (explicit operator action).

    This reaches the pinned upstream installer and runs it on the target host.
    Run it only against a host you own or are authorized to test. Installation is
    never performed automatically by run or confirm.
    """
    from purpleforge.clients.atomic_runner import AtomicInstallError, AtomicRunner, WinRMConnectionError
    from purpleforge.config import ConfigError

    settings = _load_settings()
    try:
        settings.require_winrm()
    except ConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(2)
    runner = AtomicRunner(
        host=settings.winrm_host_value(),
        user=settings.winrm_user,
        password=settings.winrm_pass(),
        port=settings.winrm_port,
        transport=settings.winrm_transport,
        use_https=settings.winrm_use_https,
        server_cert_validation=settings.winrm_cert_validation,
        ca_trust_path=settings.winrm_ca_trust_path,
        installer_ref=settings.atomic_installer_ref,
    )
    console.print(f"Installing Atomic Red Team ({settings.atomic_installer_ref}) on {settings.winrm_host}...")
    try:
        runner.check_connection()
        runner.ensure_atomic_installed()
    except (WinRMConnectionError, AtomicInstallError) as e:
        console.print(f"[red]Install failed: {e}[/red]")
        raise SystemExit(1)
    console.print("[green]Atomic Red Team is installed.[/green]")
