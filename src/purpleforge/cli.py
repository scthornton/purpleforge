"""PurpleForge CLI — primary user interface."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from purpleforge import __version__

console = Console()

BANNER = r"""
[bold red] ____                   _      _____
|  _ \ _   _ _ __ _ __ | | ___|  ___|__  _ __ __ _  ___
| |_) | | | | '__| '_ \| |/ _ \ |_ / _ \| '__/ _` |/ _ \
|  __/| |_| | |  | |_) | |  __/  _| (_) | | | (_| |  __/
|_|    \__,_|_|  | .__/|_|\___|_|  \___/|_|  \__, |\___|
                 |_|                          |___/[/bold red]"""


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

    orchestrator = PipelineOrchestrator(settings, skip_advise=skip_advise)

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
    import json as json_mod
    from pathlib import Path

    from purpleforge.models.evidence import EvidenceChain
    from purpleforge.pipeline.run_store import RunStore
    from purpleforge.report.coverage_analyzer import CoverageAnalyzer
    from purpleforge.report.heatmap_generator import HeatmapGenerator
    from purpleforge.report.html_renderer import HtmlRenderer

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


@cli.command("install-atomic")
def install_atomic() -> None:
    """Install Atomic Red Team on the configured WinRM target (explicit operator action).

    This reaches the pinned upstream installer and runs it on the target host.
    Run it only against a host you own or are authorized to test. Installation is
    never performed automatically by run or confirm.
    """
    from purpleforge.clients.atomic_runner import AtomicInstallError, AtomicRunner, WinRMConnectionError
    from purpleforge.config import PurpleForgeSettings

    settings = PurpleForgeSettings()  # type: ignore[call-arg]
    runner = AtomicRunner(
        host=settings.winrm_host,
        user=settings.winrm_user,
        password=settings.winrm_password.get_secret_value(),
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


@cli.command()
def demo() -> None:
    """Show a sample pipeline run with realistic output (for screenshots/demos)."""
    console.print(BANNER)
    console.print(f"  [dim]v{__version__}[/dim]  [bold]Evidence-Driven Purple Team Pipeline[/bold]")
    console.print("  [dim]SANS SEC598 | Caldera + Atomic Red Team + LimaCharlie[/dim]")
    console.print()

    run_id = "a3f7c2e1"
    console.print(
        Panel(
            f"[bold]Run ID:[/bold] {run_id}\n"
            f"[bold]Source:[/bold] APT29_CozyBear_Campaign_Report.pdf\n"
            f"[bold]Model:[/bold]  gpt-4o  [dim]|[/dim]  [bold]Detection wait:[/bold] 120s",
            title="[bold cyan]Pipeline Run[/bold cyan]",
            border_style="cyan",
        )
    )
    console.print()

    # Phase 1: Ingest
    console.print("[bold white]Phase 1 — INGEST[/bold white]")
    console.print("  [green]\u2714[/green] Loaded 24 pages, 47 chunks from PDF")
    console.print("  [green]\u2714[/green] Embedded into ChromaDB collection")
    console.print("  [green]\u2714[/green] RAG retrieval: top 10 relevant chunks")
    console.print()

    # Extracted TTPs
    techniques = [
        ("T1059.001", "PowerShell", "Execution", "high"),
        ("T1053.005", "Scheduled Task/Job", "Persistence", "high"),
        ("T1003.001", "LSASS Memory Dump", "Credential Access", "high"),
        ("T1071.001", "Web Protocols (C2)", "Command and Control", "medium"),
        ("T1027", "Obfuscated Files", "Defense Evasion", "medium"),
        ("T1082", "System Information Discovery", "Discovery", "medium"),
        ("T1547.001", "Registry Run Keys", "Persistence", "high"),
        ("T1105", "Ingress Tool Transfer", "Command and Control", "medium"),
    ]

    table = Table(title=f"[bold]Extracted {len(techniques)} Techniques[/bold]", border_style="dim")
    table.add_column("Technique", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Tactic", style="dim")
    table.add_column("Confidence", justify="center")
    for tid, name, tactic, conf in techniques:
        style = {"high": "green", "medium": "yellow", "low": "red"}[conf]
        table.add_row(tid, name, tactic, f"[{style}]{conf}[/{style}]")
    console.print(table)
    console.print()

    # Phase 2: Resolve
    console.print("[bold white]Phase 2 — RESOLVE[/bold white]")
    console.print("  [green]\u2714[/green] Caldera: 5 abilities matched")
    console.print("  [green]\u2714[/green] Atomic Red Team: 2 fallback tests")
    console.print("  [yellow]\u26a0[/yellow] Skipped: 1 (T1105 — no available test)")
    console.print()

    # Phase 3: Execute
    console.print("[bold white]Phase 3 — EXECUTE[/bold white]")
    results = [
        ("T1059.001", "caldera", "success"),
        ("T1053.005", "caldera", "success"),
        ("T1003.001", "caldera", "success"),
        ("T1071.001", "caldera", "success"),
        ("T1027", "caldera", "failed"),
        ("T1082", "atomic", "success"),
        ("T1547.001", "atomic", "success"),
    ]
    for tid, method, status in results:
        icon = "[green]\u2714[/green]" if status == "success" else "[red]\u2718[/red]"
        method_style = "[cyan]caldera[/cyan]" if method == "caldera" else "[magenta]atomic[/magenta]"
        status_style = f"[green]{status}[/green]" if status == "success" else f"[red]{status}[/red]"
        console.print(f"  {icon} {tid}  {method_style}  {status_style}")
    console.print()

    # Phase 4: Validate
    console.print("[bold white]Phase 4 — VALIDATE[/bold white]")
    console.print("  [dim]Waiting 120s for detection propagation...[/dim]")
    console.print("  [green]\u2714[/green] Fetched 23 detections from LimaCharlie")
    console.print()

    # Coverage results
    coverage_data = [
        ("T1059.001", "PowerShell", "[bold green]DETECTED[/bold green]", "high", "exact_technique"),
        ("T1053.005", "Scheduled Task/Job", "[bold green]DETECTED[/bold green]", "high", "exact_technique"),
        ("T1003.001", "LSASS Memory Dump", "[bold green]DETECTED[/bold green]", "high", "exact_technique"),
        ("T1071.001", "Web Protocols (C2)", "[bold yellow]PARTIAL[/bold yellow]", "medium", "parent_technique"),
        ("T1027", "Obfuscated Files", "[bold red]MISSED[/bold red]", "none", "emulation failed"),
        ("T1082", "System Info Discovery", "[bold yellow]PARTIAL[/bold yellow]", "low", "time_correlation"),
        ("T1547.001", "Registry Run Keys", "[bold red]MISSED[/bold red]", "none", "none"),
        ("T1105", "Ingress Tool Transfer", "[dim]SKIPPED[/dim]", "—", "no test available"),
    ]

    cov_table = Table(title="[bold]Coverage Results[/bold]", border_style="dim")
    cov_table.add_column("Technique", style="cyan", no_wrap=True)
    cov_table.add_column("Name", style="white")
    cov_table.add_column("Status", justify="center")
    cov_table.add_column("Confidence", justify="center")
    cov_table.add_column("Match", style="dim")
    for tid, name, status, conf, match in coverage_data:
        conf_style = {"high": "green", "medium": "yellow", "low": "red", "none": "dim", "—": "dim"}[conf]
        cov_table.add_row(tid, name, status, f"[{conf_style}]{conf}[/{conf_style}]", match)
    console.print(cov_table)
    console.print()

    # Summary
    console.print("[bold white]Phase 5 — REPORT & ADVISE[/bold white]")
    console.print("  [green]\u2714[/green] coverage_report.json")
    console.print("  [green]\u2714[/green] coverage_report.html")
    console.print("  [green]\u2714[/green] navigator_layer.json  [dim](ATT&CK Navigator)[/dim]")
    console.print("  [green]\u2714[/green] 2 Sigma rule drafts generated for missed techniques")
    console.print()

    summary = Text()
    summary.append("Coverage: ", style="bold")
    summary.append("71.4%", style="bold green")
    summary.append("  |  Strict: ", style="bold")
    summary.append("42.9%", style="bold yellow")
    console.print(
        Panel(
            f"{summary}\n\n"
            f"  [green]\u2588\u2588[/green] Detected: 3    "
            f"[yellow]\u2588\u2588[/yellow] Partial:  2    "
            f"[red]\u2588\u2588[/red] Missed:   2    "
            f"[dim]\u2588\u2588[/dim] Skipped:  1",
            title="[bold]Summary[/bold]",
            border_style="green",
        )
    )
    console.print()
    console.print(f"  [dim]Reports at: data/runs/{run_id}/[/dim]")
    console.print(f"  [dim]Deploy drafts: purpleforge deploy-draft --run-id {run_id} --technique T1027[/dim]")
