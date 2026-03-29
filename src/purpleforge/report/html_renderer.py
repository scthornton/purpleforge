"""HTML report renderer using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from purpleforge.models.evidence import CoverageResult

TEMPLATE_DIR = Path(__file__).parent.parent.parent.parent / "templates"


class HtmlRenderer:
    """Render coverage results as a self-contained HTML report."""

    def __init__(self, template_dir: str | Path | None = None) -> None:
        tpl_dir = Path(template_dir) if template_dir else TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(tpl_dir)),
            autoescape=True,
        )

    def render(self, result: CoverageResult) -> str:
        """Render the coverage report HTML."""
        template = self._env.get_template("report.html.j2")
        return template.render(
            run_id=result.run_id,
            generated_at=result.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            coverage_pct=result.coverage_pct,
            detected_count=result.detected_count,
            partial_count=result.partial_count,
            missed_count=result.missed_count,
            skipped_count=result.skipped_count,
            evidence_chains=result.evidence_chains,
            skipped_techniques=result.skipped_techniques,
        )
