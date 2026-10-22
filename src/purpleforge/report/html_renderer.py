"""HTML report renderer using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, PackageLoader

from purpleforge import __version__
from purpleforge.models.evidence import CoverageResult

TEMPLATE_NAME = "report.html.j2"


class HtmlRenderer:
    """Render coverage results as a self-contained HTML report.

    The template ships inside the package, so rendering works from an installed
    wheel. Pass template_dir to use a custom template directory instead.
    """

    def __init__(self, template_dir: str | Path | None = None) -> None:
        loader = FileSystemLoader(str(template_dir)) if template_dir else PackageLoader("purpleforge", "templates")
        self._env = Environment(loader=loader, autoescape=True)

    def render(self, result: CoverageResult) -> str:
        """Render the coverage report HTML."""
        template = self._env.get_template(TEMPLATE_NAME)
        return template.render(
            run_id=result.run_id,
            generated_at=result.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            coverage_pct=result.coverage_pct,
            detected_count=result.detected_count,
            partial_count=result.partial_count,
            missed_count=result.missed_count,
            inconclusive_count=result.inconclusive_count,
            skipped_count=result.skipped_count,
            strict_coverage_pct=result.strict_coverage_pct,
            evidence_chains=result.evidence_chains,
            skipped_techniques=result.skipped_techniques,
            version=__version__,
        )
