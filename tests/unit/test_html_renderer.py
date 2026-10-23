"""Tests for the HTML report renderer."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from purpleforge import __version__
from purpleforge.models.evidence import (
    CoverageResult,
    EvidenceChain,
    UnattributedActivity,
    UnattributedRule,
)
from purpleforge.report.html_renderer import HtmlRenderer


def _result(chains: list[EvidenceChain], unattributed: UnattributedActivity | None = None) -> CoverageResult:
    return CoverageResult(
        run_id="abc123def456",
        total_techniques=4,
        detected_count=1,
        partial_count=1,
        missed_count=1,
        skipped_count=1,
        coverage_pct=66.7,
        strict_coverage_pct=33.3,
        evidence_chains=chains,
        skipped_techniques=["T1071.001"],
        unattributed=unattributed,
    )


def test_template_ships_inside_the_package() -> None:
    assert files("purpleforge").joinpath("templates/report.html.j2").is_file()


def test_default_loader_renders(sample_evidence_chains: list[EvidenceChain]) -> None:
    html = HtmlRenderer().render(_result(sample_evidence_chains))
    assert "abc123def456" in html
    assert f"PurpleForge v{__version__}" in html
    assert "T1059.001" in html
    assert "T1071.001" in html


def test_version_is_not_hard_coded() -> None:
    source = files("purpleforge").joinpath("templates/report.html.j2").read_text()
    assert "{{ version }}" in source
    assert "v0.1.0" not in source


def test_template_dir_override(tmp_path: Path, sample_evidence_chains: list[EvidenceChain]) -> None:
    (tmp_path / "report.html.j2").write_text("custom {{ run_id }} {{ version }}")
    html = HtmlRenderer(template_dir=tmp_path).render(_result(sample_evidence_chains))
    assert html == f"custom abc123def456 {__version__}"


def test_noise_floor_section_rendered_when_present(sample_evidence_chains: list[EvidenceChain]) -> None:
    unattributed = UnattributedActivity(
        attributed_count=6,
        unattributed_count=98,
        top_rules=[UnattributedRule(rule_name="Suspicious PowerShell", count=14)],
    )
    html = HtmlRenderer().render(_result(sample_evidence_chains, unattributed))
    assert "Detection Noise Floor" in html
    assert "Suspicious PowerShell" in html
    assert "98" in html


def test_noise_floor_section_absent_when_no_unattributed(sample_evidence_chains: list[EvidenceChain]) -> None:
    # No unattributed activity (None, the default) means no noise-floor section.
    html = HtmlRenderer().render(_result(sample_evidence_chains))
    assert "Detection Noise Floor" not in html
