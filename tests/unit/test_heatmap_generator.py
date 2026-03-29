"""Tests for ATT&CK Navigator heatmap generator."""

from __future__ import annotations

from purpleforge.models.evidence import CoverageResult, EvidenceChain
from purpleforge.report.heatmap_generator import HeatmapGenerator


class TestHeatmapGenerator:
    def test_generates_valid_navigator_structure(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        result = CoverageResult(
            run_id="test-run",
            total_techniques=4,
            detected_count=1,
            partial_count=1,
            missed_count=1,
            skipped_count=1,
            coverage_pct=66.7,
            strict_coverage_pct=33.3,
            evidence_chains=sample_evidence_chains,
            skipped_techniques=["T1071.001"],
        )

        gen = HeatmapGenerator()
        layer = gen.generate(result)

        # Required Navigator fields
        assert layer["name"].startswith("PurpleForge")
        assert layer["domain"] == "enterprise-attack"
        assert "versions" in layer
        assert "techniques" in layer
        assert "gradient" in layer
        assert "legendItems" in layer

    def test_correct_technique_count(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        result = CoverageResult(
            run_id="test-run",
            total_techniques=4,
            detected_count=1,
            partial_count=1,
            missed_count=1,
            skipped_count=1,
            coverage_pct=66.7,
            strict_coverage_pct=33.3,
            evidence_chains=sample_evidence_chains,
            skipped_techniques=["T1071.001"],
        )

        gen = HeatmapGenerator()
        layer = gen.generate(result)
        assert len(layer["techniques"]) == 4  # 3 chains + 1 skipped

    def test_color_mapping(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        result = CoverageResult(
            run_id="test-run",
            total_techniques=3,
            detected_count=1,
            partial_count=1,
            missed_count=1,
            skipped_count=0,
            coverage_pct=66.7,
            strict_coverage_pct=33.3,
            evidence_chains=sample_evidence_chains,
        )

        gen = HeatmapGenerator()
        layer = gen.generate(result)
        colors = {t["techniqueID"]: t["color"] for t in layer["techniques"]}
        assert colors["T1059.001"] == "#a1d99b"  # detected = green
        assert colors["T1053.005"] == "#fee08b"  # partial = yellow
        assert colors["T1003.001"] == "#fc8d59"  # missed = red

    def test_json_output(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        import json

        result = CoverageResult(
            run_id="test-run",
            total_techniques=3,
            detected_count=1,
            partial_count=1,
            missed_count=1,
            skipped_count=0,
            coverage_pct=66.7,
            strict_coverage_pct=33.3,
            evidence_chains=sample_evidence_chains,
        )
        gen = HeatmapGenerator()
        json_str = gen.to_json(result)
        parsed = json.loads(json_str)
        assert parsed["domain"] == "enterprise-attack"
