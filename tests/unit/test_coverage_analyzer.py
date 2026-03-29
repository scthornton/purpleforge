"""Tests for coverage analyzer."""

from __future__ import annotations

from purpleforge.models.evidence import EvidenceChain
from purpleforge.report.coverage_analyzer import CoverageAnalyzer


class TestCoverageAnalyzer:
    def test_mixed_results(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(sample_evidence_chains, "test-run")
        assert result.detected_count == 1
        assert result.partial_count == 1
        assert result.missed_count == 1
        assert result.total_techniques == 3

    def test_with_skipped(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(sample_evidence_chains, "test-run", skipped_techniques=["T1071.001", "T1105"])
        assert result.skipped_count == 2
        assert result.total_techniques == 5

    def test_coverage_pct_calculation(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(sample_evidence_chains, "test-run", skipped_techniques=["T1071.001"])
        # (1 detected + 1 partial) / (4 total - 1 skipped) * 100 = 66.7%
        assert result.coverage_pct == 66.7

    def test_strict_pct_calculation(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(sample_evidence_chains, "test-run")
        # 1 detected / (3 - 0 skipped) * 100 = 33.3%
        assert result.strict_coverage_pct == 33.3

    def test_empty_chains(self) -> None:
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze([], "test-run")
        assert result.total_techniques == 0
        assert result.coverage_pct == 0.0

    def test_all_skipped(self) -> None:
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze([], "test-run", skipped_techniques=["T1059", "T1053"])
        assert result.coverage_pct == 0.0
        assert result.skipped_count == 2
