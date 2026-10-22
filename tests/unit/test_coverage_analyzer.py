"""Tests for coverage analyzer."""

from __future__ import annotations

from datetime import UTC, datetime

from purpleforge.models.evidence import CoverageStatus, EvidenceChain
from purpleforge.report.coverage_analyzer import CoverageAnalyzer


def _chain(tid: str, status: CoverageStatus) -> EvidenceChain:
    now = datetime.now(UTC)
    return EvidenceChain(
        technique_id=tid,
        technique_name="x",
        tactic="t",
        emulation_step_id="e",
        emulation_method="caldera",
        execution_timestamp=now,
        detection_query_window_start=now,
        detection_query_window_end=now,
        status=status,
    )


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

    def test_inconclusive_excluded_from_denominator(self) -> None:
        chains = [
            _chain("T1059.001", CoverageStatus.DETECTED),
            _chain("T1053.005", CoverageStatus.MISSED),
            _chain("T1003.001", CoverageStatus.INCONCLUSIVE),
        ]
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(chains, "test-run", skipped_techniques=["T1071"])
        assert result.detected_count == 1
        assert result.missed_count == 1
        assert result.inconclusive_count == 1
        assert result.skipped_count == 1
        assert result.total_techniques == 4
        # denominator = 4 total - 1 skipped - 1 inconclusive = 2
        # lenient = (1 detected + 0 partial) / 2 = 50.0
        assert result.coverage_pct == 50.0
        # strict = 1 detected / 2 = 50.0
        assert result.strict_coverage_pct == 50.0

    def test_all_inconclusive_is_zero_not_crash(self) -> None:
        chains = [_chain("T1059.001", CoverageStatus.INCONCLUSIVE)]
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(chains, "test-run")
        assert result.inconclusive_count == 1
        assert result.coverage_pct == 0.0
        assert result.strict_coverage_pct == 0.0
