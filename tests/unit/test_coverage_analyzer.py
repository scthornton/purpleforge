"""Tests for coverage analyzer."""

from __future__ import annotations

from datetime import UTC, datetime

from purpleforge.models.evidence import CoverageStatus, DetectionMatch, EvidenceChain, MatchType
from purpleforge.report.coverage_analyzer import TOP_UNATTRIBUTED_RULES, CoverageAnalyzer


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


def _match(alert_id: str, rule_name: str, match_type: MatchType = MatchType.TIME_CORRELATION) -> DetectionMatch:
    return DetectionMatch(
        alert_id=alert_id,
        alert_timestamp=datetime.now(UTC),
        rule_name=rule_name,
        matched_tag="" if match_type == MatchType.TIME_CORRELATION else "attack.t1059.001",
        match_type=match_type,
    )


def _chain_with_alerts(
    tid: str,
    status: CoverageStatus,
    matching: list[DetectionMatch] | None = None,
    unattributed: list[DetectionMatch] | None = None,
) -> EvidenceChain:
    chain = _chain(tid, status)
    chain.matching_alerts = matching or []
    chain.unattributed_alerts = unattributed or []
    return chain


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


class TestUnattributedSummary:
    def test_deduplicates_across_overlapping_windows(self) -> None:
        # The same unattributed alert sits in two techniques' windows.
        noise = _match("a1", "Suspicious PowerShell")
        chains = [
            _chain_with_alerts("T1059.001", CoverageStatus.DETECTED, unattributed=[noise]),
            _chain_with_alerts("T1057", CoverageStatus.MISSED, unattributed=[noise]),
        ]
        result = CoverageAnalyzer().analyze(chains, "r")
        assert result.unattributed is not None
        # Counted once, not twice.
        assert result.unattributed.unattributed_count == 1
        assert result.unattributed.top_rules[0].count == 1

    def test_attributed_alert_never_counted_as_unattributed(self) -> None:
        hit = _match("a1", "PowerShell rule", MatchType.EXACT_TECHNIQUE)
        # Same alert id shows up in another window's unattributed list.
        stray = _match("a1", "PowerShell rule")
        chains = [
            _chain_with_alerts("T1059.001", CoverageStatus.DETECTED, matching=[hit]),
            _chain_with_alerts("T1057", CoverageStatus.MISSED, unattributed=[stray]),
        ]
        result = CoverageAnalyzer().analyze(chains, "r")
        assert result.unattributed is not None
        assert result.unattributed.attributed_count == 1
        assert result.unattributed.unattributed_count == 0

    def test_top_rules_ranked_and_capped(self) -> None:
        unattributed = []
        # One rule with many alerts, then more rules than the cap with one alert each.
        for i in range(5):
            unattributed.append(_match(f"busy{i}", "Noisy rule"))
        for i in range(TOP_UNATTRIBUTED_RULES + 3):
            unattributed.append(_match(f"q{i}", f"Rule {i}"))
        chains = [_chain_with_alerts("T1057", CoverageStatus.MISSED, unattributed=unattributed)]
        result = CoverageAnalyzer().analyze(chains, "r")
        assert result.unattributed is not None
        assert len(result.unattributed.top_rules) == TOP_UNATTRIBUTED_RULES
        # The busiest rule leads.
        assert result.unattributed.top_rules[0].rule_name == "Noisy rule"
        assert result.unattributed.top_rules[0].count == 5
        # Every unique alert is still counted even beyond the displayed rules.
        assert result.unattributed.unattributed_count == 5 + TOP_UNATTRIBUTED_RULES + 3

    def test_no_unattributed_yields_zeros(self) -> None:
        chains = [
            _chain_with_alerts(
                "T1059.001", CoverageStatus.DETECTED, matching=[_match("a1", "x", MatchType.EXACT_TECHNIQUE)]
            )
        ]
        result = CoverageAnalyzer().analyze(chains, "r")
        assert result.unattributed is not None
        assert result.unattributed.unattributed_count == 0
        assert result.unattributed.top_rules == []
