"""Coverage analyzer: aggregates evidence chains into a coverage report."""

from __future__ import annotations

from collections import Counter

from purpleforge.models.evidence import (
    CoverageResult,
    CoverageStatus,
    EvidenceChain,
    UnattributedActivity,
    UnattributedRule,
)

# How many of the busiest unattributed rules to list in the report.
TOP_UNATTRIBUTED_RULES = 10


class CoverageAnalyzer:
    """Aggregate evidence chains into a CoverageResult."""

    def analyze(
        self,
        evidence_chains: list[EvidenceChain],
        run_id: str,
        skipped_techniques: list[str] | None = None,
    ) -> CoverageResult:
        """Classify techniques and compute coverage percentages."""
        skipped = skipped_techniques or []

        detected = sum(1 for c in evidence_chains if c.status == CoverageStatus.DETECTED)
        partial = sum(1 for c in evidence_chains if c.status == CoverageStatus.PARTIAL)
        missed = sum(1 for c in evidence_chains if c.status == CoverageStatus.MISSED)
        inconclusive = sum(1 for c in evidence_chains if c.status == CoverageStatus.INCONCLUSIVE)
        total = len(evidence_chains) + len(skipped)
        skipped_count = len(skipped)

        return CoverageResult(
            run_id=run_id,
            total_techniques=total,
            detected_count=detected,
            partial_count=partial,
            missed_count=missed,
            skipped_count=skipped_count,
            inconclusive_count=inconclusive,
            coverage_pct=CoverageResult.compute_coverage_pct(detected, partial, total, skipped_count, inconclusive),
            strict_coverage_pct=CoverageResult.compute_strict_coverage_pct(
                detected, total, skipped_count, inconclusive
            ),
            evidence_chains=evidence_chains,
            skipped_techniques=skipped,
            unattributed=self._summarize_unattributed(evidence_chains),
        )

    @staticmethod
    def _summarize_unattributed(evidence_chains: list[EvidenceChain]) -> UnattributedActivity:
        """Roll up unattributed activity across all chains, de-duplicated by alert id.

        The validator records unattributed alerts per technique window, so an
        alert sitting in several overlapping windows appears in several chains.
        Counting by unique alert id turns that duplicated noise into one honest
        number: how many distinct detections fired in the run's windows without
        matching any emulated technique, and which rules were the noisiest.
        """
        attributed_ids: set[str] = set()
        for chain in evidence_chains:
            for alert in chain.matching_alerts:
                if alert.alert_id:
                    attributed_ids.add(alert.alert_id)

        # Keep one rule name per unique unattributed alert id, skipping any id
        # that was also attributed to a technique somewhere.
        rule_by_alert: dict[str, str] = {}
        for chain in evidence_chains:
            for alert in chain.unattributed_alerts:
                aid = alert.alert_id
                if not aid or aid in attributed_ids or aid in rule_by_alert:
                    continue
                rule_by_alert[aid] = alert.rule_name or "Unknown"

        counts = Counter(rule_by_alert.values())
        top_rules = [
            UnattributedRule(rule_name=name, count=count) for name, count in counts.most_common(TOP_UNATTRIBUTED_RULES)
        ]
        return UnattributedActivity(
            attributed_count=len(attributed_ids),
            unattributed_count=len(rule_by_alert),
            top_rules=top_rules,
        )
