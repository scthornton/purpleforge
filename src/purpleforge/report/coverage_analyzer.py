"""Coverage analyzer: aggregates evidence chains into a coverage report."""

from __future__ import annotations

from purpleforge.models.evidence import CoverageResult, CoverageStatus, EvidenceChain


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
        )
