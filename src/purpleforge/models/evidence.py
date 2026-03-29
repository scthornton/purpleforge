"""Evidence chain models — the core data structure backing all coverage claims."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class MatchType(str, Enum):
    EXACT_TECHNIQUE = "exact_technique"
    PARENT_TECHNIQUE = "parent_technique"
    TIME_CORRELATION = "time_correlation"
    NONE = "none"


class DetectionConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class CoverageStatus(str, Enum):
    """Classification of detection coverage for a technique."""

    DETECTED = "detected"
    PARTIAL = "partial"
    MISSED = "missed"


class DetectionMatch(BaseModel):
    """A single detection alert that matched an emulated technique."""

    alert_id: str
    alert_timestamp: datetime
    rule_name: str
    matched_tag: str
    match_type: MatchType
    alert_description: str = ""
    raw_alert: dict = Field(default_factory=dict)


class EvidenceChain(BaseModel):
    """Complete evidence for one technique's detection status.

    This is the core data structure. Every claim of 'detected' or 'missed'
    is backed by this chain. Without it, the coverage report is untrustworthy.
    """

    # Technique identity
    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    tactic: str

    # Emulation evidence
    emulation_step_id: str
    emulation_method: str
    execution_timestamp: datetime
    execution_end_timestamp: datetime | None = None

    # Detection query parameters
    detection_query_window_start: datetime
    detection_query_window_end: datetime
    detection_source: str = "limacharlie"

    # Detection results
    matching_alerts: list[DetectionMatch] = Field(default_factory=list)
    best_match_type: MatchType = MatchType.NONE
    confidence: DetectionConfidence = DetectionConfidence.NONE

    # Classification — uses enum instead of bare string
    status: CoverageStatus = CoverageStatus.MISSED

    # Reconciliation
    reconciliation_note: str = ""
    parent_technique_checked: str = ""


class CoverageResult(BaseModel):
    """Aggregated coverage report for an entire run."""

    run_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    total_techniques: int
    detected_count: int
    partial_count: int
    missed_count: int
    skipped_count: int
    coverage_pct: float
    strict_coverage_pct: float
    evidence_chains: list[EvidenceChain]
    skipped_techniques: list[str] = Field(default_factory=list)

    @staticmethod
    def compute_coverage_pct(detected: int, partial: int, total: int, skipped: int) -> float:
        """Compute lenient coverage: (detected + partial) / (total - skipped) * 100."""
        denominator = total - skipped
        if denominator <= 0:
            return 0.0
        return round((detected + partial) / denominator * 100, 1)

    @staticmethod
    def compute_strict_coverage_pct(detected: int, total: int, skipped: int) -> float:
        """Compute strict coverage: detected / (total - skipped) * 100."""
        denominator = total - skipped
        if denominator <= 0:
            return 0.0
        return round(detected / denominator * 100, 1)
