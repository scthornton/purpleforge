"""Comprehensive tests for all Pydantic data models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from purpleforge.models import (
    AdvisoryRule,
    Confidence,
    CoverageResult,
    CoverageStatus,
    DetectionConfidence,
    DetectionMatch,
    EmulationMethod,
    EmulationRecord,
    EmulationStatus,
    EvidenceChain,
    ExecutionPlan,
    ExtractedTTP,
    MatchType,
    NormalizedTechnique,
    PipelineRun,
    PipelineStep,
    ResolvedTechnique,
    RuleConfidence,
    RunStatus,
    StepStatus,
    ThreatReport,
    TTPExtractionResult,
)


# === Extraction Models ===


class TestExtractedTTP:
    def test_valid_technique_id(self) -> None:
        ttp = ExtractedTTP(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Uses PowerShell",
            confidence=Confidence.HIGH,
        )
        assert ttp.technique_id == "T1059.001"

    def test_valid_parent_technique_id(self) -> None:
        ttp = ExtractedTTP(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            description="Uses scripting",
            confidence=Confidence.MEDIUM,
        )
        assert ttp.technique_id == "T1059"

    def test_invalid_technique_id_short(self) -> None:
        with pytest.raises(ValidationError, match="technique_id"):
            ExtractedTTP(
                technique_id="T123",
                technique_name="Bad",
                tactic="Execution",
                description="Invalid",
                confidence=Confidence.LOW,
            )

    def test_invalid_technique_id_letters(self) -> None:
        with pytest.raises(ValidationError, match="technique_id"):
            ExtractedTTP(
                technique_id="TXXX",
                technique_name="Bad",
                tactic="Execution",
                description="Invalid",
                confidence=Confidence.LOW,
            )

    def test_invalid_technique_id_too_long(self) -> None:
        with pytest.raises(ValidationError, match="technique_id"):
            ExtractedTTP(
                technique_id="T12345",
                technique_name="Bad",
                tactic="Execution",
                description="Invalid",
                confidence=Confidence.LOW,
            )

    def test_serialization_roundtrip(self) -> None:
        ttp = ExtractedTTP(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="test",
            confidence=Confidence.HIGH,
            source_chunk="chunk text",
        )
        data = ttp.model_dump()
        restored = ExtractedTTP.model_validate(data)
        assert restored == ttp


class TestTTPExtractionResult:
    def test_empty_techniques(self) -> None:
        result = TTPExtractionResult(techniques=[])
        assert len(result.techniques) == 0

    def test_multiple_techniques(self) -> None:
        result = TTPExtractionResult(
            techniques=[
                ExtractedTTP(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    tactic="Execution",
                    description="test",
                    confidence=Confidence.HIGH,
                ),
                ExtractedTTP(
                    technique_id="T1053.005",
                    technique_name="Scheduled Task",
                    tactic="Persistence",
                    description="test",
                    confidence=Confidence.MEDIUM,
                ),
            ]
        )
        assert len(result.techniques) == 2


class TestNormalizedTechnique:
    def test_with_operator_notes(self) -> None:
        nt = NormalizedTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="test",
            operator_notes="Confirmed relevant to our environment",
        )
        assert nt.operator_notes == "Confirmed relevant to our environment"

    def test_default_empty_notes(self) -> None:
        nt = NormalizedTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="test",
        )
        assert nt.operator_notes == ""


# === Emulation Models ===


class TestResolvedTechnique:
    def test_caldera_resolution(self) -> None:
        rt = ResolvedTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            method=EmulationMethod.CALDERA,
            ability_id="abc-123",
        )
        assert rt.method == EmulationMethod.CALDERA
        assert rt.ability_id == "abc-123"
        assert rt.parent_match is False

    def test_skip_with_reason(self) -> None:
        rt = ResolvedTechnique(
            technique_id="T1071.001",
            technique_name="Web Protocols",
            method=EmulationMethod.SKIP,
            skip_reason="No emulation available",
        )
        assert rt.method == EmulationMethod.SKIP
        assert rt.skip_reason is not None

    def test_parent_match_flag(self) -> None:
        rt = ResolvedTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            method=EmulationMethod.CALDERA,
            ability_id="parent-ability",
            parent_match=True,
        )
        assert rt.parent_match is True


class TestExecutionPlan:
    def test_counts(self, sample_resolved_techniques: list[ResolvedTechnique]) -> None:
        plan = ExecutionPlan(
            run_id="test123",
            techniques=sample_resolved_techniques,
            caldera_count=2,
            atomic_count=1,
            skip_count=1,
        )
        assert plan.caldera_count + plan.atomic_count + plan.skip_count == len(plan.techniques)


class TestEmulationRecord:
    def test_success_record(self) -> None:
        now = datetime.now(UTC)
        record = EmulationRecord(
            technique_id="T1059.001",
            method=EmulationMethod.CALDERA,
            status=EmulationStatus.SUCCESS,
            execution_id="op-001",
            start_time=now,
            end_time=now,
            raw_output="command executed",
        )
        assert record.status == EmulationStatus.SUCCESS
        assert record.error_message is None

    def test_error_record(self) -> None:
        now = datetime.now(UTC)
        record = EmulationRecord(
            technique_id="T1003.001",
            method=EmulationMethod.ATOMIC,
            status=EmulationStatus.ERROR,
            start_time=now,
            error_message="WinRM connection refused",
        )
        assert record.status == EmulationStatus.ERROR
        assert record.error_message is not None

    def test_default_start_time_is_utc(self) -> None:
        record = EmulationRecord(
            technique_id="T1059",
            method=EmulationMethod.CALDERA,
            status=EmulationStatus.SUCCESS,
        )
        assert record.start_time.tzinfo is not None


# === Evidence Models ===


class TestDetectionMatch:
    def test_exact_match(self) -> None:
        now = datetime.now(UTC)
        match = DetectionMatch(
            alert_id="lc-001",
            alert_timestamp=now,
            rule_name="PowerShell Execution",
            matched_tag="t1059.001",
            match_type=MatchType.EXACT_TECHNIQUE,
        )
        assert match.match_type == MatchType.EXACT_TECHNIQUE

    def test_with_raw_alert(self) -> None:
        now = datetime.now(UTC)
        match = DetectionMatch(
            alert_id="lc-002",
            alert_timestamp=now,
            rule_name="Test Rule",
            matched_tag="t1059",
            match_type=MatchType.PARENT_TECHNIQUE,
            raw_alert={"detect": {"event": {"COMMAND_LINE": "powershell -enc ..."}}},
        )
        assert "COMMAND_LINE" in match.raw_alert["detect"]["event"]


class TestEvidenceChain:
    def test_detected_chain(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        detected = sample_evidence_chains[0]
        assert detected.status == CoverageStatus.DETECTED
        assert detected.confidence == DetectionConfidence.HIGH
        assert len(detected.matching_alerts) == 1

    def test_partial_chain_with_reconciliation(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        partial = sample_evidence_chains[1]
        assert partial.status == CoverageStatus.PARTIAL
        assert partial.confidence == DetectionConfidence.MEDIUM
        assert partial.reconciliation_note != ""
        assert partial.parent_technique_checked == "T1053"

    def test_missed_chain(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        missed = sample_evidence_chains[2]
        assert missed.status == CoverageStatus.MISSED
        assert missed.confidence == DetectionConfidence.NONE
        assert len(missed.matching_alerts) == 0

    def test_invalid_status_rejected(self) -> None:
        """CoverageStatus enum rejects invalid values."""
        with pytest.raises(ValidationError):
            EvidenceChain(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic="Execution",
                emulation_step_id="test",
                emulation_method="caldera",
                execution_timestamp=datetime.now(UTC),
                detection_query_window_start=datetime.now(UTC),
                detection_query_window_end=datetime.now(UTC),
                status="deteced",  # typo — should be rejected
            )

    def test_serialization_roundtrip(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        chain = sample_evidence_chains[0]
        data = chain.model_dump()
        restored = EvidenceChain.model_validate(data)
        assert restored.technique_id == chain.technique_id
        assert restored.status == chain.status
        assert len(restored.matching_alerts) == len(chain.matching_alerts)


class TestCoverageResult:
    def test_coverage_pct_normal(self) -> None:
        pct = CoverageResult.compute_coverage_pct(detected=3, partial=1, total=5, skipped=1)
        assert pct == 100.0  # (3+1) / (5-1) * 100

    def test_coverage_pct_partial(self) -> None:
        pct = CoverageResult.compute_coverage_pct(detected=2, partial=1, total=5, skipped=0)
        assert pct == 60.0

    def test_strict_coverage_pct(self) -> None:
        pct = CoverageResult.compute_strict_coverage_pct(detected=2, total=5, skipped=1)
        assert pct == 50.0  # 2 / (5-1) * 100

    def test_coverage_pct_all_skipped(self) -> None:
        """Division by zero guard: all techniques skipped."""
        pct = CoverageResult.compute_coverage_pct(detected=0, partial=0, total=3, skipped=3)
        assert pct == 0.0

    def test_strict_coverage_pct_all_skipped(self) -> None:
        pct = CoverageResult.compute_strict_coverage_pct(detected=0, total=3, skipped=3)
        assert pct == 0.0

    def test_coverage_pct_zero_techniques(self) -> None:
        pct = CoverageResult.compute_coverage_pct(detected=0, partial=0, total=0, skipped=0)
        assert pct == 0.0

    def test_all_detected(self, sample_evidence_chains: list[EvidenceChain]) -> None:
        result = CoverageResult(
            run_id="test123",
            total_techniques=3,
            detected_count=3,
            partial_count=0,
            missed_count=0,
            skipped_count=0,
            coverage_pct=100.0,
            strict_coverage_pct=100.0,
            evidence_chains=sample_evidence_chains,
        )
        assert result.coverage_pct == 100.0

    def test_all_missed(self) -> None:
        result = CoverageResult(
            run_id="test123",
            total_techniques=3,
            detected_count=0,
            partial_count=0,
            missed_count=3,
            skipped_count=0,
            coverage_pct=0.0,
            strict_coverage_pct=0.0,
            evidence_chains=[],
        )
        assert result.coverage_pct == 0.0
        assert result.strict_coverage_pct == 0.0


# === Advisory Models ===


class TestAdvisoryRule:
    def test_auto_deployed_always_false(self) -> None:
        rule = AdvisoryRule(
            technique_id="T1027",
            technique_name="Obfuscated Files",
            rule_yaml="title: Test\nstatus: experimental",
            confidence=RuleConfidence.MEDIUM,
            explanation="Detects obfuscation",
            limitations="May miss custom encoding",
            false_positive_notes="Legitimate encoded scripts",
        )
        assert rule.auto_deployed is False

    def test_auto_deployed_cannot_be_set_true(self) -> None:
        """auto_deployed is frozen — setting True should raise."""
        with pytest.raises(ValidationError):
            AdvisoryRule(
                technique_id="T1027",
                technique_name="Obfuscated Files",
                rule_yaml="title: Test",
                confidence=RuleConfidence.LOW,
                explanation="test",
                limitations="test",
                false_positive_notes="test",
                auto_deployed=True,
            )

    def test_advisory_id_is_uuid(self) -> None:
        rule = AdvisoryRule(
            technique_id="T1059.001",
            technique_name="PowerShell",
            rule_yaml="title: Test",
            confidence=RuleConfidence.HIGH,
            explanation="test",
            limitations="test",
            false_positive_notes="test",
        )
        assert len(rule.advisory_id) == 36  # UUID format


# === Pipeline Models ===


class TestPipelineRun:
    def test_default_values(self) -> None:
        run = PipelineRun(source_path="/tmp/test.pdf")
        assert run.status == RunStatus.CREATED
        assert len(run.run_id) == 12
        assert run.created_at.tzinfo is not None
        assert run.error is None

    def test_run_id_length(self) -> None:
        """run_id should be 12-char hex for collision resistance."""
        run = PipelineRun(source_path="/tmp/test.pdf")
        assert len(run.run_id) == 12
        int(run.run_id, 16)  # Should be valid hex

    def test_status_transitions(self) -> None:
        run = PipelineRun(source_path="/tmp/test.pdf")
        assert run.status == RunStatus.CREATED
        run.status = RunStatus.INGESTING
        assert run.status == RunStatus.INGESTING
        run.status = RunStatus.FAILED
        assert run.status == RunStatus.FAILED


class TestPipelineStep:
    def test_default_pending(self) -> None:
        step = PipelineStep(step_name="INGEST")
        assert step.status == StepStatus.PENDING
        assert step.started_at is None

    def test_with_error(self) -> None:
        step = PipelineStep(
            step_name="EXECUTE",
            status=StepStatus.FAILED,
            error_message="Caldera unreachable",
        )
        assert step.status == StepStatus.FAILED
        assert step.error_message == "Caldera unreachable"
