"""Tests for the execution-time Atomic fallback: target selection and result merge."""

from __future__ import annotations

from purpleforge.execute.fallback import merge_fallback_results, select_fallback_targets
from purpleforge.models.emulation import (
    EmulationMethod,
    EmulationRecord,
    EmulationStatus,
    ResolvedTechnique,
)


def _caldera_tech(tid: str, name: str = "x") -> ResolvedTechnique:
    return ResolvedTechnique(
        technique_id=tid,
        technique_name=name,
        method=EmulationMethod.CALDERA,
        ability_id=f"ability-{tid}",
    )


def _record(tid: str, status: EmulationStatus, method: EmulationMethod, error: str | None = None) -> EmulationRecord:
    return EmulationRecord(technique_id=tid, method=method, status=status, error_message=error)


class TestSelectFallbackTargets:
    def test_only_failed_caldera_records_are_retried(self) -> None:
        records = [
            _record("T1059.001", EmulationStatus.SUCCESS, EmulationMethod.CALDERA),
            _record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA),
            _record("T1057", EmulationStatus.TIMEOUT, EmulationMethod.CALDERA),
            _record("T1082", EmulationStatus.ERROR, EmulationMethod.CALDERA),
        ]
        techs = [_caldera_tech("T1059.001"), _caldera_tech("T1016"), _caldera_tech("T1057"), _caldera_tech("T1082")]

        targets = select_fallback_targets(records, techs)

        # Only the FAILED one is retried; timeout and error are different problems.
        assert [t.technique_id for t in targets] == ["T1016"]
        assert all(t.method == EmulationMethod.ATOMIC for t in targets)

    def test_technique_name_is_carried_over(self) -> None:
        records = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA)]
        techs = [_caldera_tech("T1016", name="System Network Configuration Discovery")]

        targets = select_fallback_targets(records, techs)

        assert targets[0].technique_name == "System Network Configuration Discovery"

    def test_name_defaults_to_id_when_plan_entry_absent(self) -> None:
        records = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA)]

        targets = select_fallback_targets(records, [])

        # A missing plan entry must not break target construction (name is required).
        assert targets[0].technique_name == "T1016"

    def test_no_failures_yields_no_targets(self) -> None:
        records = [_record("T1059.001", EmulationStatus.SUCCESS, EmulationMethod.CALDERA)]
        assert select_fallback_targets(records, [_caldera_tech("T1059.001")]) == []


class TestMergeFallbackResults:
    def test_atomic_success_replaces_caldera_failure(self) -> None:
        caldera = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA, error="status 1")]
        atomic = [_record("T1016", EmulationStatus.SUCCESS, EmulationMethod.ATOMIC)]

        merged = merge_fallback_results(caldera, atomic)

        assert len(merged) == 1
        assert merged[0].method == EmulationMethod.ATOMIC
        assert merged[0].status == EmulationStatus.SUCCESS

    def test_atomic_failure_keeps_annotated_caldera_failure(self) -> None:
        caldera = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA, error="status 1")]
        atomic = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.ATOMIC)]

        merged = merge_fallback_results(caldera, atomic)

        assert merged[0].method == EmulationMethod.CALDERA
        assert merged[0].status == EmulationStatus.FAILED
        assert merged[0].error_message is not None
        assert "status 1" in merged[0].error_message
        assert "fallback also did not succeed" in merged[0].error_message

    def test_annotation_without_prior_error_message(self) -> None:
        caldera = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA, error=None)]
        atomic = [_record("T1016", EmulationStatus.ERROR, EmulationMethod.ATOMIC)]

        merged = merge_fallback_results(caldera, atomic)

        assert merged[0].error_message is not None
        assert merged[0].error_message.startswith("Atomic Red Team fallback also did not succeed")

    def test_success_and_unretried_records_pass_through_in_order(self) -> None:
        caldera = [
            _record("T1059.001", EmulationStatus.SUCCESS, EmulationMethod.CALDERA),
            _record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA, error="status 1"),
            _record("T1057", EmulationStatus.TIMEOUT, EmulationMethod.CALDERA),
        ]
        # Only the failed technique was retried, and it succeeded.
        atomic = [_record("T1016", EmulationStatus.SUCCESS, EmulationMethod.ATOMIC)]

        merged = merge_fallback_results(caldera, atomic)

        assert [r.technique_id for r in merged] == ["T1059.001", "T1016", "T1057"]
        assert merged[0].status == EmulationStatus.SUCCESS and merged[0].method == EmulationMethod.CALDERA
        assert merged[1].method == EmulationMethod.ATOMIC  # recovered
        assert merged[2].status == EmulationStatus.TIMEOUT  # untouched

    def test_failure_with_no_matching_retry_is_unchanged(self) -> None:
        caldera = [_record("T1016", EmulationStatus.FAILED, EmulationMethod.CALDERA, error="status 1")]

        merged = merge_fallback_results(caldera, [])

        assert merged[0].method == EmulationMethod.CALDERA
        assert merged[0].error_message == "status 1"
