"""Atomic Red Team executor — runs tests via WinRM."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from purpleforge.clients.atomic_runner import AtomicRunner, WinRMConnectionError
from purpleforge.models.emulation import EmulationMethod, EmulationRecord, EmulationStatus, ResolvedTechnique

logger = logging.getLogger(__name__)


class AtomicExecutor:
    """Execute Atomic Red Team tests for resolved techniques."""

    def __init__(self, runner: AtomicRunner) -> None:
        self._runner = runner

    def execute(self, techniques: list[ResolvedTechnique]) -> list[EmulationRecord]:
        """Execute Atomic tests sequentially via WinRM.

        Individual technique failures are recorded but do not abort other techniques.
        """
        records: list[EmulationRecord] = []

        for technique in techniques:
            start_time = datetime.now(UTC)
            try:
                result = self._runner.run_technique(technique.technique_id)
                end_time = datetime.now(UTC)

                status = EmulationStatus.SUCCESS if result["status_code"] == 0 else EmulationStatus.FAILED
                records.append(EmulationRecord(
                    technique_id=technique.technique_id,
                    method=EmulationMethod.ATOMIC,
                    status=status,
                    execution_id=f"atomic-{technique.technique_id}",
                    start_time=start_time,
                    end_time=end_time,
                    raw_output=result["output"][:5000],
                    error_message=result.get("error"),
                ))

            except WinRMConnectionError as e:
                records.append(EmulationRecord(
                    technique_id=technique.technique_id,
                    method=EmulationMethod.ATOMIC,
                    status=EmulationStatus.ERROR,
                    start_time=start_time,
                    end_time=datetime.now(UTC),
                    error_message=str(e),
                ))

        return records
