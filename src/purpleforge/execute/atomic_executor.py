"""Atomic Red Team executor: runs tests via WinRM, then cleans up."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from purpleforge.clients.atomic_runner import AtomicRunner, WinRMConnectionError
from purpleforge.models.emulation import EmulationMethod, EmulationRecord, EmulationStatus, ResolvedTechnique

logger = logging.getLogger(__name__)


class AtomicExecutor:
    """Execute Atomic Red Team tests for resolved techniques."""

    def __init__(self, runner: AtomicRunner, test_timeout: int = 120) -> None:
        self._runner = runner
        self._test_timeout = test_timeout

    def execute(self, techniques: list[ResolvedTechnique]) -> list[EmulationRecord]:
        """Execute Atomic tests sequentially via WinRM, cleaning up after each.

        Individual technique failures are recorded but do not abort other techniques.
        Cleanup runs after every attempt so persistence artifacts do not linger on
        the host; a cleanup failure is noted but does not fail the technique.
        """
        records: list[EmulationRecord] = []

        for technique in techniques:
            start_time = datetime.now(UTC)
            try:
                result = self._runner.run_technique(
                    technique.technique_id,
                    timeout_seconds=self._test_timeout,
                )
                end_time = datetime.now(UTC)

                status = EmulationStatus.SUCCESS if result["status_code"] == 0 else EmulationStatus.FAILED
                error = result.get("error")
                cleanup_note = self._cleanup(technique.technique_id)
                if cleanup_note:
                    error = f"{error}; {cleanup_note}" if error else cleanup_note

                records.append(
                    EmulationRecord(
                        technique_id=technique.technique_id,
                        method=EmulationMethod.ATOMIC,
                        status=status,
                        execution_id=f"atomic-{technique.technique_id}",
                        start_time=start_time,
                        end_time=end_time,
                        raw_output=result["output"][:5000],
                        error_message=error,
                    )
                )

            except WinRMConnectionError as e:
                records.append(
                    EmulationRecord(
                        technique_id=technique.technique_id,
                        method=EmulationMethod.ATOMIC,
                        status=EmulationStatus.ERROR,
                        start_time=start_time,
                        end_time=datetime.now(UTC),
                        error_message=str(e),
                    )
                )

        return records

    def _cleanup(self, technique_id: str) -> str:
        """Run cleanup for a technique. Returns a note on failure, empty on success."""
        try:
            result = self._runner.cleanup_technique(technique_id)
        except WinRMConnectionError as e:
            logger.warning("Cleanup unreachable for %s: %s", technique_id, e)
            return f"cleanup unreachable: {e}"
        if result["status_code"] != 0:
            logger.warning("Cleanup failed for %s", technique_id)
            return f"cleanup failed: {result.get('error') or 'nonzero exit'}"
        return ""
