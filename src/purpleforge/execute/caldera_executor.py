"""Caldera operation executor — creates adversaries, runs operations, collects results."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from purpleforge.clients.caldera_client import CalderaClient, CalderaOperationTimeoutError
from purpleforge.models.emulation import EmulationMethod, EmulationRecord, EmulationStatus, ResolvedTechnique

logger = logging.getLogger(__name__)


class CalderaExecutor:
    """Execute Caldera operations for resolved techniques."""

    def __init__(self, client: CalderaClient, run_id: str, timeout: int = 300, poll_interval: int = 5) -> None:
        self._client = client
        self._run_id = run_id
        self._timeout = timeout
        self._poll_interval = poll_interval

    def execute(self, techniques: list[ResolvedTechnique]) -> list[EmulationRecord]:
        """Execute all Caldera techniques as a single operation.

        Creates an adversary with all ability IDs, then creates and polls an operation.
        Supports idempotency: checks for existing operation with the same name.
        """
        ability_ids = [t.ability_id for t in techniques if t.ability_id]
        if not ability_ids:
            return []

        op_name = f"purpleforge-{self._run_id}"

        # Create adversary
        adversary = self._client.create_adversary(
            name=op_name,
            ability_ids=ability_ids,
        )
        adversary_id = adversary.get("adversary_id", "")

        # Check for existing operation (idempotency)
        existing_ops = self._client.list_operations()
        existing = next((op for op in existing_ops if op.get("name") == op_name), None)

        if existing and existing.get("state") == "finished":
            logger.info("Reusing existing finished operation %s", existing["id"])
            return self._extract_results(existing, techniques)

        if existing and existing.get("state") == "running":
            logger.info("Resuming existing operation %s", existing["id"])
            op = self._client.wait_for_operation(
                existing["id"], timeout=self._timeout, poll_interval=self._poll_interval
            )
            return self._extract_results(op, techniques)

        # Create new operation
        start_time = datetime.now(UTC)
        op = self._client.create_operation(
            name=op_name,
            adversary_id=adversary_id,
        )
        operation_id = op.get("id", "")

        try:
            finished_op = self._client.wait_for_operation(
                operation_id, timeout=self._timeout, poll_interval=self._poll_interval
            )
            return self._extract_results(finished_op, techniques, start_time)
        except CalderaOperationTimeoutError:
            return [
                EmulationRecord(
                    technique_id=t.technique_id,
                    method=EmulationMethod.CALDERA,
                    status=EmulationStatus.TIMEOUT,
                    execution_id=operation_id,
                    start_time=start_time,
                    error_message=f"Caldera operation timed out after {self._timeout}s",
                )
                for t in techniques
            ]

    def _extract_results(
        self,
        operation: dict,
        techniques: list[ResolvedTechnique],
        start_time: datetime | None = None,
    ) -> list[EmulationRecord]:
        """Extract per-technique results from a completed Caldera operation."""
        chain = operation.get("chain", [])
        now = datetime.now(UTC)
        start = start_time or now

        # Build a map from technique_id to link results
        link_map: dict[str, dict] = {}
        for link in chain:
            ability = link.get("ability", {})
            tid = ability.get("technique_id", "")
            if tid:
                link_map[tid] = link

        records: list[EmulationRecord] = []
        for technique in techniques:
            tid = technique.technique_id
            parent_tid = tid[:5] if "." in tid else tid

            # Match by exact or parent technique
            link = link_map.get(tid) or link_map.get(parent_tid)

            if link:
                status_code = link.get("status", -1)
                records.append(EmulationRecord(
                    technique_id=tid,
                    method=EmulationMethod.CALDERA,
                    status=EmulationStatus.SUCCESS if status_code == 0 else EmulationStatus.FAILED,
                    execution_id=str(link.get("id", "")),
                    start_time=start,
                    end_time=now,
                    raw_output=str(link.get("output", ""))[:5000],
                ))
            else:
                records.append(EmulationRecord(
                    technique_id=tid,
                    method=EmulationMethod.CALDERA,
                    status=EmulationStatus.FAILED,
                    start_time=start,
                    end_time=now,
                    error_message=f"No matching link in operation chain for {tid}",
                ))

        return records
