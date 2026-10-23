"""Caldera executor: one operation per run, per-link results with server-side timestamps and output."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from purpleforge.clients.caldera_client import (
    CalderaAPIError,
    CalderaClient,
    CalderaOperationTimeoutError,
)
from purpleforge.models.emulation import EmulationMethod, EmulationRecord, EmulationStatus, ResolvedTechnique

logger = logging.getLogger(__name__)

CALDERA_TIME_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S")


def parse_caldera_time(value: Any) -> datetime | None:
    """Parse a Caldera timestamp string into an aware UTC datetime, or None when absent or malformed."""
    if not value or not isinstance(value, str):
        return None
    for fmt in CALDERA_TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _failure_reason(status_code: Any, output: str) -> str:
    """Build a concise failure reason for a non-zero Caldera link.

    The link's command output (which ``decode_link_output`` already enriched with
    stderr and any non-zero exit_code) usually carries the real cause, so its tail
    is included. This is what makes an inconclusive technique actionable instead of
    just "failed" with an empty error_message.
    """
    detail = output.strip()
    if detail:
        return f"Caldera link reported non-zero status {status_code}; output tail: {detail[-500:]}"
    return f"Caldera link reported non-zero status {status_code} with no command output captured"


def max_beacon_seconds(agents: list[dict[str, Any]]) -> int:
    """Largest agent beacon (``sleep_max``) across the agents, or 0 when unknown.

    The slowest agent bounds how long the operation needs, since each ability
    only runs when its agent next checks in.
    """
    values = [int(a["sleep_max"]) for a in agents if isinstance(a.get("sleep_max"), int | float)]
    return max(values) if values else 0


def estimate_operation_seconds(num_abilities: int, beacon_max: int, grace: int = 30) -> int:
    """Rough lower bound for every link to run: each ability waits up to one beacon."""
    return max(num_abilities, 0) * max(beacon_max, 0) + grace


def scaled_timeout(configured: int, estimated: int, ceiling: int) -> int:
    """Raise the configured timeout toward the estimate, never below configured, never above the ceiling."""
    if estimated <= configured:
        return configured
    return min(estimated, max(configured, ceiling))


class CalderaExecutor:
    """Execute the Caldera portion of an execution plan as a single operation."""

    def __init__(
        self,
        client: CalderaClient,
        run_id: str,
        timeout: int = 300,
        poll_interval: int = 5,
        group: str = "red",
        max_operation_timeout: int = 1800,
    ) -> None:
        self._client = client
        self._run_id = run_id
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._group = group
        # Ceiling for the beacon-aware timeout auto-raise, so a pathological
        # beacon cannot make the operation hang indefinitely.
        self._max_operation_timeout = max_operation_timeout
        # The operation object this executor ran or reused, for the audit report.
        self.last_operation: dict[str, Any] | None = None

    def execute(self, techniques: list[ResolvedTechnique]) -> list[EmulationRecord]:
        """Run all Caldera techniques as one operation and return per-technique records.

        Reuses an operation named for this run when one already exists (idempotent).
        For a new operation, verifies that a trusted agent is in the group before
        creating any server-side objects, and deletes the one-off adversary afterward.
        """
        ability_ids = [t.ability_id for t in techniques if t.ability_id]
        if not ability_ids:
            return []

        op_name = f"purpleforge-{self._run_id}"
        existing = next((op for op in self._client.list_operations() if op.get("name") == op_name), None)

        if existing and existing.get("state") == "finished":
            logger.info("Reusing finished Caldera operation %s", existing.get("id"))
            self.last_operation = existing
            return self._extract_results(existing, techniques, str(existing.get("id", "")))

        if existing and existing.get("state") == "running":
            logger.info("Resuming running Caldera operation %s", existing.get("id"))
            op = self._client.wait_for_operation(
                str(existing.get("id", "")), timeout=self._timeout, poll_interval=self._poll_interval
            )
            self.last_operation = op
            return self._extract_results(op, techniques, str(existing.get("id", "")))

        # New operation. Fail before creating anything if no agent can run it.
        agents = self._client.find_agents(self._group)

        # A fixed timeout against a slow agent beacon silently times the whole
        # operation out and turns every technique inconclusive with no hint why.
        # Estimate the time this plan needs from the beacon and raise the timeout
        # to fit it, bounded so a pathological beacon cannot hang the run.
        effective_timeout = self._timeout
        beacon = max_beacon_seconds(agents)
        estimated = estimate_operation_seconds(len(ability_ids), beacon)
        if beacon > 0 and estimated > self._timeout:
            effective_timeout = scaled_timeout(self._timeout, estimated, self._max_operation_timeout)
            logger.warning(
                "Caldera plan of %d abilities with agent beacon up to %ds needs about %ds, over "
                "CALDERA_OPERATION_TIMEOUT=%ds. Raising the effective timeout to %ds for this operation; "
                "lower the agent beacon (sleep_max) or raise the timeout to avoid a silent all-inconclusive run.",
                len(ability_ids),
                beacon,
                estimated,
                self._timeout,
                effective_timeout,
            )

        adversary = self._client.create_adversary(name=op_name, ability_ids=ability_ids)
        adversary_id = str(adversary.get("adversary_id", ""))

        start_time = datetime.now(UTC)
        op = self._client.create_operation(name=op_name, adversary_id=adversary_id, group=self._group)
        operation_id = str(op.get("id", ""))
        self.last_operation = op

        try:
            finished = self._client.wait_for_operation(
                operation_id, timeout=effective_timeout, poll_interval=self._poll_interval
            )
            self.last_operation = finished
            return self._extract_results(finished, techniques, operation_id)
        except CalderaOperationTimeoutError:
            return [
                EmulationRecord(
                    technique_id=t.technique_id,
                    method=EmulationMethod.CALDERA,
                    status=EmulationStatus.TIMEOUT,
                    execution_id=operation_id,
                    start_time=start_time,
                    error_message=(
                        f"Caldera operation timed out after {effective_timeout}s "
                        f"({len(ability_ids)} abilities, agent beacon up to {beacon}s). "
                        "Lower the agent beacon (sleep_max) or raise CALDERA_OPERATION_TIMEOUT."
                    ),
                )
                for t in techniques
            ]
        finally:
            if adversary_id:
                try:
                    self._client.delete_adversary(adversary_id)
                except Exception as e:  # cleanup is best effort
                    logger.warning("Could not delete adversary %s: %s", adversary_id, e)

    def _extract_results(
        self,
        operation: dict[str, Any],
        techniques: list[ResolvedTechnique],
        operation_id: str,
    ) -> list[EmulationRecord]:
        """Build one record per technique from the operation's link chain."""
        chain = operation.get("chain", [])
        op_start = parse_caldera_time(operation.get("start"))
        now = datetime.now(UTC)

        link_map: dict[str, dict[str, Any]] = {}
        for link in chain:
            tid = link.get("ability", {}).get("technique_id", "")
            if tid:
                link_map.setdefault(tid, link)

        records: list[EmulationRecord] = []
        for technique in techniques:
            tid = technique.technique_id
            parent_tid = tid[:5] if "." in tid else tid
            link = link_map.get(tid) or link_map.get(parent_tid)

            if not link:
                records.append(
                    EmulationRecord(
                        technique_id=tid,
                        method=EmulationMethod.CALDERA,
                        status=EmulationStatus.FAILED,
                        start_time=op_start or now,
                        end_time=now,
                        error_message=f"No matching link in operation chain for {tid}",
                    )
                )
                continue

            status_code = link.get("status", -1)
            link_start = parse_caldera_time(link.get("decide")) or op_start or now
            link_end = parse_caldera_time(link.get("finish")) or parse_caldera_time(link.get("collect")) or link_start
            link_id = str(link.get("id", ""))

            raw_output = ""
            if link_id and operation_id:
                try:
                    raw_output = str(self._client.get_link_result(operation_id, link_id))
                except CalderaAPIError as e:
                    logger.warning("Could not fetch link result for %s: %s", link_id, e)

            succeeded = status_code == 0
            records.append(
                EmulationRecord(
                    technique_id=tid,
                    method=EmulationMethod.CALDERA,
                    status=EmulationStatus.SUCCESS if succeeded else EmulationStatus.FAILED,
                    execution_id=link_id,
                    start_time=link_start,
                    end_time=link_end,
                    raw_output=raw_output[:5000],
                    error_message=None if succeeded else _failure_reason(status_code, raw_output),
                )
            )

        return records
