"""Tests for the Caldera executor: timestamps, link output, agent checks, cleanup."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

from purpleforge.clients.caldera_client import CalderaNoAgentsError
from purpleforge.execute.caldera_executor import CalderaExecutor, parse_caldera_time
from purpleforge.models.emulation import EmulationMethod, EmulationStatus, ResolvedTechnique


def _tech(tid: str) -> ResolvedTechnique:
    return ResolvedTechnique(
        technique_id=tid,
        technique_name="x",
        method=EmulationMethod.CALDERA,
        ability_id=f"ability-{tid}",
    )


class TestParseCalderaTime:
    def test_z_suffix(self) -> None:
        dt = parse_caldera_time("2026-10-01T10:00:00Z")
        assert dt is not None and dt.year == 2026 and dt.tzinfo is not None

    def test_space_format(self) -> None:
        assert parse_caldera_time("2026-10-01 10:00:00") is not None

    def test_empty_or_bad(self) -> None:
        assert parse_caldera_time("") is None
        assert parse_caldera_time("nonsense") is None
        assert parse_caldera_time(None) is None


class TestReusedOperation:
    def test_uses_link_timestamps_and_fetches_output(self) -> None:
        client = MagicMock()
        client.list_operations.return_value = [
            {
                "id": "op-old",
                "name": "purpleforge-run1",
                "state": "finished",
                "start": "2026-10-01T10:00:00Z",
                "chain": [
                    {
                        "id": "l1",
                        "ability": {"technique_id": "T1059.001"},
                        "status": 0,
                        "decide": "2026-10-01T10:00:30Z",
                        "finish": "2026-10-01T10:01:00Z",
                    }
                ],
            }
        ]
        client.get_link_result.return_value = "command output here"

        records = CalderaExecutor(client, run_id="run1").execute([_tech("T1059.001")])

        assert len(records) == 1
        rec = records[0]
        # Timestamp comes from the link, not from "now".
        assert rec.start_time.isoformat().startswith("2026-10-01T10:00:30")
        assert rec.end_time is not None and rec.end_time.isoformat().startswith("2026-10-01T10:01:00")
        assert rec.raw_output == "command output here"
        assert rec.status == EmulationStatus.SUCCESS
        client.get_link_result.assert_called_once_with("op-old", "l1")
        # A reused operation creates no adversary.
        client.create_adversary.assert_not_called()

    def test_missing_link_is_failed(self) -> None:
        client = MagicMock()
        client.list_operations.return_value = [
            {"id": "op", "name": "purpleforge-run1", "state": "finished", "start": "2026-10-01T10:00:00Z", "chain": []}
        ]
        records = CalderaExecutor(client, run_id="run1").execute([_tech("T1059.001")])
        assert records[0].status == EmulationStatus.FAILED
        assert "No matching link" in (records[0].error_message or "")


class TestNewOperation:
    def test_fails_before_creating_when_no_agents(self) -> None:
        client = MagicMock()
        client.list_operations.return_value = []
        client.find_agents.side_effect = CalderaNoAgentsError("no agents in group 'red'")

        with pytest.raises(CalderaNoAgentsError):
            CalderaExecutor(client, run_id="run1", group="red").execute([_tech("T1059.001")])

        client.create_adversary.assert_not_called()
        client.create_operation.assert_not_called()

    def test_deletes_adversary_after_run(self) -> None:
        client = MagicMock()
        client.list_operations.return_value = []
        client.find_agents.return_value = [{"paw": "a1", "group": "red", "trusted": True}]
        client.create_adversary.return_value = {"adversary_id": "adv-1"}
        client.create_operation.return_value = {"id": "op-1", "state": "running"}
        encoded = base64.b64encode(b"ok").decode()
        client.wait_for_operation.return_value = {
            "id": "op-1",
            "state": "finished",
            "start": "2026-10-01T10:00:00Z",
            "chain": [{"id": "l1", "ability": {"technique_id": "T1059.001"}, "status": 0}],
        }
        client.get_link_result.return_value = encoded

        records = CalderaExecutor(client, run_id="run1", group="red").execute([_tech("T1059.001")])

        assert len(records) == 1
        client.create_operation.assert_called_once()
        assert client.create_operation.call_args.kwargs["group"] == "red"
        client.delete_adversary.assert_called_once_with("adv-1")

    def test_no_abilities_returns_empty(self) -> None:
        client = MagicMock()
        no_ability = ResolvedTechnique(
            technique_id="T1059.001", technique_name="x", method=EmulationMethod.CALDERA, ability_id=None
        )
        assert CalderaExecutor(client, run_id="run1").execute([no_ability]) == []
        client.list_operations.assert_not_called()
