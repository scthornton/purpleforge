"""Tests for the Caldera executor: timestamps, link output, agent checks, cleanup."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import pytest

from purpleforge.clients.caldera_client import CalderaNoAgentsError, CalderaOperationTimeoutError
from purpleforge.execute.caldera_executor import (
    CalderaExecutor,
    estimate_operation_seconds,
    max_beacon_seconds,
    parse_caldera_time,
    scaled_timeout,
)
from purpleforge.models.emulation import EmulationMethod, EmulationStatus, ResolvedTechnique


def _tech(tid: str) -> ResolvedTechnique:
    return ResolvedTechnique(
        technique_id=tid,
        technique_name="x",
        method=EmulationMethod.CALDERA,
        ability_id=f"ability-{tid}",
    )


def _techs(n: int) -> list[ResolvedTechnique]:
    return [_tech(f"T{1000 + i}") for i in range(n)]


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

    def test_failed_link_surfaces_reason(self) -> None:
        client = MagicMock()
        client.list_operations.return_value = [
            {
                "id": "op-f",
                "name": "purpleforge-run1",
                "state": "finished",
                "start": "2026-10-01T10:00:00Z",
                "chain": [
                    {
                        "id": "l1",
                        "ability": {"technique_id": "T1016"},
                        "status": 1,
                        "decide": "2026-10-01T10:00:30Z",
                        "finish": "2026-10-01T10:00:31Z",
                    }
                ],
            }
        ]
        client.get_link_result.return_value = "The system cannot find the path specified.\nexit_code: 1"

        rec = CalderaExecutor(client, run_id="run1").execute([_tech("T1016")])[0]

        assert rec.status == EmulationStatus.FAILED
        # The real cause is surfaced into error_message, not just left in raw_output.
        assert rec.error_message is not None
        assert "status 1" in rec.error_message
        assert "cannot find the path" in rec.error_message

    def test_successful_link_has_no_error_message(self) -> None:
        client = MagicMock()
        client.list_operations.return_value = [
            {
                "id": "op-s",
                "name": "purpleforge-run1",
                "state": "finished",
                "start": "2026-10-01T10:00:00Z",
                "chain": [{"id": "l1", "ability": {"technique_id": "T1033"}, "status": 0}],
            }
        ]
        client.get_link_result.return_value = "pf-win\\user"
        rec = CalderaExecutor(client, run_id="run1").execute([_tech("T1033")])[0]
        assert rec.status == EmulationStatus.SUCCESS
        assert rec.error_message is None


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


class TestBeaconTimeoutHelpers:
    def test_max_beacon_picks_largest(self) -> None:
        assert max_beacon_seconds([{"sleep_max": 30}, {"sleep_max": 60}, {"sleep_max": 5}]) == 60

    def test_max_beacon_unknown_is_zero(self) -> None:
        assert max_beacon_seconds([{"paw": "a"}, {"sleep_max": None}]) == 0
        assert max_beacon_seconds([]) == 0

    def test_estimate_scales_with_abilities_and_beacon(self) -> None:
        assert estimate_operation_seconds(6, 60, grace=30) == 6 * 60 + 30

    def test_scaled_timeout_raises_to_estimate_within_ceiling(self) -> None:
        assert scaled_timeout(300, 390, 1800) == 390

    def test_scaled_timeout_capped_at_ceiling(self) -> None:
        assert scaled_timeout(300, 6030, 500) == 500

    def test_scaled_timeout_keeps_configured_when_estimate_lower(self) -> None:
        assert scaled_timeout(300, 42, 1800) == 300

    def test_scaled_timeout_never_below_configured(self) -> None:
        # A ceiling below the configured timeout must not shrink it.
        assert scaled_timeout(600, 700, 500) == 600


class TestBeaconAwareTimeout:
    @staticmethod
    def _client_for_new_op(sleep_max: object, finished: bool = True) -> MagicMock:
        client = MagicMock()
        client.list_operations.return_value = []
        client.find_agents.return_value = [{"paw": "a1", "group": "red", "trusted": True, "sleep_max": sleep_max}]
        client.create_adversary.return_value = {"adversary_id": "adv-1"}
        client.create_operation.return_value = {"id": "op-1", "state": "running"}
        if finished:
            client.wait_for_operation.return_value = {
                "id": "op-1",
                "state": "finished",
                "start": "2026-10-01T10:00:00Z",
                "chain": [],
            }
        return client

    def test_slow_beacon_raises_effective_timeout(self, caplog: pytest.LogCaptureFixture) -> None:
        client = self._client_for_new_op(sleep_max=60)  # estimate 6*60+30 = 390 > 300
        with caplog.at_level("WARNING"):
            CalderaExecutor(client, run_id="r", timeout=300, max_operation_timeout=1800, group="red").execute(_techs(6))
        assert client.wait_for_operation.call_args.kwargs["timeout"] == 390
        assert "beacon" in caplog.text.lower()

    def test_fast_beacon_keeps_configured_timeout(self) -> None:
        client = self._client_for_new_op(sleep_max=2)  # estimate 42 < 300
        CalderaExecutor(client, run_id="r", timeout=300, group="red").execute(_techs(6))
        assert client.wait_for_operation.call_args.kwargs["timeout"] == 300

    def test_unknown_beacon_keeps_configured_timeout(self) -> None:
        client = self._client_for_new_op(sleep_max=None)
        CalderaExecutor(client, run_id="r", timeout=300, group="red").execute(_techs(6))
        assert client.wait_for_operation.call_args.kwargs["timeout"] == 300

    def test_raise_is_capped_at_ceiling(self) -> None:
        client = self._client_for_new_op(sleep_max=1000)  # estimate 6030, capped at ceiling 500
        CalderaExecutor(client, run_id="r", timeout=300, max_operation_timeout=500, group="red").execute(_techs(6))
        assert client.wait_for_operation.call_args.kwargs["timeout"] == 500

    def test_timeout_message_names_beacon_and_plan(self) -> None:
        client = self._client_for_new_op(sleep_max=60, finished=False)
        client.wait_for_operation.side_effect = CalderaOperationTimeoutError("boom")
        recs = CalderaExecutor(client, run_id="r", timeout=300, group="red").execute(_techs(6))
        assert all(r.status == EmulationStatus.TIMEOUT for r in recs)
        msg = recs[0].error_message or ""
        assert "6 abilities" in msg
        assert "beacon up to 60s" in msg
        assert "390s" in msg  # the scaled effective timeout appears in the message
