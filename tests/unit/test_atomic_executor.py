"""Tests for the Atomic executor: timeout plumbing and post-run cleanup."""

from __future__ import annotations

from unittest.mock import MagicMock

from purpleforge.clients.atomic_runner import WinRMConnectionError
from purpleforge.execute.atomic_executor import AtomicExecutor
from purpleforge.models.emulation import EmulationMethod, EmulationStatus, ResolvedTechnique


def _tech(tid: str) -> ResolvedTechnique:
    return ResolvedTechnique(technique_id=tid, technique_name="x", method=EmulationMethod.ATOMIC)


def test_cleanup_runs_after_success() -> None:
    runner = MagicMock()
    runner.run_technique.return_value = {"output": "done", "status_code": 0, "error": None}
    runner.cleanup_technique.return_value = {"output": "", "status_code": 0, "error": None}

    records = AtomicExecutor(runner, test_timeout=30).execute([_tech("T1003.001")])

    runner.run_technique.assert_called_once_with("T1003.001", timeout_seconds=30)
    runner.cleanup_technique.assert_called_once_with("T1003.001")
    assert records[0].status == EmulationStatus.SUCCESS


def test_cleanup_failure_is_noted_not_fatal() -> None:
    runner = MagicMock()
    runner.run_technique.return_value = {"output": "done", "status_code": 0, "error": None}
    runner.cleanup_technique.return_value = {"output": "", "status_code": 1, "error": "left artifacts"}

    records = AtomicExecutor(runner).execute([_tech("T1003.001")])

    assert records[0].status == EmulationStatus.SUCCESS
    assert "cleanup failed" in (records[0].error_message or "")


def test_connection_error_records_error_and_skips_cleanup() -> None:
    runner = MagicMock()
    runner.run_technique.side_effect = WinRMConnectionError("unreachable")

    records = AtomicExecutor(runner).execute([_tech("T1003.001")])

    assert records[0].status == EmulationStatus.ERROR
    runner.cleanup_technique.assert_not_called()
