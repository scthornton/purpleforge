"""Tests for the file-based RunStore."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from purpleforge.models import RunStatus, StepStatus
from purpleforge.models.emulation import (
    EmulationMethod,
    EmulationRecord,
    EmulationStatus,
    ExecutionPlan,
    ResolvedTechnique,
)
from purpleforge.pipeline.run_store import RunStore


class TestRunStoreCreate:
    def test_create_run(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        assert run.status == RunStatus.CREATED
        assert run.source_path == "/tmp/test.pdf"
        assert len(run.run_id) == 12

    def test_creates_directory(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_dir = Path(run_store.base_dir) / run.run_id
        assert run_dir.exists()
        assert (run_dir / "run_state.yaml").exists()

    def test_state_file_is_valid_yaml(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        state_path = Path(run_store.base_dir) / run.run_id / "run_state.yaml"
        data = yaml.safe_load(state_path.read_text())
        assert data["run_id"] == run.run_id
        assert data["status"] == "created"

    def test_config_snapshot_preserved(self, run_store: RunStore) -> None:
        snapshot = {"openai_model": "gpt-4o-mini", "detection_wait": 120}
        run = run_store.create_run("/tmp/test.pdf", config_snapshot=snapshot)
        loaded = run_store.load_run(run.run_id)
        assert loaded.config_snapshot == snapshot


class TestRunStoreLoad:
    def test_load_run(self, run_store: RunStore) -> None:
        original = run_store.create_run("/tmp/test.pdf")
        loaded = run_store.load_run(original.run_id)
        assert loaded.run_id == original.run_id
        assert loaded.source_path == original.source_path
        assert loaded.status == original.status

    def test_load_nonexistent_run(self, run_store: RunStore) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            run_store.load_run("nonexistent")


class TestRunStoreUpdate:
    def test_update_status(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        updated = run_store.update_status(run.run_id, RunStatus.INGESTING)
        assert updated.status == RunStatus.INGESTING

    def test_update_status_with_error(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        updated = run_store.update_status(run.run_id, RunStatus.FAILED, error="PDF parse failed")
        assert updated.status == RunStatus.FAILED
        assert updated.error == "PDF parse failed"


class TestRunStoreSteps:
    def test_start_step(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        updated = run_store.start_step(run.run_id, "INGEST")
        assert len(updated.steps) == 1
        assert updated.steps[0].step_name == "INGEST"
        assert updated.steps[0].status == StepStatus.RUNNING
        assert updated.current_step == "INGEST"

    def test_complete_step(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.start_step(run.run_id, "INGEST")
        updated = run_store.complete_step(run.run_id, "INGEST", artifact_path="extracted_ttps.yaml")
        assert updated.steps[0].status == StepStatus.COMPLETE
        assert updated.steps[0].artifact_path == "extracted_ttps.yaml"
        assert updated.steps[0].completed_at is not None

    def test_fail_step(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.start_step(run.run_id, "INGEST")
        updated = run_store.fail_step(run.run_id, "INGEST", "Embedding failed")
        assert updated.steps[0].status == StepStatus.FAILED
        assert updated.steps[0].error_message == "Embedding failed"
        assert updated.status == RunStatus.FAILED

    def test_multiple_steps(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.start_step(run.run_id, "INGEST")
        run_store.complete_step(run.run_id, "INGEST")
        run_store.start_step(run.run_id, "RESOLVE")
        updated = run_store.complete_step(run.run_id, "RESOLVE")
        assert len(updated.steps) == 2
        assert all(s.status == StepStatus.COMPLETE for s in updated.steps)


class TestRunStoreArtifacts:
    def test_write_and_read_yaml(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        data = {"techniques": [{"id": "T1059.001", "name": "PowerShell"}]}
        path = run_store.write_artifact(run.run_id, "extracted_ttps.yaml", data)
        assert path.exists()
        loaded = run_store.read_artifact(run.run_id, "extracted_ttps.yaml")
        assert loaded == data

    def test_write_and_read_json(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        data = {"detected": 3, "missed": 1, "coverage_pct": 75.0}
        path = run_store.write_artifact(run.run_id, "coverage_report.json", data)
        assert path.exists()
        loaded = run_store.read_artifact(run.run_id, "coverage_report.json")
        assert loaded == data

    def test_read_nonexistent_artifact(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        with pytest.raises(FileNotFoundError, match="not found"):
            run_store.read_artifact(run.run_id, "missing.json")

    def test_execution_plan_round_trip(self, run_store: RunStore) -> None:
        """Models dumped in json mode come back as plain strings that safe_load accepts."""
        run = run_store.create_run("/tmp/test.pdf")
        plan = ExecutionPlan(
            run_id=run.run_id,
            techniques=[
                ResolvedTechnique(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    method=EmulationMethod.CALDERA,
                    ability_id="abc-002",
                )
            ],
            caldera_count=1,
        )
        run_store.write_artifact(run.run_id, "execution_plan.yaml", plan.model_dump(mode="json"))
        loaded = run_store.read_artifact(run.run_id, "execution_plan.yaml")
        assert loaded["techniques"][0]["method"] == "caldera"
        assert ExecutionPlan.model_validate(loaded) == plan

    def test_emulation_record_round_trip(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        record = EmulationRecord(
            technique_id="T1059.001",
            method=EmulationMethod.CALDERA,
            status=EmulationStatus.SUCCESS,
            execution_id="link-1",
        )
        run_store.write_artifact(run.run_id, "emulation_results.yaml", {"records": [record.model_dump(mode="json")]})
        loaded = run_store.read_artifact(run.run_id, "emulation_results.yaml")
        assert loaded["records"][0]["status"] == "success"
        assert EmulationRecord.model_validate(loaded["records"][0]) == record

    def test_write_rejects_non_plain_objects(self, run_store: RunStore) -> None:
        """A raw enum must fail at write time instead of producing an unreadable file."""
        run = run_store.create_run("/tmp/test.pdf")
        with pytest.raises(yaml.representer.RepresenterError):
            run_store.write_artifact(run.run_id, "bad.yaml", {"method": EmulationMethod.CALDERA})
        assert not (Path(run_store.base_dir) / run.run_id / "bad.yaml").exists()

    def test_overwrite_existing_artifact(self, run_store: RunStore) -> None:
        """Path.replace overwrites an existing target on every platform."""
        run = run_store.create_run("/tmp/test.pdf")
        run_store.write_artifact(run.run_id, "x.json", {"v": 1})
        run_store.write_artifact(run.run_id, "x.json", {"v": 2})
        assert run_store.read_artifact(run.run_id, "x.json") == {"v": 2}

    def test_atomic_write_produces_no_tmp_files(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.write_artifact(run.run_id, "test.yaml", {"key": "value"})
        run_dir = Path(run_store.base_dir) / run.run_id
        tmp_files = list(run_dir.glob("*.tmp"))
        assert len(tmp_files) == 0


class TestRunStoreList:
    def test_list_empty(self, run_store: RunStore) -> None:
        runs = run_store.list_runs()
        assert len(runs) == 0

    def test_list_multiple_runs(self, run_store: RunStore) -> None:
        run_store.create_run("/tmp/a.pdf")
        run_store.create_run("/tmp/b.pdf")
        run_store.create_run("/tmp/c.pdf")
        runs = run_store.list_runs()
        assert len(runs) == 3

    def test_list_ignores_invalid_directories(self, run_store: RunStore) -> None:
        run_store.create_run("/tmp/test.pdf")
        # Create a junk directory without run_state.yaml
        junk = Path(run_store.base_dir) / "not-a-run"
        junk.mkdir()
        runs = run_store.list_runs()
        assert len(runs) == 1


class TestRunStoreLock:
    def test_acquire_then_second_acquire_raises(self, run_store: RunStore) -> None:
        from purpleforge.pipeline.run_store import RunLockedError

        run = run_store.create_run("/tmp/test.pdf")
        run_store.acquire_lock(run.run_id)
        with pytest.raises(RunLockedError, match="locked"):
            run_store.acquire_lock(run.run_id)

    def test_release_lets_acquire_again(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.acquire_lock(run.run_id)
        run_store.release_lock(run.run_id)
        # Should not raise now that the lock is gone.
        run_store.acquire_lock(run.run_id)

    def test_release_missing_lock_is_safe(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.release_lock(run.run_id)  # no lock yet; must not raise

    def test_locked_context_releases_on_error(self, run_store: RunStore) -> None:
        from purpleforge.pipeline.run_store import LOCK_FILENAME

        run = run_store.create_run("/tmp/test.pdf")
        lock_path = Path(run_store.base_dir) / run.run_id / LOCK_FILENAME
        with pytest.raises(ValueError):
            with run_store.locked(run.run_id):
                assert lock_path.exists()
                raise ValueError("boom")
        assert not lock_path.exists()
