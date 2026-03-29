"""Tests for the file-based RunStore."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from purpleforge.models import RunStatus, StepStatus
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
