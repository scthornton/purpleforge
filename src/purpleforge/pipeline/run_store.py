"""File-based run state management. No database — all state is YAML/JSON on disk."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from purpleforge.models.pipeline import PipelineRun, PipelineStep, RunStatus, StepStatus


class RunStore:
    """Read/write run state and artifacts as files in a run directory."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        return self.base_dir / run_id

    def create_run(self, source_path: str, config_snapshot: dict | None = None) -> PipelineRun:
        """Create a new run directory and initialize run_state.yaml."""
        run = PipelineRun(source_path=source_path, config_snapshot=config_snapshot or {})
        run_dir = self._run_dir(run.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        self._write_state(run)
        return run

    def load_run(self, run_id: str) -> PipelineRun:
        """Load run state from run_state.yaml."""
        state_path = self._run_dir(run_id) / "run_state.yaml"
        if not state_path.exists():
            raise FileNotFoundError(f"Run {run_id} not found at {state_path}")
        data = yaml.safe_load(state_path.read_text())
        return PipelineRun.model_validate(data)

    def update_status(self, run_id: str, status: RunStatus, error: str | None = None) -> PipelineRun:
        """Update the run's top-level status."""
        run = self.load_run(run_id)
        run.status = status
        run.updated_at = datetime.now(UTC)
        if error:
            run.error = error
        self._write_state(run)
        return run

    def start_step(self, run_id: str, step_name: str) -> PipelineRun:
        """Record that a pipeline step has started."""
        run = self.load_run(run_id)
        step = PipelineStep(
            step_name=step_name,
            status=StepStatus.RUNNING,
            started_at=datetime.now(UTC),
        )
        run.steps.append(step)
        run.current_step = step_name
        run.updated_at = datetime.now(UTC)
        self._write_state(run)
        return run

    def complete_step(
        self, run_id: str, step_name: str, artifact_path: str | None = None
    ) -> PipelineRun:
        """Record that a pipeline step completed successfully."""
        run = self.load_run(run_id)
        for step in run.steps:
            if step.step_name == step_name and step.status == StepStatus.RUNNING:
                step.status = StepStatus.COMPLETE
                step.completed_at = datetime.now(UTC)
                step.artifact_path = artifact_path
                break
        run.updated_at = datetime.now(UTC)
        self._write_state(run)
        return run

    def fail_step(self, run_id: str, step_name: str, error_message: str) -> PipelineRun:
        """Record that a pipeline step failed."""
        run = self.load_run(run_id)
        for step in run.steps:
            if step.step_name == step_name and step.status == StepStatus.RUNNING:
                step.status = StepStatus.FAILED
                step.completed_at = datetime.now(UTC)
                step.error_message = error_message
                break
        run.status = RunStatus.FAILED
        run.error = error_message
        run.updated_at = datetime.now(UTC)
        self._write_state(run)
        return run

    def write_artifact(self, run_id: str, filename: str, data: Any) -> Path:
        """Write an artifact (YAML or JSON) to the run directory.

        Uses atomic write (write to .tmp, then rename) to prevent partial files.
        """
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        target = run_dir / filename
        tmp = target.with_suffix(target.suffix + ".tmp")

        if filename.endswith(".yaml") or filename.endswith(".yml"):
            content = yaml.dump(data, default_flow_style=False, sort_keys=False)
        else:
            content = json.dumps(data, indent=2, default=str)

        tmp.write_text(content)
        tmp.rename(target)
        return target

    def read_artifact(self, run_id: str, filename: str) -> Any:
        """Read an artifact from the run directory."""
        path = self._run_dir(run_id) / filename
        if not path.exists():
            raise FileNotFoundError(f"Artifact {filename} not found for run {run_id}")
        text = path.read_text()
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            return yaml.safe_load(text)
        return json.loads(text)

    def list_runs(self) -> list[PipelineRun]:
        """List all runs from the base directory, sorted by creation time descending."""
        runs: list[PipelineRun] = []
        if not self.base_dir.exists():
            return runs
        for run_dir in sorted(self.base_dir.iterdir(), reverse=True):
            state_file = run_dir / "run_state.yaml"
            if run_dir.is_dir() and state_file.exists():
                try:
                    data = yaml.safe_load(state_file.read_text())
                    runs.append(PipelineRun.model_validate(data))
                except Exception:
                    continue
        return runs

    def _write_state(self, run: PipelineRun) -> None:
        """Write run_state.yaml atomically."""
        run_dir = self._run_dir(run.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        target = run_dir / "run_state.yaml"
        tmp = target.with_suffix(".yaml.tmp")
        data = json.loads(run.model_dump_json())
        content = yaml.dump(data, default_flow_style=False, sort_keys=False)
        tmp.write_text(content)
        tmp.rename(target)
