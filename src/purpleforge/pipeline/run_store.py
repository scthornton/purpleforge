"""File-based run state management. No database, all state is YAML/JSON on disk."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from purpleforge import __version__
from purpleforge.models.pipeline import PipelineRun, PipelineStep, RunStatus, StepStatus

LOCK_FILENAME = ".lock"
MANIFEST_FILENAME = "manifest.json"
LOG_FILENAME = "run.log"

# Files excluded from the evidence manifest: the lock, the manifest itself, the
# run log, and any in-progress temp file.
_MANIFEST_EXCLUDE = {LOCK_FILENAME, MANIFEST_FILENAME, LOG_FILENAME}


def _current_operator() -> str:
    """Best-effort local operator name, empty when it cannot be determined."""
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USER", "")


class RunLockedError(Exception):
    """Raised when a run already holds a lock, so a second process may not run it."""


class RunStore:
    """Read/write run state and artifacts as files in a run directory."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _run_dir(self, run_id: str) -> Path:
        return self.base_dir / run_id

    def _lock_path(self, run_id: str) -> Path:
        return self._run_dir(run_id) / LOCK_FILENAME

    def acquire_lock(self, run_id: str) -> Path:
        """Create a lock file for the run. Raise RunLockedError if one already exists."""
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self._lock_path(run_id)
        try:
            # O_CREAT | O_EXCL fails if the file exists, so the check and create are atomic.
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            raise RunLockedError(
                f"Run {run_id} is locked by another process ({lock_path}). "
                f"If no run is in progress, delete the lock file and try again."
            ) from None
        with os.fdopen(fd, "w") as f:
            f.write(f"pid: {os.getpid()}\nacquired_at: {datetime.now(UTC).isoformat()}\n")
        return lock_path

    def release_lock(self, run_id: str) -> None:
        """Remove the run's lock file if it exists."""
        self._lock_path(run_id).unlink(missing_ok=True)

    @contextmanager
    def locked(self, run_id: str) -> Iterator[None]:
        """Hold the run lock for the duration of the block, releasing it even on error."""
        self.acquire_lock(run_id)
        try:
            yield
        finally:
            self.release_lock(run_id)

    def create_run(self, source_path: str, config_snapshot: dict[str, Any] | None = None) -> PipelineRun:
        """Create a new run directory and initialize run_state.yaml."""
        run = PipelineRun(
            source_path=source_path,
            config_snapshot=config_snapshot or {},
            tool_version=__version__,
            operator=_current_operator(),
            host=socket.gethostname(),
        )
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

    def complete_step(self, run_id: str, step_name: str, artifact_path: str | None = None) -> PipelineRun:
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

        Uses an atomic write (write to .tmp, then replace) to prevent partial files.
        Data must be plain YAML/JSON types; dump Pydantic models with
        model_dump(mode="json") first. Raises yaml.representer.RepresenterError
        otherwise, so a file that cannot be read back is never written.
        """
        run_dir = self._run_dir(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        target = run_dir / filename
        tmp = target.with_suffix(target.suffix + ".tmp")

        if filename.endswith(".yaml") or filename.endswith(".yml"):
            content = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
        else:
            content = json.dumps(data, indent=2, default=str)

        tmp.write_text(content)
        tmp.replace(target)
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

    def write_manifest(self, run_id: str) -> Path:
        """Write manifest.json: a SHA-256 and size for every artifact in the run.

        The manifest makes the evidence set tamper-evident. The lock file, the
        manifest itself, the run log, and any temp file are excluded. Entries are
        sorted by file name so the manifest is stable across runs.
        """
        run_dir = self._run_dir(run_id)
        entries: list[dict[str, Any]] = []
        for path in sorted(run_dir.rglob("*")):
            if not path.is_file():
                continue
            if path.name in _MANIFEST_EXCLUDE or path.suffix == ".tmp":
                continue
            raw = path.read_bytes()
            entries.append(
                {
                    "name": path.relative_to(run_dir).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
            )

        manifest = {
            "schema_version": "1",
            "tool_version": __version__,
            "generated_at": datetime.now(UTC).isoformat(),
            "files": entries,
        }
        target = run_dir / MANIFEST_FILENAME
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(manifest, indent=2))
        tmp.replace(target)
        return target

    def list_runs(self) -> list[PipelineRun]:
        """List all runs from the base directory, sorted by creation time descending."""
        runs: list[PipelineRun] = []
        if not self.base_dir.exists():
            return runs
        for run_dir in self.base_dir.iterdir():
            state_file = run_dir / "run_state.yaml"
            if run_dir.is_dir() and state_file.exists():
                try:
                    data = yaml.safe_load(state_file.read_text())
                    runs.append(PipelineRun.model_validate(data))
                except Exception:
                    continue
        runs.sort(key=lambda r: r.created_at, reverse=True)
        return runs

    def _write_state(self, run: PipelineRun) -> None:
        """Write run_state.yaml atomically."""
        run_dir = self._run_dir(run.run_id)
        run_dir.mkdir(parents=True, exist_ok=True)
        target = run_dir / "run_state.yaml"
        tmp = target.with_suffix(".yaml.tmp")
        data = json.loads(run.model_dump_json())
        content = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
        tmp.write_text(content)
        tmp.replace(target)
