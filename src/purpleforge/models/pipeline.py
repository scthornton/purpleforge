"""Pipeline orchestration state models."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class RunStatus(str, Enum):
    CREATED = "created"
    INGESTING = "ingesting"
    AWAITING_REVIEW = "awaiting_review"
    RESOLVING = "resolving"
    EXECUTING = "executing"
    WAITING = "waiting"
    VALIDATING = "validating"
    REPORTING = "reporting"
    ADVISING = "advising"
    COMPLETE = "complete"
    FAILED = "failed"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    SKIPPED = "skipped"


class PipelineStep(BaseModel):
    """Record of a single pipeline step execution."""

    step_name: str
    status: StepStatus = StepStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    artifact_path: str | None = None


class PipelineRun(BaseModel):
    """Top-level run state. Serialized to run_state.yaml."""

    run_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    source_path: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: RunStatus = RunStatus.CREATED
    current_step: str = ""
    steps: list[PipelineStep] = Field(default_factory=list)
    config_snapshot: dict = Field(default_factory=dict)
    error: str | None = None
