"""Models for technique resolution and emulation execution."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class EmulationMethod(str, Enum):
    CALDERA = "caldera"
    ATOMIC = "atomic"
    SKIP = "skip"


class ResolvedTechnique(BaseModel):
    """A technique with its execution method determined."""

    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    method: EmulationMethod
    ability_id: str | None = None
    parent_match: bool = False
    skip_reason: str | None = None


class ExecutionPlan(BaseModel):
    """Complete execution plan for a run."""

    run_id: str
    techniques: list[ResolvedTechnique]
    caldera_count: int = 0
    atomic_count: int = 0
    skip_count: int = 0


class EmulationStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"


class EmulationRecord(BaseModel):
    """Result of emulating a single technique."""

    technique_id: str
    method: EmulationMethod
    status: EmulationStatus
    execution_id: str = ""
    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    raw_output: str = ""
    error_message: str | None = None
