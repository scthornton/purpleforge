"""Models for AI-generated advisory detection rule drafts."""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class RuleConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AdvisoryRule(BaseModel):
    """An AI-generated draft detection rule. NEVER auto-deployed."""

    advisory_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    rule_yaml: str
    confidence: RuleConfidence
    explanation: str
    limitations: str
    false_positive_notes: str
    suggested_log_sources: list[str] = Field(default_factory=list)
    auto_deployed: Literal[False] = False
