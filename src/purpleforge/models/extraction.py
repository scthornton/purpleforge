"""Models for threat report ingestion and TTP extraction."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExtractedTTP(BaseModel):
    """A single TTP extracted from a threat report by the LLM."""

    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    tactic: str
    description: str
    confidence: Confidence
    source_chunk: str = ""


class TTPExtractionResult(BaseModel):
    """Structured output schema for LLM extraction."""

    techniques: list[ExtractedTTP]


class ThreatReport(BaseModel):
    """Metadata about the ingested threat report."""

    source_path: str
    title: str = ""
    total_chunks: int = 0
    ttps: list[ExtractedTTP] = Field(default_factory=list)


class NormalizedTechnique(BaseModel):
    """A confirmed technique ready for resolution. Operator may have edited this."""

    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    technique_name: str
    tactic: str
    description: str
    operator_notes: str = ""
