"""Shared test fixtures."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from purpleforge.models import (
    CoverageStatus,
    DetectionConfidence,
    DetectionMatch,
    EmulationMethod,
    EmulationRecord,
    EmulationStatus,
    EvidenceChain,
    MatchType,
    ResolvedTechnique,
)
from purpleforge.pipeline.run_store import RunStore


@pytest.fixture
def tmp_run_dir(tmp_path: Path) -> str:
    """Provide a temporary directory for run storage."""
    return str(tmp_path / "runs")


@pytest.fixture
def run_store(tmp_run_dir: str) -> RunStore:
    """Provide a RunStore backed by a temp directory."""
    return RunStore(tmp_run_dir)


@pytest.fixture
def sample_resolved_techniques() -> list[ResolvedTechnique]:
    return [
        ResolvedTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            method=EmulationMethod.CALDERA,
            ability_id="abc-123",
        ),
        ResolvedTechnique(
            technique_id="T1053.005",
            technique_name="Scheduled Task",
            method=EmulationMethod.CALDERA,
            ability_id="def-456",
        ),
        ResolvedTechnique(
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            method=EmulationMethod.ATOMIC,
        ),
        ResolvedTechnique(
            technique_id="T1071.001",
            technique_name="Web Protocols",
            method=EmulationMethod.SKIP,
            skip_reason="No emulation available for T1071.001",
        ),
    ]


@pytest.fixture
def sample_emulation_records() -> list[EmulationRecord]:
    now = datetime.now(UTC)
    return [
        EmulationRecord(
            technique_id="T1059.001",
            method=EmulationMethod.CALDERA,
            status=EmulationStatus.SUCCESS,
            execution_id="op-link-001",
            start_time=now,
            end_time=now,
        ),
        EmulationRecord(
            technique_id="T1053.005",
            method=EmulationMethod.CALDERA,
            status=EmulationStatus.SUCCESS,
            execution_id="op-link-002",
            start_time=now,
            end_time=now,
        ),
        EmulationRecord(
            technique_id="T1003.001",
            method=EmulationMethod.ATOMIC,
            status=EmulationStatus.SUCCESS,
            execution_id="winrm-001",
            start_time=now,
            end_time=now,
        ),
    ]


@pytest.fixture
def sample_evidence_chains() -> list[EvidenceChain]:
    now = datetime.now(UTC)
    return [
        EvidenceChain(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            emulation_step_id="op-link-001",
            emulation_method="caldera",
            execution_timestamp=now,
            detection_query_window_start=now,
            detection_query_window_end=now,
            matching_alerts=[
                DetectionMatch(
                    alert_id="lc-001",
                    alert_timestamp=now,
                    rule_name="PowerShell Execution",
                    matched_tag="t1059.001",
                    match_type=MatchType.EXACT_TECHNIQUE,
                )
            ],
            best_match_type=MatchType.EXACT_TECHNIQUE,
            confidence=DetectionConfidence.HIGH,
            status=CoverageStatus.DETECTED,
        ),
        EvidenceChain(
            technique_id="T1053.005",
            technique_name="Scheduled Task",
            tactic="Persistence",
            emulation_step_id="op-link-002",
            emulation_method="caldera",
            execution_timestamp=now,
            detection_query_window_start=now,
            detection_query_window_end=now,
            matching_alerts=[
                DetectionMatch(
                    alert_id="lc-002",
                    alert_timestamp=now,
                    rule_name="Scheduled Task Created",
                    matched_tag="t1053",
                    match_type=MatchType.PARENT_TECHNIQUE,
                )
            ],
            best_match_type=MatchType.PARENT_TECHNIQUE,
            confidence=DetectionConfidence.MEDIUM,
            status=CoverageStatus.PARTIAL,
            reconciliation_note="Matched parent T1053 for sub-technique T1053.005",
            parent_technique_checked="T1053",
        ),
        EvidenceChain(
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Credential Access",
            emulation_step_id="winrm-001",
            emulation_method="atomic",
            execution_timestamp=now,
            detection_query_window_start=now,
            detection_query_window_end=now,
            best_match_type=MatchType.NONE,
            confidence=DetectionConfidence.NONE,
            status=CoverageStatus.MISSED,
        ),
    ]
