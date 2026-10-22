"""Tests for detection validator and evidence chain construction."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from purpleforge.models.emulation import EmulationMethod, EmulationRecord, EmulationStatus
from purpleforge.models.evidence import CoverageStatus, DetectionConfidence, MatchType
from purpleforge.validate.detection_validator import DetectionValidator

FIXTURES = Path(__file__).parent.parent / "fixtures"
DETECTIONS = json.loads((FIXTURES / "mock_limacharlie_detections.json").read_text())


@pytest.fixture
def mock_lc() -> MagicMock:
    from purpleforge.clients.limacharlie_client import LimaCharlieClient

    client = MagicMock(spec=LimaCharlieClient)
    client.get_detections_by_time_range.return_value = DETECTIONS
    # Use the real search method
    real_client = LimaCharlieClient.__new__(LimaCharlieClient)
    client.search_detections_by_technique = real_client.search_detections_by_technique
    return client


def _record(tid: str, method: str = "caldera") -> EmulationRecord:
    now = datetime.fromtimestamp(1711900050, tz=UTC)
    return EmulationRecord(
        technique_id=tid,
        method=EmulationMethod(method),
        status=EmulationStatus.SUCCESS,
        execution_id=f"exec-{tid}",
        start_time=now,
        end_time=now + timedelta(seconds=10),
    )


class TestDetectionValidator:
    def test_exact_technique_match(self, mock_lc: MagicMock) -> None:
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1059.001")])
        assert len(chains) == 1
        assert chains[0].status == CoverageStatus.DETECTED
        assert chains[0].confidence == DetectionConfidence.HIGH
        assert chains[0].best_match_type == MatchType.EXACT_TECHNIQUE

    def test_parent_technique_match(self, mock_lc: MagicMock) -> None:
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1003.001")])
        assert len(chains) == 1
        assert chains[0].status == CoverageStatus.PARTIAL
        assert chains[0].confidence == DetectionConfidence.MEDIUM
        assert chains[0].reconciliation_note != ""

    def test_no_match_is_missed(self, mock_lc: MagicMock) -> None:
        # T9999 has no matching tags
        mock_lc.get_detections_by_time_range.return_value = []
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T9999")])
        assert len(chains) == 1
        assert chains[0].status == CoverageStatus.MISSED
        assert chains[0].confidence == DetectionConfidence.NONE

    def test_failed_records_included_as_missed(self, mock_lc: MagicMock) -> None:
        """Failed emulations should appear in evidence chains as MISSED,
        not disappear from coverage math entirely."""
        now = datetime.now(UTC)
        failed = EmulationRecord(
            technique_id="T1059.001",
            method=EmulationMethod.CALDERA,
            status=EmulationStatus.FAILED,
            start_time=now,
        )
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([failed])
        assert len(chains) == 1
        assert chains[0].status == CoverageStatus.MISSED
        assert chains[0].confidence == DetectionConfidence.NONE
        assert "failed" in chains[0].reconciliation_note.lower()

    def test_multiple_techniques(self, mock_lc: MagicMock) -> None:
        records = [_record("T1059.001"), _record("T1003.001")]
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate(records)
        assert len(chains) == 2

    def test_matching_alerts_populated(self, mock_lc: MagicMock) -> None:
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1059.001")])
        assert len(chains[0].matching_alerts) > 0
        alert = chains[0].matching_alerts[0]
        assert alert.alert_id != ""
        assert alert.match_type == MatchType.EXACT_TECHNIQUE


class TestTimestampFormats:
    def test_millisecond_timestamps_are_in_window(self, mock_lc: MagicMock) -> None:
        mock_lc.get_detections_by_time_range.return_value = [{**d, "ts": d["ts"] * 1000} for d in DETECTIONS]
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1059.001")])
        assert chains[0].status == CoverageStatus.DETECTED
        assert chains[0].matching_alerts[0].alert_timestamp == datetime.fromtimestamp(1711900000, tz=UTC)

    def test_iso_string_timestamps_are_in_window(self, mock_lc: MagicMock) -> None:
        iso = [{**DETECTIONS[0], "ts": "2024-03-31T15:46:40Z"}]
        mock_lc.get_detections_by_time_range.return_value = iso
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1059.001")])
        assert chains[0].status == CoverageStatus.DETECTED
        assert chains[0].matching_alerts[0].alert_timestamp == datetime.fromtimestamp(1711900000, tz=UTC)

    def test_unparseable_timestamp_is_excluded_not_fatal(self, mock_lc: MagicMock) -> None:
        mock_lc.get_detections_by_time_range.return_value = [{**DETECTIONS[0], "ts": "garbage"}]
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1059.001")])
        assert chains[0].status == CoverageStatus.MISSED
        assert chains[0].matching_alerts == []


class TestChildTechniqueMatch:
    def test_child_tag_detects_parent_emulation(self, mock_lc: MagicMock) -> None:
        mock_lc.get_detections_by_time_range.return_value = [
            {
                "detect_id": "lc-child",
                "ts": 1711900060,
                "detect_mtd": {"description": "Scheduled task persistence", "tags": ["attack.t1053.005"]},
                "detect": {},
            }
        ]
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1053")])
        assert chains[0].status == CoverageStatus.DETECTED
        assert chains[0].confidence == DetectionConfidence.HIGH
        assert chains[0].best_match_type == MatchType.CHILD_TECHNIQUE
        assert chains[0].matching_alerts[0].matched_tag == "attack.t1053.005"
        assert "sub-technique" in chains[0].reconciliation_note
        assert chains[0].parent_technique_checked == ""

    def test_exact_outranks_child_across_alerts(self, mock_lc: MagicMock) -> None:
        child = {"detect_id": "a", "ts": 1711900060, "detect_mtd": {"description": "x", "tags": ["t1053.005"]}}
        exact = {"detect_id": "b", "ts": 1711900070, "detect_mtd": {"description": "y", "tags": ["t1053"]}}
        mock_lc.get_detections_by_time_range.return_value = [child, exact]
        validator = DetectionValidator(mock_lc, query_buffer=60)
        chains = validator.validate([_record("T1053")])
        assert chains[0].best_match_type == MatchType.EXACT_TECHNIQUE
        assert len(chains[0].matching_alerts) == 2
        assert chains[0].reconciliation_note == ""
