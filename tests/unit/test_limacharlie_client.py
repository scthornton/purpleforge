"""Tests for LimaCharlie REST API client with mocked HTTP."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from purpleforge.clients.limacharlie_client import LimaCharlieClient

FIXTURES = Path(__file__).parent.parent / "fixtures"
DETECTIONS = json.loads((FIXTURES / "mock_limacharlie_detections.json").read_text())


@pytest.fixture
def lc() -> LimaCharlieClient:
    return LimaCharlieClient(api_key="lc-test", org_id="test-org")


class TestLimaCharlieGetDetections:
    @respx.mock
    def test_returns_detections(self, lc: LimaCharlieClient) -> None:
        respx.get(url__regex=r"https://api\.limacharlie\.io/v1/detects.*").mock(
            return_value=httpx.Response(200, json={"detects": DETECTIONS})
        )
        result = lc.get_detections()
        assert len(result) == 5


class TestLimaCharlieSearchByTechnique:
    def test_exact_match(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T1059.001", DETECTIONS)
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "exact_technique"
        assert matches[0]["detect_id"] == "lc-detect-001"

    def test_parent_match(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T1003.001", DETECTIONS)
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "parent_technique"
        assert matches[0]["detect_id"] == "lc-detect-003"

    def test_no_match(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T9999", DETECTIONS)
        assert len(matches) == 0

    def test_case_insensitive(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("t1083", DETECTIONS)
        assert len(matches) == 1

    def test_tagless_detection_not_matched(self, lc: LimaCharlieClient) -> None:
        """Detection with empty tags should not match any technique."""
        matches = lc.search_detections_by_technique("T1071", DETECTIONS)
        # lc-detect-005 has empty tags — should not match
        assert len(matches) == 0


class TestLimaCharlieTimeRange:
    @respx.mock
    def test_filters_by_time(self, lc: LimaCharlieClient) -> None:
        respx.get(url__regex=r"https://api\.limacharlie\.io/v1/detects.*").mock(
            return_value=httpx.Response(200, json={"detects": DETECTIONS})
        )
        # Timestamps in fixture: 1711900000, 1711900100, 1711900200, 1711900300, 1711900400
        start = datetime.fromtimestamp(1711900050, tz=UTC)
        end = datetime.fromtimestamp(1711900250, tz=UTC)
        result = lc.get_detections_by_time_range(start, end)
        # Should include ts=1711900100 and ts=1711900200 (2 detections)
        assert len(result) == 2
