"""LimaCharlie REST API client."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

# SEC598 UpdateDetections.yml line 40 pattern
TECHNIQUE_TAG_PATTERN = re.compile(r"\bt\d{4}(\.\d{3})?\b", re.IGNORECASE)


class LimaCharlieConnectionError(Exception):
    """Raised when LimaCharlie is unreachable."""


class LimaCharlieRateLimitError(Exception):
    """Raised on rate limit (429)."""


class LimaCharlieAPIError(Exception):
    """Raised on unexpected API errors."""


class LimaCharlieClient:
    """Synchronous LimaCharlie REST API client using httpx."""

    BASE_URL = "https://api.limacharlie.io/v1"

    def __init__(self, api_key: str, org_id: str, timeout: int = 15) -> None:
        self._client = httpx.Client(
            base_url=self.BASE_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            params={"oid": org_id},
            timeout=timeout,
        )
        self._org_id = org_id

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(min=1, max=60),
        retry=retry_if_exception_type((LimaCharlieRateLimitError, httpx.HTTPStatusError)),
    )
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = self._client.request(method, path, **kwargs)
            if resp.status_code == 429:
                raise LimaCharlieRateLimitError("Rate limited by LimaCharlie API")
            resp.raise_for_status()
            return resp
        except httpx.ConnectError as e:
            raise LimaCharlieConnectionError(f"Cannot connect to LimaCharlie: {e}") from e

    def get_detections(self, limit: int = 1000) -> list[dict[str, Any]]:
        """GET /v1/detects — retrieve recent detections."""
        resp = self._request("GET", "/detects", params={"limit": limit})
        data = resp.json()
        return data.get("detects", [])  # type: ignore[no-any-return]

    def get_detections_by_time_range(
        self, start: datetime, end: datetime, limit: int = 1000
    ) -> list[dict[str, Any]]:
        """Get detections filtered to a time range."""
        all_detections = self.get_detections(limit=limit)
        return [
            d for d in all_detections
            if self._detection_in_range(d, start, end)
        ]

    def search_detections_by_technique(
        self, technique_id: str, detections: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Filter detections matching a technique ID by tag.

        Uses regex pattern from SEC598 UpdateDetections.yml for tag extraction.
        Matches are case-insensitive.
        """
        technique_lower = technique_id.lower()
        parent_lower = technique_lower[:5]  # T1059 for T1059.001
        matches = []

        for detection in detections:
            tags = [t.lower() for t in detection.get("detect_mtd", {}).get("tags", [])]

            # Check exact match first (higher priority)
            if technique_lower in tags:
                matched_tag = next(t for t in detection["detect_mtd"]["tags"] if t.lower() == technique_lower)
                matches.append({**detection, "_match_type": "exact_technique", "_matched_tag": matched_tag})
            elif "." in technique_id and parent_lower in tags:
                matched_tag = next(t for t in detection["detect_mtd"]["tags"] if t.lower() == parent_lower)
                matches.append({**detection, "_match_type": "parent_technique", "_matched_tag": matched_tag})

        return matches

    def get_detection_rules(self) -> dict[str, Any]:
        """GET /v1/rules/d — retrieve D&R rules."""
        resp = self._request("GET", "/rules/d")
        return resp.json()  # type: ignore[no-any-return]

    def _detection_in_range(self, detection: dict[str, Any], start: datetime, end: datetime) -> bool:
        """Check if a detection timestamp falls within [start, end]."""
        ts = detection.get("ts")
        if ts is None:
            return False
        # LC timestamps can be epoch seconds or ISO strings
        if isinstance(ts, int | float):
            det_time = datetime.fromtimestamp(ts, tz=start.tzinfo)
        else:
            det_time = datetime.fromisoformat(str(ts))
        return start <= det_time <= end

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
