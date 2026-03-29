"""Detection validator — queries LimaCharlie and builds evidence chains."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from purpleforge.clients.limacharlie_client import LimaCharlieClient
from purpleforge.models.emulation import EmulationRecord, EmulationStatus
from purpleforge.models.evidence import (
    CoverageStatus,
    DetectionConfidence,
    DetectionMatch,
    EvidenceChain,
    MatchType,
)

logger = logging.getLogger(__name__)


class DetectionValidator:
    """Query detections and build evidence chains per emulated technique."""

    def __init__(self, client: LimaCharlieClient, query_buffer: int = 60) -> None:
        self._client = client
        self._query_buffer = query_buffer

    def validate(
        self, records: list[EmulationRecord], detection_wait: int = 120
    ) -> list[EvidenceChain]:
        """Build evidence chains for all successfully emulated techniques."""
        chains: list[EvidenceChain] = []

        # Only validate successful emulations
        successful = [r for r in records if r.status == EmulationStatus.SUCCESS]
        if not successful:
            return chains

        # Determine the overall query window
        earliest_start = min(r.start_time for r in successful)
        latest_end = max(r.end_time or r.start_time for r in successful)
        window_start = earliest_start - timedelta(seconds=self._query_buffer)
        window_end = latest_end + timedelta(seconds=detection_wait + self._query_buffer)

        # Fetch all detections in the window
        all_detections = self._client.get_detections_by_time_range(
            start=window_start, end=window_end
        )
        logger.info("Fetched %d detections in query window", len(all_detections))

        for record in successful:
            chain = self._build_chain(record, all_detections, detection_wait)
            chains.append(chain)

        return chains

    def _build_chain(
        self,
        record: EmulationRecord,
        all_detections: list[dict],
        detection_wait: int,
    ) -> EvidenceChain:
        """Build an evidence chain for a single emulated technique."""
        tid = record.technique_id
        start = record.start_time
        end = record.end_time or record.start_time

        query_start = start - timedelta(seconds=self._query_buffer)
        query_end = end + timedelta(seconds=detection_wait + self._query_buffer)

        # Filter detections to this technique's query window
        windowed = [
            d for d in all_detections
            if self._in_window(d, query_start, query_end)
        ]

        # Search by technique tag (exact, then parent)
        tag_matches = self._client.search_detections_by_technique(tid, windowed)

        # Build detection matches
        matching_alerts: list[DetectionMatch] = []
        best_match = MatchType.NONE

        for m in tag_matches:
            match_type = MatchType(m["_match_type"])
            ts = m.get("ts", 0)
            alert_time = (
                datetime.fromtimestamp(ts, tz=UTC)
                if isinstance(ts, int | float)
                else datetime.fromisoformat(str(ts))
            )
            matching_alerts.append(DetectionMatch(
                alert_id=m.get("detect_id", ""),
                alert_timestamp=alert_time,
                rule_name=m.get("detect_mtd", {}).get("description", "Unknown"),
                matched_tag=m["_matched_tag"],
                match_type=match_type,
                alert_description=m.get("detect_mtd", {}).get("description", ""),
                raw_alert=m.get("detect", {}),
            ))
            if match_type == MatchType.EXACT_TECHNIQUE:
                best_match = MatchType.EXACT_TECHNIQUE
            elif match_type == MatchType.PARENT_TECHNIQUE and best_match != MatchType.EXACT_TECHNIQUE:
                best_match = MatchType.PARENT_TECHNIQUE

        # If no tag matches, check for time correlation
        if not matching_alerts and windowed:
            best_match = MatchType.TIME_CORRELATION
            for d in windowed[:3]:  # Max 3 time-correlated detections
                ts = d.get("ts", 0)
                alert_time = (
                    datetime.fromtimestamp(ts, tz=UTC)
                    if isinstance(ts, int | float)
                    else datetime.fromisoformat(str(ts))
                )
                matching_alerts.append(DetectionMatch(
                    alert_id=d.get("detect_id", ""),
                    alert_timestamp=alert_time,
                    rule_name=d.get("detect_mtd", {}).get("description", "Unknown"),
                    matched_tag="",
                    match_type=MatchType.TIME_CORRELATION,
                ))

        # Assign confidence and status
        confidence, status = self._classify(best_match)

        # Reconciliation note
        reconciliation = ""
        parent_checked = ""
        if best_match == MatchType.PARENT_TECHNIQUE and "." in tid:
            parent_checked = tid[:5]
            reconciliation = f"Matched parent {parent_checked} for sub-technique {tid}"

        return EvidenceChain(
            technique_id=tid,
            technique_name="",  # Will be populated by coverage analyzer
            tactic="",
            emulation_step_id=record.execution_id,
            emulation_method=record.method.value,
            execution_timestamp=start,
            execution_end_timestamp=end,
            detection_query_window_start=query_start,
            detection_query_window_end=query_end,
            matching_alerts=matching_alerts,
            best_match_type=best_match,
            confidence=confidence,
            status=status,
            reconciliation_note=reconciliation,
            parent_technique_checked=parent_checked,
        )

    def _classify(
        self, match_type: MatchType
    ) -> tuple[DetectionConfidence, CoverageStatus]:
        """Assign confidence and coverage status based on match type."""
        if match_type == MatchType.EXACT_TECHNIQUE:
            return DetectionConfidence.HIGH, CoverageStatus.DETECTED
        if match_type == MatchType.PARENT_TECHNIQUE:
            return DetectionConfidence.MEDIUM, CoverageStatus.PARTIAL
        if match_type == MatchType.TIME_CORRELATION:
            return DetectionConfidence.LOW, CoverageStatus.PARTIAL
        return DetectionConfidence.NONE, CoverageStatus.MISSED

    def _in_window(self, detection: dict, start: datetime, end: datetime) -> bool:
        """Check if detection falls within the query window."""
        ts = detection.get("ts")
        if ts is None:
            return False
        if isinstance(ts, int | float):
            det_time = datetime.fromtimestamp(ts, tz=UTC)
        else:
            det_time = datetime.fromisoformat(str(ts))
        return start <= det_time <= end
