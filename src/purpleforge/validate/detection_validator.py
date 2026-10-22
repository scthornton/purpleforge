"""Detection validator: queries LimaCharlie and builds evidence chains."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from purpleforge.clients.limacharlie_client import LimaCharlieClient
from purpleforge.models.emulation import EmulationRecord, EmulationStatus
from purpleforge.models.evidence import (
    CoverageStatus,
    DetectionConfidence,
    DetectionMatch,
    EvidenceChain,
    MatchType,
)
from purpleforge.timeutil import parse_timestamp

logger = logging.getLogger(__name__)

# Higher is a stronger match. Used to pick best_match_type across several alerts.
MATCH_PRIORITY: dict[MatchType, int] = {
    MatchType.EXACT_TECHNIQUE: 4,
    MatchType.CHILD_TECHNIQUE: 3,
    MatchType.PARENT_TECHNIQUE: 2,
    MatchType.TIME_CORRELATION: 1,
    MatchType.NONE: 0,
}


class DetectionValidator:
    """Query detections and build evidence chains per emulated technique."""

    def __init__(self, client: LimaCharlieClient, query_buffer: int = 60) -> None:
        self._client = client
        self._query_buffer = query_buffer

    def validate(
        self,
        records: list[EmulationRecord],
        detection_wait: int = 120,
        technique_metadata: dict[str, dict[str, str]] | None = None,
    ) -> list[EvidenceChain]:
        """Build evidence chains for all emulated techniques.

        Args:
            records: Emulation results for all techniques.
            detection_wait: Seconds waited for detection propagation.
            technique_metadata: Optional map of technique_id to {"name": ..., "tactic": ...}
                to populate human-readable fields in evidence chains.

        Successful emulations are validated against LimaCharlie detections.
        Failed, timed-out, and error emulations get chains with MISSED status so they
        remain in the coverage denominator rather than silently disappearing.
        """
        chains: list[EvidenceChain] = []
        meta = technique_metadata or {}

        successful = [r for r in records if r.status == EmulationStatus.SUCCESS]
        failed = [r for r in records if r.status != EmulationStatus.SUCCESS]

        # Query detections only if there are successful emulations
        all_detections: list[dict[str, Any]] = []
        if successful:
            earliest_start = min(r.start_time for r in successful)
            latest_end = max(r.end_time or r.start_time for r in successful)
            window_start = earliest_start - timedelta(seconds=self._query_buffer)
            window_end = latest_end + timedelta(seconds=detection_wait + self._query_buffer)

            all_detections = self._client.get_detections_by_time_range(start=window_start, end=window_end)
            logger.info("Fetched %d detections in query window", len(all_detections))

        for record in successful:
            chain = self._build_chain(record, all_detections, detection_wait)
            self._apply_metadata(chain, meta)
            chains.append(chain)

        # Include failed, timed-out, and error emulations as MISSED so they count
        # in the coverage denominator instead of vanishing
        for record in failed:
            chain = self._build_failed_chain(record)
            self._apply_metadata(chain, meta)
            chains.append(chain)

        return chains

    @staticmethod
    def _apply_metadata(chain: EvidenceChain, meta: dict[str, dict[str, str]]) -> None:
        """Fill in technique_name and tactic from the metadata lookup."""
        info = meta.get(chain.technique_id, {})
        if info.get("name"):
            chain.technique_name = info["name"]
        if info.get("tactic"):
            chain.tactic = info["tactic"]

    def _build_chain(
        self,
        record: EmulationRecord,
        all_detections: list[dict[str, Any]],
        detection_wait: int,
    ) -> EvidenceChain:
        """Build an evidence chain for a single emulated technique."""
        tid = record.technique_id
        start = record.start_time
        end = record.end_time or record.start_time

        query_start = start - timedelta(seconds=self._query_buffer)
        query_end = end + timedelta(seconds=detection_wait + self._query_buffer)

        # Filter detections to this technique's query window
        windowed = [d for d in all_detections if self._in_window(d, query_start, query_end)]

        # Search by technique tag (exact, then child or parent)
        tag_matches = self._client.search_detections_by_technique(tid, windowed)

        # Build detection matches
        matching_alerts: list[DetectionMatch] = []
        best_match = MatchType.NONE

        for m in tag_matches:
            match_type = MatchType(m["_match_type"])
            matching_alerts.append(
                DetectionMatch(
                    alert_id=m.get("detect_id", ""),
                    alert_timestamp=self._alert_time(m, start),
                    rule_name=m.get("detect_mtd", {}).get("description", "Unknown"),
                    matched_tag=m["_matched_tag"],
                    match_type=match_type,
                    alert_description=m.get("detect_mtd", {}).get("description", ""),
                    raw_alert=m.get("detect", {}),
                )
            )
            if MATCH_PRIORITY[match_type] > MATCH_PRIORITY[best_match]:
                best_match = match_type

        # If no tag matches, check for time correlation
        if not matching_alerts and windowed:
            best_match = MatchType.TIME_CORRELATION
            for d in windowed[:3]:  # Max 3 time-correlated detections
                matching_alerts.append(
                    DetectionMatch(
                        alert_id=d.get("detect_id", ""),
                        alert_timestamp=self._alert_time(d, start),
                        rule_name=d.get("detect_mtd", {}).get("description", "Unknown"),
                        matched_tag="",
                        match_type=MatchType.TIME_CORRELATION,
                    )
                )

        # Assign confidence and status
        confidence, status = self._classify(best_match)

        # Reconciliation note
        reconciliation = ""
        parent_checked = ""
        if best_match == MatchType.PARENT_TECHNIQUE and "." in tid:
            parent_checked = tid[:5]
            reconciliation = f"Matched parent {parent_checked} for sub-technique {tid}"
        elif best_match == MatchType.CHILD_TECHNIQUE:
            child_tag = next(a.matched_tag for a in matching_alerts if a.match_type == MatchType.CHILD_TECHNIQUE)
            reconciliation = f"Matched sub-technique tag {child_tag} for parent technique {tid}"

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

    def _build_failed_chain(self, record: EmulationRecord) -> EvidenceChain:
        """Build an evidence chain for a failed, timed-out, or error emulation.

        These get MISSED status so they stay in the coverage denominator.
        """
        tid = record.technique_id
        start = record.start_time
        end = record.end_time or record.start_time

        note = f"Emulation {record.status.value}: {record.error_message or 'no details'}"

        return EvidenceChain(
            technique_id=tid,
            technique_name="",
            tactic="",
            emulation_step_id=record.execution_id,
            emulation_method=record.method.value,
            execution_timestamp=start,
            execution_end_timestamp=end,
            detection_query_window_start=start,
            detection_query_window_end=end,
            matching_alerts=[],
            best_match_type=MatchType.NONE,
            confidence=DetectionConfidence.NONE,
            status=CoverageStatus.MISSED,
            reconciliation_note=note,
        )

    def _classify(self, match_type: MatchType) -> tuple[DetectionConfidence, CoverageStatus]:
        """Assign confidence and coverage status based on match type."""
        if match_type in (MatchType.EXACT_TECHNIQUE, MatchType.CHILD_TECHNIQUE):
            return DetectionConfidence.HIGH, CoverageStatus.DETECTED
        if match_type == MatchType.PARENT_TECHNIQUE:
            return DetectionConfidence.MEDIUM, CoverageStatus.PARTIAL
        if match_type == MatchType.TIME_CORRELATION:
            return DetectionConfidence.LOW, CoverageStatus.PARTIAL
        return DetectionConfidence.NONE, CoverageStatus.MISSED

    @staticmethod
    def _alert_time(detection: dict[str, Any], fallback: datetime) -> datetime:
        """Parse the detection timestamp, falling back to the emulation start when absent or malformed."""
        ts = detection.get("ts")
        if ts is None:
            return fallback
        try:
            return parse_timestamp(ts)
        except ValueError:
            logger.warning("Detection %s has an unparseable timestamp %r", detection.get("detect_id"), ts)
            return fallback

    def _in_window(self, detection: dict[str, Any], start: datetime, end: datetime) -> bool:
        """Check if detection falls within the query window. Unparseable timestamps are excluded."""
        ts = detection.get("ts")
        if ts is None:
            return False
        try:
            det_time = parse_timestamp(ts)
        except ValueError:
            return False
        return start <= det_time <= end
