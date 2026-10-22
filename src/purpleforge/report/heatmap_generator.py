"""ATT&CK Navigator heatmap layer generator."""

from __future__ import annotations

import json
from typing import Any

from purpleforge.models.evidence import CoverageResult, CoverageStatus

# ATT&CK Navigator color scheme
COLORS = {
    CoverageStatus.DETECTED: "#a1d99b",  # green
    CoverageStatus.PARTIAL: "#fee08b",  # yellow
    CoverageStatus.MISSED: "#fc8d59",  # red
    CoverageStatus.INCONCLUSIVE: "#cccccc",  # gray, emulation did not run cleanly
}
SKIPPED_COLOR = "#ffffff"  # white, not tested


class HeatmapGenerator:
    """Generate ATT&CK Navigator layer JSON from coverage results."""

    def generate(self, result: CoverageResult) -> dict[str, Any]:
        """Build a Navigator v4.5 layer JSON object."""
        techniques = []

        for chain in result.evidence_chains:
            color = COLORS.get(chain.status, SKIPPED_COLOR)
            score = {CoverageStatus.DETECTED: 3, CoverageStatus.PARTIAL: 2, CoverageStatus.MISSED: 1}.get(
                chain.status, 0
            )
            techniques.append(
                {
                    "techniqueID": chain.technique_id,
                    "color": color,
                    "score": score,
                    "comment": chain.reconciliation_note or f"{chain.status.value} ({chain.confidence.value})",
                    "enabled": True,
                    "showSubtechniques": True,
                }
            )

        # Skipped techniques shown as white
        for tid in result.skipped_techniques:
            techniques.append(
                {
                    "techniqueID": tid,
                    "color": SKIPPED_COLOR,
                    "score": 0,
                    "comment": "Not emulated",
                    "enabled": True,
                    "showSubtechniques": False,
                }
            )

        return {
            "name": f"PurpleForge Coverage, Run {result.run_id}",
            "versions": {"attack": "16", "navigator": "4.5", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": (
                f"Coverage: {result.coverage_pct}% "
                f"(D:{result.detected_count} P:{result.partial_count} "
                f"M:{result.missed_count} I:{result.inconclusive_count} S:{result.skipped_count})"
            ),
            "filters": {"platforms": ["Windows"]},
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#fc8d59", "#fee08b", "#a1d99b"],
                "minValue": 1,
                "maxValue": 3,
            },
            "legendItems": [
                {"label": "Detected (high confidence)", "color": "#a1d99b"},
                {"label": "Partial (parent-technique match)", "color": "#fee08b"},
                {"label": "Missed (no detection)", "color": "#fc8d59"},
                {"label": "Inconclusive (emulation failed)", "color": "#cccccc"},
                {"label": "Not tested", "color": "#ffffff"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
        }

    def to_json(self, result: CoverageResult) -> str:
        """Generate Navigator layer as a JSON string."""
        return json.dumps(self.generate(result), indent=2)
