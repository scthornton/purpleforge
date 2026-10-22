"""End-to-end test of confirm_run with every external client mocked.

Exercises the real orchestrator, run store, resolver, executors, validator,
coverage analyzer, renderers, and the YAML/JSON artifacts between steps.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import yaml

from purpleforge.clients.limacharlie_client import LimaCharlieClient
from purpleforge.models.pipeline import RunStatus, StepStatus
from purpleforge.pipeline.orchestrator import PipelineOrchestrator

FIXTURES = Path(__file__).parent.parent / "fixtures"
ABILITIES = json.loads((FIXTURES / "mock_caldera_abilities.json").read_text())

TTPS = {
    "techniques": [
        {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": "Execution",
            "description": "d",
            "operator_notes": "",
        },
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task",
            "tactic": "Persistence",
            "description": "d",
            "operator_notes": "",
        },
        {
            "technique_id": "T1003.001",
            "technique_name": "LSASS Memory",
            "tactic": "Credential Access",
            "description": "d",
            "operator_notes": "",
        },
        {"technique_id": "T9999", "technique_name": "Nope", "tactic": "X", "description": "d", "operator_notes": ""},
    ]
}

EXPECTED_ARTIFACTS = [
    "execution_plan.yaml",
    "emulation_results.yaml",
    "evidence_chains.json",
    "coverage_report.json",
    "coverage_report.html",
    "navigator_layer.json",
]


def _settings(tmp_path: Path) -> MagicMock:
    settings = MagicMock()
    settings.run_base_dir = str(tmp_path / "runs")
    settings.chroma_persist_dir = str(tmp_path / "chroma")
    settings.openai_api_key.get_secret_value.return_value = "sk-test"
    settings.openai_model = "gpt-4o-mini"
    settings.detection_wait_seconds = 120
    settings.caldera_operation_timeout = 300
    settings.caldera_poll_interval = 1
    settings.detection_query_buffer = 60
    settings.caldera_url = "http://caldera:8888"
    settings.caldera_api_key.get_secret_value.return_value = "KEY"
    settings.lc_api_key.get_secret_value.return_value = "lc"
    settings.lc_org_id = "oid"
    settings.winrm_host = "h"
    settings.winrm_user = "u"
    settings.winrm_password.get_secret_value.return_value = "p"
    settings.winrm_port = 5985
    settings.winrm_transport = "ntlm"
    return settings


def _caldera() -> MagicMock:
    caldera = MagicMock()
    caldera.get_abilities.return_value = ABILITIES
    caldera.list_operations.return_value = []
    caldera.create_adversary.return_value = {"adversary_id": "adv-1"}
    caldera.create_operation.return_value = {"id": "op-1", "state": "running"}
    caldera.wait_for_operation.return_value = {
        "id": "op-1",
        "state": "finished",
        "chain": [
            {"id": "link-1", "ability": {"technique_id": "T1059.001"}, "status": 0, "output": "True"},
            {"id": "link-2", "ability": {"technique_id": "T1053.005"}, "status": 0, "output": "True"},
        ],
    }
    return caldera


def _atomic() -> MagicMock:
    atomic = MagicMock()
    atomic.ensure_atomic_installed.return_value = True
    atomic.check_technique_available.side_effect = lambda tid: tid == "T1003.001"
    atomic.run_technique.return_value = {"output": "ok", "status_code": 0, "error": None}
    return atomic


def _limacharlie() -> MagicMock:
    lc = MagicMock(spec=LimaCharlieClient)
    # Use the real tag matcher so the evidence chain is built the way production builds it
    real = LimaCharlieClient.__new__(LimaCharlieClient)
    lc.search_detections_by_technique.side_effect = real.search_detections_by_technique

    def detections(start: datetime, end: datetime, **_: Any) -> list[dict[str, Any]]:
        # One detection, tagged only for T1059.001, inside the query window
        return [
            {
                "detect_id": "lc-1",
                "ts": int(start.timestamp()) + 70,
                "detect_mtd": {"description": "PowerShell exec", "tags": ["t1059.001"]},
                "detect": {},
            }
        ]

    lc.get_detections_by_time_range.side_effect = detections
    return lc


@pytest.fixture
def completed_run(tmp_path: Path) -> tuple[PipelineOrchestrator, str]:
    settings = _settings(tmp_path)
    orch = PipelineOrchestrator(settings, skip_advise=True)
    run = orch.store.create_run("/tmp/report.pdf", config_snapshot={"skip_advise": True})
    orch.store.update_status(run.run_id, RunStatus.AWAITING_REVIEW)
    (Path(settings.run_base_dir) / run.run_id / "extracted_ttps.yaml").write_text(yaml.safe_dump(TTPS))

    with (
        patch("purpleforge.pipeline.orchestrator.CalderaClient", return_value=_caldera()),
        patch("purpleforge.pipeline.orchestrator.AtomicRunner", return_value=_atomic()),
        patch("purpleforge.pipeline.orchestrator.LimaCharlieClient", return_value=_limacharlie()),
        patch("purpleforge.pipeline.orchestrator.time.sleep"),
    ):
        orch.confirm_run(run.run_id)

    return orch, run.run_id


class TestConfirmPipeline:
    def test_run_completes(self, completed_run: tuple[PipelineOrchestrator, str]) -> None:
        orch, run_id = completed_run
        state = orch.store.load_run(run_id)
        assert state.status == RunStatus.COMPLETE
        done = {s.step_name: s.status for s in state.steps}
        for step in ("RESOLVE", "EXECUTE", "WAIT", "VALIDATE", "REPORT"):
            assert done[step] == StepStatus.COMPLETE, step

    def test_artifacts_exist(self, completed_run: tuple[PipelineOrchestrator, str]) -> None:
        orch, run_id = completed_run
        run_dir = Path(orch.store.base_dir) / run_id
        for name in EXPECTED_ARTIFACTS:
            assert (run_dir / name).exists(), name

    def test_yaml_artifacts_are_plain(self, completed_run: tuple[PipelineOrchestrator, str]) -> None:
        orch, run_id = completed_run
        run_dir = Path(orch.store.base_dir) / run_id
        plan = yaml.safe_load((run_dir / "execution_plan.yaml").read_text())
        assert {t["method"] for t in plan["techniques"]} == {"caldera", "atomic", "skip"}
        results = yaml.safe_load((run_dir / "emulation_results.yaml").read_text())
        assert all(isinstance(r["status"], str) and isinstance(r["method"], str) for r in results["records"])
        assert "!!python" not in (run_dir / "execution_plan.yaml").read_text()

    def test_evidence_links_alert_to_technique(self, completed_run: tuple[PipelineOrchestrator, str]) -> None:
        orch, run_id = completed_run
        report = json.loads((Path(orch.store.base_dir) / run_id / "coverage_report.json").read_text())
        chains = {c["technique_id"]: c for c in report["evidence_chains"]}
        ps = chains["T1059.001"]
        assert ps["status"] == "detected"
        assert ps["best_match_type"] == "exact_technique"
        assert [a["alert_id"] for a in ps["matching_alerts"]] == ["lc-1"]
        assert report["skipped_techniques"] == ["T9999"]
        assert report["total_techniques"] == 4

    def test_report_can_be_regenerated(self, completed_run: tuple[PipelineOrchestrator, str]) -> None:
        orch, run_id = completed_run
        run_dir = Path(orch.store.base_dir) / run_id
        before = json.loads((run_dir / "coverage_report.json").read_text())
        orch._step_report(run_id)
        after = json.loads((run_dir / "coverage_report.json").read_text())
        assert after["evidence_chains"] == before["evidence_chains"]
        assert after["coverage_pct"] == before["coverage_pct"]
        steps = [s for s in orch.store.load_run(run_id).steps if s.step_name == "REPORT"]
        assert len(steps) == 2 and all(s.status == StepStatus.COMPLETE for s in steps)
