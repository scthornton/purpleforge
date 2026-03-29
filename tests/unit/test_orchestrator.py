"""Tests for pipeline orchestrator INGEST step."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from purpleforge.models.extraction import Confidence, ExtractedTTP
from purpleforge.models.pipeline import RunStatus
from purpleforge.pipeline.orchestrator import PipelineError, PipelineOrchestrator


@pytest.fixture
def mock_settings(tmp_path: Path) -> MagicMock:
    """Create mock settings with real temp directories."""
    settings = MagicMock()
    settings.run_base_dir = str(tmp_path / "runs")
    settings.chroma_persist_dir = str(tmp_path / "chroma")
    settings.openai_api_key.get_secret_value.return_value = "sk-test"
    settings.openai_model = "gpt-4o-mini"
    settings.detection_wait_seconds = 120
    settings.caldera_operation_timeout = 300
    return settings


@pytest.fixture
def sample_ttps() -> list[ExtractedTTP]:
    return [
        ExtractedTTP(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Uses PowerShell",
            confidence=Confidence.HIGH,
        ),
        ExtractedTTP(
            technique_id="T1053.005",
            technique_name="Scheduled Task",
            tactic="Persistence",
            description="Creates tasks",
            confidence=Confidence.MEDIUM,
        ),
    ]


class TestOrchestratorIngest:
    @patch("purpleforge.pipeline.orchestrator.TTPExtractor")
    @patch("purpleforge.pipeline.orchestrator.VectorStore")
    @patch("purpleforge.pipeline.orchestrator.load_pdf")
    @patch("purpleforge.pipeline.orchestrator.chunk_documents")
    def test_start_run_creates_run_and_extracts(
        self,
        mock_chunk: MagicMock,
        mock_load: MagicMock,
        mock_vs_cls: MagicMock,
        mock_ext_cls: MagicMock,
        mock_settings: MagicMock,
        sample_ttps: list[ExtractedTTP],
        tmp_path: Path,
    ) -> None:
        # Setup mocks
        mock_load.return_value = [MagicMock(page_content="page 1")]
        mock_chunk.return_value = [MagicMock(page_content="chunk 1")]
        mock_vs = MagicMock()
        mock_vs.similarity_search.return_value = [MagicMock(page_content="relevant")]
        mock_vs_cls.return_value = mock_vs
        mock_ext = MagicMock()
        mock_ext.extract.return_value = sample_ttps
        mock_ext_cls.return_value = mock_ext

        orchestrator = PipelineOrchestrator(mock_settings)
        run_id = orchestrator.start_run("/tmp/test.pdf")

        # Verify run was created
        run = orchestrator.store.load_run(run_id)
        assert run.status == RunStatus.AWAITING_REVIEW

        # Verify extracted TTPs were written
        ttps_path = Path(mock_settings.run_base_dir) / run_id / "extracted_ttps.yaml"
        assert ttps_path.exists()
        data = yaml.safe_load(ttps_path.read_text())
        assert len(data["techniques"]) == 2
        assert data["techniques"][0]["technique_id"] == "T1059.001"

    @patch("purpleforge.pipeline.orchestrator.TTPExtractor")
    @patch("purpleforge.pipeline.orchestrator.VectorStore")
    @patch("purpleforge.pipeline.orchestrator.load_pdf")
    @patch("purpleforge.pipeline.orchestrator.chunk_documents")
    def test_start_run_pdf_failure_marks_failed(
        self,
        mock_chunk: MagicMock,
        mock_load: MagicMock,
        mock_vs_cls: MagicMock,
        mock_ext_cls: MagicMock,
        mock_settings: MagicMock,
    ) -> None:
        mock_load.side_effect = FileNotFoundError("PDF not found: /bad/path.pdf")

        orchestrator = PipelineOrchestrator(mock_settings)
        with pytest.raises(FileNotFoundError):
            orchestrator.start_run("/bad/path.pdf")


class TestOrchestratorConfirm:
    def test_confirm_wrong_state_raises(self, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        # Run is in CREATED state, not AWAITING_REVIEW
        with pytest.raises(PipelineError, match="awaiting_review"):
            orchestrator.confirm_run(run.run_id)

    def test_confirm_complete_run_raises(self, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        orchestrator.store.update_status(run.run_id, RunStatus.COMPLETE)
        with pytest.raises(PipelineError, match="expected 'awaiting_review'"):
            orchestrator.confirm_run(run.run_id)

    @patch.object(PipelineOrchestrator, "_step_report")
    @patch.object(PipelineOrchestrator, "_step_validate")
    @patch.object(PipelineOrchestrator, "_step_wait")
    @patch.object(PipelineOrchestrator, "_step_execute")
    @patch.object(PipelineOrchestrator, "_step_resolve")
    def test_confirm_with_valid_ttps(
        self,
        mock_resolve: MagicMock,
        mock_execute: MagicMock,
        mock_wait: MagicMock,
        mock_validate: MagicMock,
        mock_report: MagicMock,
        mock_settings: MagicMock,
        tmp_path: Path,
    ) -> None:
        mock_resolve.return_value = []
        mock_execute.return_value = []

        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        orchestrator.store.update_status(run.run_id, RunStatus.AWAITING_REVIEW)

        # Write TTPs file
        ttps_data = {
            "techniques": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "tactic": "Execution",
                    "description": "test",
                    "operator_notes": "",
                }
            ]
        }
        ttps_path = Path(mock_settings.run_base_dir) / run.run_id / "extracted_ttps.yaml"
        ttps_path.write_text(yaml.dump(ttps_data))

        orchestrator.confirm_run(run.run_id)

        updated = orchestrator.store.load_run(run.run_id)
        assert updated.status == RunStatus.COMPLETE
        mock_resolve.assert_called_once()
        mock_execute.assert_called_once()

    def test_confirm_empty_ttps_raises(self, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        orchestrator.store.update_status(run.run_id, RunStatus.AWAITING_REVIEW)

        ttps_path = Path(mock_settings.run_base_dir) / run.run_id / "extracted_ttps.yaml"
        ttps_path.write_text(yaml.dump({"techniques": []}))

        with pytest.raises(PipelineError, match="No techniques"):
            orchestrator.confirm_run(run.run_id)

    def test_confirm_missing_ttps_file_raises(self, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        orchestrator.store.update_status(run.run_id, RunStatus.AWAITING_REVIEW)

        with pytest.raises(PipelineError, match="not found"):
            orchestrator.confirm_run(run.run_id)
