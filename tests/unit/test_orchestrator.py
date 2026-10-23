"""Tests for pipeline orchestrator INGEST step."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from purpleforge.models.emulation import EmulationMethod, EmulationRecord, EmulationStatus, ResolvedTechnique
from purpleforge.models.extraction import Confidence, ExtractedTTP
from purpleforge.models.pipeline import RunStatus
from purpleforge.pipeline.orchestrator import PipelineError, PipelineOrchestrator


@pytest.fixture
def mock_settings(tmp_path: Path) -> MagicMock:
    """Create mock settings with real temp directories."""
    settings = MagicMock()
    settings.run_base_dir = str(tmp_path / "runs")
    settings.openai_api_key.get_secret_value.return_value = "sk-test"
    settings.openai_model = "gpt-4o-mini"
    settings.openai_base_url = None
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


class TestStartRunFromTtps:
    def test_creates_run_without_llm(self, mock_settings: MagicMock, tmp_path: Path) -> None:
        ttps_file = tmp_path / "ttps.yaml"
        ttps_file.write_text(
            yaml.dump(
                {
                    "techniques": [
                        {
                            "technique_id": "T1059.001",
                            "technique_name": "PowerShell",
                            "tactic": "Execution",
                            "description": "Uses PowerShell",
                            "confidence": "high",
                        }
                    ]
                }
            )
        )
        with patch("purpleforge.pipeline.orchestrator.TTPExtractor") as extractor:
            orch = PipelineOrchestrator(mock_settings)
            run_id = orch.start_run_from_ttps(str(ttps_file))
            extractor.assert_not_called()

        mock_settings.require_openai.assert_not_called()
        run = orch.store.load_run(run_id)
        assert run.status == RunStatus.AWAITING_REVIEW
        written = orch.store.read_artifact(run_id, "extracted_ttps.yaml")
        assert written["techniques"][0]["technique_id"] == "T1059.001"
        assert written["techniques"][0]["confidence"] == "high"
        assert run.config_snapshot.get("source") == "provided_ttps"

    def test_rejects_file_without_techniques(self, mock_settings: MagicMock, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(yaml.dump({"not_techniques": []}))
        orch = PipelineOrchestrator(mock_settings)
        with pytest.raises(PipelineError, match="techniques"):
            orch.start_run_from_ttps(str(bad))

    def test_rejects_invalid_technique_id(self, mock_settings: MagicMock, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        entry = {"technique_id": "nope", "technique_name": "x", "tactic": "y", "description": "z"}
        bad.write_text(yaml.dump({"techniques": [entry]}))
        orch = PipelineOrchestrator(mock_settings)
        with pytest.raises(ValueError):
            orch.start_run_from_ttps(str(bad))


class TestOrchestratorIngest:
    @patch("purpleforge.pipeline.orchestrator.TTPExtractor")
    @patch("purpleforge.pipeline.orchestrator.load_pdf")
    @patch("purpleforge.pipeline.orchestrator.chunk_documents")
    def test_start_run_creates_run_and_extracts(
        self,
        mock_chunk: MagicMock,
        mock_load: MagicMock,
        mock_ext_cls: MagicMock,
        mock_settings: MagicMock,
        sample_ttps: list[ExtractedTTP],
        tmp_path: Path,
    ) -> None:
        # Setup mocks
        mock_load.return_value = [MagicMock(text="page 1")]
        mock_chunk.return_value = [MagicMock(text="chunk 1")]
        mock_ext = MagicMock()
        mock_ext.extract.return_value = sample_ttps
        mock_ext_cls.return_value = mock_ext

        orchestrator = PipelineOrchestrator(mock_settings)
        run_id = orchestrator.start_run("/tmp/test.pdf")

        # Verify run was created
        run = orchestrator.store.load_run(run_id)
        assert run.status == RunStatus.AWAITING_REVIEW

        # Verify extracted TTPs were written with the review signals
        ttps_path = Path(mock_settings.run_base_dir) / run_id / "extracted_ttps.yaml"
        assert ttps_path.exists()
        data = yaml.safe_load(ttps_path.read_text())
        assert len(data["techniques"]) == 2
        assert data["techniques"][0]["technique_id"] == "T1059.001"
        assert data["techniques"][0]["confidence"] in {"high", "medium", "low"}
        assert "source_chunk" in data["techniques"][0]

    @patch("purpleforge.pipeline.orchestrator.TTPExtractor")
    @patch("purpleforge.pipeline.orchestrator.load_pdf")
    @patch("purpleforge.pipeline.orchestrator.chunk_documents")
    def test_start_run_pdf_failure_marks_failed(
        self,
        mock_chunk: MagicMock,
        mock_load: MagicMock,
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


class TestAtomicFallback:
    """Execution-time Atomic fallback for failed Caldera techniques."""

    @staticmethod
    def _configure_winrm(settings: MagicMock, *, enabled: bool = True, host: str | None = "10.0.0.3") -> None:
        settings.atomic_fallback = enabled
        settings.winrm_host = host
        settings.winrm_password = "pw" if host else None
        settings.winrm_host_value.return_value = host
        settings.winrm_user = "pfadmin"
        settings.winrm_pass.return_value = "pw"
        settings.winrm_port = 5986
        settings.winrm_transport = "basic"
        settings.winrm_use_https = True
        settings.winrm_cert_validation = "ignore"
        settings.winrm_ca_trust_path = None
        settings.atomic_installer_ref = "v2.3.0"
        settings.atomic_test_timeout = 120

    @staticmethod
    def _failed_caldera() -> tuple[list[ResolvedTechnique], list[EmulationRecord]]:
        techs = [
            ResolvedTechnique(
                technique_id="T1016", technique_name="Net Config", method=EmulationMethod.CALDERA, ability_id="a1"
            )
        ]
        records = [
            EmulationRecord(
                technique_id="T1016",
                method=EmulationMethod.CALDERA,
                status=EmulationStatus.FAILED,
                error_message="status 1",
            )
        ]
        return techs, records

    def test_disabled_setting_skips_fallback(self, mock_settings: MagicMock) -> None:
        self._configure_winrm(mock_settings, enabled=False)
        techs, records = self._failed_caldera()
        orch = PipelineOrchestrator(mock_settings)

        with patch("purpleforge.pipeline.orchestrator.AtomicExecutor") as ax:
            out = orch._apply_atomic_fallback(techs, records)

        ax.assert_not_called()
        assert out == records

    def test_no_failures_skips_fallback(self, mock_settings: MagicMock) -> None:
        self._configure_winrm(mock_settings)
        techs = [
            ResolvedTechnique(
                technique_id="T1016", technique_name="Net Config", method=EmulationMethod.CALDERA, ability_id="a1"
            )
        ]
        records = [
            EmulationRecord(technique_id="T1016", method=EmulationMethod.CALDERA, status=EmulationStatus.SUCCESS)
        ]
        orch = PipelineOrchestrator(mock_settings)

        with patch("purpleforge.pipeline.orchestrator.AtomicExecutor") as ax:
            out = orch._apply_atomic_fallback(techs, records)

        ax.assert_not_called()
        assert out == records

    def test_winrm_unconfigured_skips_fallback(self, mock_settings: MagicMock) -> None:
        self._configure_winrm(mock_settings, host=None)
        techs, records = self._failed_caldera()
        orch = PipelineOrchestrator(mock_settings)

        with patch("purpleforge.pipeline.orchestrator.AtomicExecutor") as ax:
            out = orch._apply_atomic_fallback(techs, records)

        ax.assert_not_called()
        assert out == records

    def test_atomic_success_replaces_failure(self, mock_settings: MagicMock) -> None:
        self._configure_winrm(mock_settings)
        techs, records = self._failed_caldera()
        atomic_rec = EmulationRecord(
            technique_id="T1016", method=EmulationMethod.ATOMIC, status=EmulationStatus.SUCCESS
        )
        orch = PipelineOrchestrator(mock_settings)

        with (
            patch("purpleforge.pipeline.orchestrator.AtomicRunner"),
            patch("purpleforge.pipeline.orchestrator.AtomicExecutor") as ax,
        ):
            ax.return_value.execute.return_value = [atomic_rec]
            out = orch._apply_atomic_fallback(techs, records)

        # The retried technique was passed to the executor, and its success replaced the failure.
        targets = ax.return_value.execute.call_args.args[0]
        assert [t.technique_id for t in targets] == ["T1016"]
        assert all(t.method == EmulationMethod.ATOMIC for t in targets)
        assert len(out) == 1
        assert out[0].method == EmulationMethod.ATOMIC and out[0].status == EmulationStatus.SUCCESS

    def test_executor_error_is_best_effort(self, mock_settings: MagicMock) -> None:
        self._configure_winrm(mock_settings)
        techs, records = self._failed_caldera()
        orch = PipelineOrchestrator(mock_settings)

        with (
            patch("purpleforge.pipeline.orchestrator.AtomicRunner"),
            patch("purpleforge.pipeline.orchestrator.AtomicExecutor") as ax,
        ):
            ax.return_value.execute.side_effect = RuntimeError("winrm blew up")
            out = orch._apply_atomic_fallback(techs, records)

        # A fallback failure never aborts the run; the original Caldera records are kept.
        assert out == records


class TestResume:
    """Resume a failed or interrupted run from its first incomplete step."""

    def _failed_at_validate(self, orchestrator: PipelineOrchestrator) -> str:
        """Create a run with RESOLVE, EXECUTE, WAIT complete and VALIDATE failed."""
        run = orchestrator.store.create_run("/tmp/test.pdf")
        for step in ("RESOLVE", "EXECUTE", "WAIT"):
            orchestrator.store.start_step(run.run_id, step)
            orchestrator.store.complete_step(run.run_id, step)
        orchestrator.store.start_step(run.run_id, "VALIDATE")
        orchestrator.store.fail_step(run.run_id, "VALIDATE", "boom")
        return run.run_id

    @patch.object(PipelineOrchestrator, "_step_advise")
    @patch.object(PipelineOrchestrator, "_step_report")
    @patch.object(PipelineOrchestrator, "_step_validate")
    @patch.object(PipelineOrchestrator, "_step_execute")
    @patch.object(PipelineOrchestrator, "_step_resolve")
    def test_resume_runs_only_remaining_steps(
        self,
        mock_resolve: MagicMock,
        mock_execute: MagicMock,
        mock_validate: MagicMock,
        mock_report: MagicMock,
        mock_advise: MagicMock,
        mock_settings: MagicMock,
    ) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run_id = self._failed_at_validate(orchestrator)

        orchestrator.resume_run(run_id)

        mock_resolve.assert_not_called()
        mock_execute.assert_not_called()
        mock_validate.assert_called_once()
        mock_report.assert_called_once()
        mock_advise.assert_called_once()
        assert orchestrator.store.load_run(run_id).status == RunStatus.COMPLETE

    def test_resume_awaiting_review_raises(self, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        orchestrator.store.update_status(run.run_id, RunStatus.AWAITING_REVIEW)
        with pytest.raises(PipelineError, match="confirm"):
            orchestrator.resume_run(run.run_id)

    def test_resume_complete_raises(self, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run = orchestrator.store.create_run("/tmp/test.pdf")
        orchestrator.store.update_status(run.run_id, RunStatus.COMPLETE)
        with pytest.raises(PipelineError, match="already complete"):
            orchestrator.resume_run(run.run_id)

    @patch.object(PipelineOrchestrator, "_step_validate", side_effect=RuntimeError("fail"))
    def test_resume_releases_lock_on_failure(self, _mock_validate: MagicMock, mock_settings: MagicMock) -> None:
        orchestrator = PipelineOrchestrator(mock_settings)
        run_id = self._failed_at_validate(orchestrator)
        with pytest.raises(RuntimeError):
            orchestrator.resume_run(run_id)
        lock = Path(orchestrator.store.base_dir) / run_id / ".lock"
        assert not lock.exists()
