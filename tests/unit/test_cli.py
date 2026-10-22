"""CLI tests for run --ttps, JSON output, the coverage gate, id checks, and demo removal."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from click.testing import CliRunner

from purpleforge.cli import cli

_ENV_VARS = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "CALDERA_API_KEY",
    "CALDERA_URL",
    "LC_API_KEY",
    "LC_ORG_ID",
    "WINRM_HOST",
    "WINRM_PASSWORD",
    "GITHUB_TOKEN",
    "DETECTION_REPO",
    "RUN_BASE_DIR",
]


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_demo_command_removed(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["demo"])
    assert result.exit_code != 0
    assert "No such command" in result.output


class TestRunFromTtps:
    def test_ttps_path_skips_llm(self, runner: CliRunner, tmp_path: Path) -> None:
        ttps = tmp_path / "ttps.yaml"
        ttps.write_text(
            yaml.dump(
                {
                    "techniques": [
                        {
                            "technique_id": "T1059.001",
                            "technique_name": "PowerShell",
                            "tactic": "Execution",
                            "description": "d",
                        }
                    ]
                }
            )
        )
        fake = MagicMock()
        fake.start_run_from_ttps.return_value = "0123abcd4567"
        fake.store.read_artifact.return_value = {"techniques": []}
        settings = MagicMock()
        settings.run_base_dir = str(tmp_path / "runs")
        with (
            patch("purpleforge.cli._load_settings", return_value=settings),
            patch("purpleforge.pipeline.orchestrator.PipelineOrchestrator", return_value=fake),
        ):
            result = runner.invoke(cli, ["run", "--ttps", str(ttps)])
        assert result.exit_code == 0, result.output
        fake.start_run_from_ttps.assert_called_once_with(str(ttps))
        fake.start_run.assert_not_called()
        settings.require_openai.assert_not_called()

    def test_source_and_ttps_mutually_exclusive(self, runner: CliRunner, tmp_path: Path) -> None:
        pdf = tmp_path / "r.pdf"
        pdf.write_text("x")
        ttps = tmp_path / "t.yaml"
        ttps.write_text("techniques: []")
        result = runner.invoke(cli, ["run", "--source", str(pdf), "--ttps", str(ttps)])
        assert result.exit_code != 0
        assert "exactly one" in result.output

    def test_neither_source_nor_ttps(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["run"])
        assert result.exit_code != 0
        assert "exactly one" in result.output


class TestMinCoverageGate:
    def _patched(self, tmp_path: Path, pct: float) -> tuple[MagicMock, MagicMock]:
        fake = MagicMock()
        fake.confirm_run.return_value = None
        fake.store.read_artifact.return_value = {
            "coverage_pct": pct,
            "detected_count": 1,
            "partial_count": 0,
            "missed_count": 0,
            "skipped_count": 0,
        }
        settings = MagicMock()
        settings.run_base_dir = str(tmp_path / "runs")
        return fake, settings

    def test_below_threshold_exits_3(self, runner: CliRunner, tmp_path: Path) -> None:
        fake, settings = self._patched(tmp_path, 40.0)
        with (
            patch("purpleforge.cli._load_settings", return_value=settings),
            patch("purpleforge.pipeline.orchestrator.PipelineOrchestrator", return_value=fake),
        ):
            result = runner.invoke(cli, ["confirm", "--run-id", "0123abcd4567", "--min-coverage", "80"])
        assert result.exit_code == 3, result.output
        assert "below" in result.output

    def test_at_or_above_threshold_exits_0(self, runner: CliRunner, tmp_path: Path) -> None:
        fake, settings = self._patched(tmp_path, 90.0)
        with (
            patch("purpleforge.cli._load_settings", return_value=settings),
            patch("purpleforge.pipeline.orchestrator.PipelineOrchestrator", return_value=fake),
        ):
            result = runner.invoke(cli, ["confirm", "--run-id", "0123abcd4567", "--min-coverage", "80"])
        assert result.exit_code == 0, result.output


class TestIdValidation:
    def test_traversal_run_id_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["status", "--run-id", "../../../../etc"])
        assert result.exit_code != 0
        assert "Invalid run id" in result.output

    def test_bad_technique_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["deploy-draft", "--run-id", "0123abcd4567", "--technique", "passwd"])
        assert result.exit_code != 0
        assert "Invalid technique id" in result.output


class TestJsonOutput:
    def test_list_json(self, runner: CliRunner) -> None:
        store = MagicMock()
        run = MagicMock()
        run.run_id = "0123abcd4567"
        run.source_path = "/tmp/x.pdf"
        run.status.value = "complete"
        run.created_at.isoformat.return_value = "2026-10-22T00:00:00+00:00"
        store.list_runs.return_value = [run]
        with patch("purpleforge.cli._load_store", return_value=store):
            result = runner.invoke(cli, ["list", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data[0]["run_id"] == "0123abcd4567"
        assert data[0]["status"] == "complete"

    def test_status_json(self, runner: CliRunner) -> None:
        store = MagicMock()
        run = MagicMock()
        run.model_dump.return_value = {"run_id": "0123abcd4567", "status": "complete", "steps": []}
        store.load_run.return_value = run
        with patch("purpleforge.cli._load_store", return_value=store):
            result = runner.invoke(cli, ["status", "--run-id", "0123abcd4567", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["run_id"] == "0123abcd4567"
