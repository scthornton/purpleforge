"""Tests for the `purpleforge doctor` command."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from purpleforge.cli import cli
from purpleforge.config import PurpleForgeSettings

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
]


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _settings(**overrides: object) -> PurpleForgeSettings:
    return PurpleForgeSettings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _all_configured() -> PurpleForgeSettings:
    return _settings(
        openai_api_key="sk",
        caldera_api_key="ck",
        lc_api_key="lk",
        lc_org_id="oid",
        winrm_host="h",
        winrm_password="pw",
    )


class TestDoctor:
    def test_all_not_configured_exits_zero(self) -> None:
        with patch("purpleforge.cli._load_settings", return_value=_settings()):
            result = CliRunner().invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "not configured" in result.output
        assert "OpenAI" in result.output and "WinRM" in result.output

    def test_all_passing_exits_zero(self) -> None:
        openai_mod = MagicMock()
        openai_mod.OpenAI.return_value.models.list.return_value = []
        caldera = MagicMock()
        caldera.get_agents.return_value = [{"paw": "a1"}]
        lc = MagicMock()
        runner = MagicMock()
        with (
            patch("purpleforge.cli._load_settings", return_value=_all_configured()),
            patch.dict("sys.modules", {"openai": openai_mod}),
            patch("purpleforge.clients.caldera_client.CalderaClient", return_value=caldera),
            patch("purpleforge.clients.limacharlie_client.LimaCharlieClient", return_value=lc),
            patch("purpleforge.clients.atomic_runner.AtomicRunner", return_value=runner),
        ):
            result = CliRunner().invoke(cli, ["doctor"])
        assert result.exit_code == 0
        assert "ok" in result.output
        runner.check_connection.assert_called_once()
        lc._token.assert_called_once()

    def test_configured_but_failing_exits_nonzero(self) -> None:
        openai_mod = MagicMock()
        openai_mod.OpenAI.return_value.models.list.side_effect = RuntimeError("bad key")
        caldera = MagicMock()
        caldera.get_agents.side_effect = RuntimeError("unreachable")
        lc = MagicMock()
        lc._token.side_effect = RuntimeError("auth failed")
        runner = MagicMock()
        runner.check_connection.side_effect = RuntimeError("winrm down")
        with (
            patch("purpleforge.cli._load_settings", return_value=_all_configured()),
            patch.dict("sys.modules", {"openai": openai_mod}),
            patch("purpleforge.clients.caldera_client.CalderaClient", return_value=caldera),
            patch("purpleforge.clients.limacharlie_client.LimaCharlieClient", return_value=lc),
            patch("purpleforge.clients.atomic_runner.AtomicRunner", return_value=runner),
        ):
            result = CliRunner().invoke(cli, ["doctor"])
        assert result.exit_code == 1
        assert "failed" in result.output

    def test_mixed_one_failure_exits_nonzero(self) -> None:
        # Only Caldera configured, and it fails.
        openai_mod = MagicMock()
        caldera = MagicMock()
        caldera.get_agents.side_effect = RuntimeError("unreachable")
        with (
            patch("purpleforge.cli._load_settings", return_value=_settings(caldera_api_key="ck")),
            patch.dict("sys.modules", {"openai": openai_mod}),
            patch("purpleforge.clients.caldera_client.CalderaClient", return_value=caldera),
        ):
            result = CliRunner().invoke(cli, ["doctor"])
        assert result.exit_code == 1
        assert "failed" in result.output
        assert "not configured" in result.output
