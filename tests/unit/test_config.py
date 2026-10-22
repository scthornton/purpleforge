"""Tests for settings: optional load, per-integration validation, and accessors."""

from __future__ import annotations

import pytest

from purpleforge.config import ConfigError, PurpleForgeSettings

_ENV_VARS = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "CALDERA_API_KEY",
    "CALDERA_URL",
    "CALDERA_GROUP",
    "LC_API_KEY",
    "LC_ORG_ID",
    "WINRM_HOST",
    "WINRM_PASSWORD",
    "GITHUB_TOKEN",
    "DETECTION_REPO",
    "GITHUB_BASE_URL",
    "RUN_BASE_DIR",
]


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the real shell environment from leaking credentials into these tests."""
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _settings(**overrides: object) -> PurpleForgeSettings:
    """Build validated settings with no .env influence and explicit overrides."""
    return PurpleForgeSettings(_env_file=None, **overrides)  # type: ignore[call-arg]


class TestConstructsWithoutCredentials:
    def test_no_env_constructs(self) -> None:
        s = _settings()
        assert s.openai_api_key is None
        assert s.caldera_api_key is None
        assert s.run_base_dir == "./data/runs"


class TestRequireOpenAI:
    def test_raises_when_missing(self) -> None:
        with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
            _settings().require_openai()

    def test_passes_when_set(self) -> None:
        _settings(openai_api_key="sk-test").require_openai()


class TestRequireCaldera:
    def test_raises_when_missing(self) -> None:
        with pytest.raises(ConfigError, match="CALDERA_API_KEY"):
            _settings().require_caldera()

    def test_passes_when_set(self) -> None:
        _settings(caldera_api_key="ck").require_caldera()


class TestRequireLimaCharlie:
    def test_raises_naming_both_when_missing(self) -> None:
        with pytest.raises(ConfigError, match="LC_API_KEY, LC_ORG_ID"):
            _settings().require_limacharlie()

    def test_raises_naming_org_only(self) -> None:
        with pytest.raises(ConfigError, match="LC_ORG_ID"):
            _settings(lc_api_key="lk").require_limacharlie()

    def test_passes_when_both_set(self) -> None:
        _settings(lc_api_key="lk", lc_org_id="oid").require_limacharlie()


class TestRequireWinRM:
    def test_raises_when_missing(self) -> None:
        with pytest.raises(ConfigError, match="WINRM_HOST"):
            _settings().require_winrm()

    def test_passes_when_set(self) -> None:
        _settings(winrm_host="h", winrm_password="pw").require_winrm()


class TestRequireGitHub:
    def test_raises_when_missing(self) -> None:
        with pytest.raises(ConfigError, match="GITHUB_TOKEN, DETECTION_REPO"):
            _settings().require_github()

    def test_passes_when_set(self) -> None:
        _settings(github_token="t", detection_repo="o/r").require_github()


class TestAccessors:
    def test_resolved_values(self) -> None:
        s = _settings(
            openai_api_key="sk",
            caldera_api_key="ck",
            lc_api_key="lk",
            lc_org_id="oid",
            winrm_host="h",
            winrm_password="pw",
            github_token="t",
            detection_repo="o/r",
        )
        assert s.openai_key() == "sk"
        assert s.caldera_key() == "ck"
        assert s.lc_key() == "lk"
        assert s.lc_org() == "oid"
        assert s.winrm_host_value() == "h"
        assert s.winrm_pass() == "pw"
        assert s.github_token_value() == "t"
        assert s.detection_repo_value() == "o/r"

    def test_accessor_raises_when_unset(self) -> None:
        with pytest.raises(ConfigError):
            _settings().openai_key()
