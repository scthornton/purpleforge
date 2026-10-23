"""Configuration via Pydantic Settings. Single source of truth for all env vars.

Credentials are optional at load time so the settings object always constructs.
A step validates only the integrations it needs by calling the matching
``require_*`` method, which raises ``ConfigError`` naming the missing variables.
"""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(Exception):
    """Raised when a step runs without the configuration it needs."""


class PurpleForgeSettings(BaseSettings):
    """All PurpleForge configuration loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # LLM. OPENAI_API_KEY and OPENAI_BASE_URL keep their standard names on purpose:
    # they are the variables the OpenAI SDK itself reads, so a PURPLEFORGE_ prefix
    # would surprise operators and break gateway setups.
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str | None = None

    # Caldera
    caldera_url: str = "http://localhost:8888"
    caldera_api_key: SecretStr | None = None
    caldera_group: str = "red"

    # LimaCharlie
    lc_api_key: SecretStr | None = None
    lc_org_id: str | None = None

    # WinRM (Atomic Red Team target)
    winrm_host: str | None = None
    winrm_user: str = "Administrator"
    winrm_password: SecretStr | None = None
    winrm_transport: str = "ntlm"
    winrm_port: int = 5985
    winrm_use_https: bool = False
    winrm_cert_validation: str = "validate"
    winrm_ca_trust_path: str | None = None
    atomic_installer_ref: str = "v2.3.0"
    atomic_test_timeout: int = 120
    # When a Caldera ability runs but fails (a broken stock ability on a healthy
    # host), retry the same technique via Atomic Red Team and keep whichever
    # result actually executed. Requires WinRM to be configured; otherwise the
    # Caldera failures are left untouched.
    atomic_fallback: bool = True

    # GitHub (optional, only needed for deploy-draft --target github)
    github_token: SecretStr | None = None
    detection_repo: str | None = None
    github_base_url: str | None = None

    # Pipeline
    detection_wait_seconds: int = 120
    caldera_operation_timeout: int = 300
    # Ceiling for the beacon-aware auto-raise of the Caldera operation timeout.
    # The executor raises the timeout to fit the plan when a slow agent beacon
    # would otherwise time the operation out, but never above this bound.
    caldera_max_operation_timeout: int = 1800
    caldera_poll_interval: int = 5
    detection_query_buffer: int = 60
    run_base_dir: str = "./data/runs"

    @staticmethod
    def _missing(**named: object) -> list[str]:
        """Return the names of the arguments whose value is falsy."""
        return [name for name, value in named.items() if not value]

    def require_openai(self) -> None:
        """Ensure the OpenAI credentials needed for extraction and advisories are set."""
        missing = self._missing(OPENAI_API_KEY=self.openai_api_key)
        if missing:
            raise ConfigError(f"{', '.join(missing)} is not set (needed for TTP extraction and advisories)")

    def require_caldera(self) -> None:
        """Ensure the Caldera credentials needed for emulation are set."""
        missing = self._missing(CALDERA_API_KEY=self.caldera_api_key)
        if missing:
            raise ConfigError(f"{', '.join(missing)} is not set (needed for Caldera emulation)")

    def require_limacharlie(self) -> None:
        """Ensure the LimaCharlie credentials needed for detection validation are set."""
        missing = self._missing(LC_API_KEY=self.lc_api_key, LC_ORG_ID=self.lc_org_id)
        if missing:
            raise ConfigError(f"{', '.join(missing)} is not set (needed for LimaCharlie validation)")

    def require_winrm(self) -> None:
        """Ensure the WinRM credentials needed for Atomic tests are set."""
        missing = self._missing(WINRM_HOST=self.winrm_host, WINRM_PASSWORD=self.winrm_password)
        if missing:
            raise ConfigError(f"{', '.join(missing)} is not set (needed for Atomic Red Team over WinRM)")

    def require_github(self) -> None:
        """Ensure the GitHub credentials needed to open advisory PRs are set."""
        missing = self._missing(GITHUB_TOKEN=self.github_token, DETECTION_REPO=self.detection_repo)
        if missing:
            raise ConfigError(f"{', '.join(missing)} is not set (needed for deploy-draft --target github)")

    # Resolved accessors. Each validates then returns the concrete value, so callers
    # get a non-optional type and a clear error instead of an AttributeError on None.

    def openai_key(self) -> str:
        """Return the OpenAI API key, validating it is set."""
        self.require_openai()
        assert self.openai_api_key is not None
        return self.openai_api_key.get_secret_value()

    def caldera_key(self) -> str:
        """Return the Caldera API key, validating it is set."""
        self.require_caldera()
        assert self.caldera_api_key is not None
        return self.caldera_api_key.get_secret_value()

    def lc_key(self) -> str:
        """Return the LimaCharlie API key, validating it is set."""
        self.require_limacharlie()
        assert self.lc_api_key is not None
        return self.lc_api_key.get_secret_value()

    def lc_org(self) -> str:
        """Return the LimaCharlie organization ID, validating it is set."""
        self.require_limacharlie()
        assert self.lc_org_id is not None
        return self.lc_org_id

    def winrm_host_value(self) -> str:
        """Return the WinRM host, validating it is set."""
        self.require_winrm()
        assert self.winrm_host is not None
        return self.winrm_host

    def winrm_pass(self) -> str:
        """Return the WinRM password, validating it is set."""
        self.require_winrm()
        assert self.winrm_password is not None
        return self.winrm_password.get_secret_value()

    def github_token_value(self) -> str:
        """Return the GitHub token, validating it is set."""
        self.require_github()
        assert self.github_token is not None
        return self.github_token.get_secret_value()

    def detection_repo_value(self) -> str:
        """Return the detection repository, validating it is set."""
        self.require_github()
        assert self.detection_repo is not None
        return self.detection_repo
