"""Configuration via Pydantic Settings. Single source of truth for all env vars."""

from __future__ import annotations

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class PurpleForgeSettings(BaseSettings):
    """All PurpleForge configuration loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # LLM
    openai_api_key: SecretStr
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str | None = None

    # Caldera
    caldera_url: str = "http://localhost:8888"
    caldera_api_key: SecretStr
    caldera_group: str = "red"

    # LimaCharlie
    lc_api_key: SecretStr
    lc_org_id: str

    # WinRM (Atomic Red Team target)
    winrm_host: str
    winrm_user: str = "Administrator"
    winrm_password: SecretStr
    winrm_transport: str = "ntlm"
    winrm_port: int = 5985
    winrm_use_https: bool = False
    winrm_cert_validation: str = "validate"
    winrm_ca_trust_path: str | None = None
    atomic_installer_ref: str = "v2.3.0"
    atomic_test_timeout: int = 120

    # GitHub (optional, only needed for deploy-draft --target github)
    github_token: SecretStr | None = None
    detection_repo: str | None = None
    github_base_url: str | None = None

    # Pipeline
    detection_wait_seconds: int = 120
    caldera_operation_timeout: int = 300
    caldera_poll_interval: int = 5
    detection_query_buffer: int = 60
    run_base_dir: str = "./data/runs"
