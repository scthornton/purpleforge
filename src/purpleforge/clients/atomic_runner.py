"""WinRM-based Atomic Red Team runner."""

from __future__ import annotations

import logging
from typing import Any

import winrm

logger = logging.getLogger(__name__)


class WinRMConnectionError(Exception):
    """Raised when WinRM connection fails."""


class AtomicInstallError(Exception):
    """Raised when Atomic Red Team installation fails."""


class AtomicExecutionError(Exception):
    """Raised when an Atomic test execution fails."""


class AtomicRunner:
    """Execute Atomic Red Team tests on a Windows host via WinRM."""

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 5985,
        transport: str = "ntlm",
    ) -> None:
        self._url = f"http://{host}:{port}/wsman"
        self._session = winrm.Session(
            self._url,
            auth=(user, password),
            transport=transport,
        )

    def _run_ps(self, script: str) -> winrm.Response:
        """Run a PowerShell script via WinRM."""
        try:
            return self._session.run_ps(script)
        except Exception as e:
            raise WinRMConnectionError(f"WinRM connection failed: {e}") from e

    def ensure_atomic_installed(self) -> bool:
        """Check if Atomic Red Team is installed, install if not.

        Mirrors SEC598_AdversaryEmulation.yml install pattern.
        """
        result = self._run_ps("Test-Path C:/AtomicRedTeam")
        if "True" in result.std_out.decode():
            logger.info("Atomic Red Team already installed")
            return True

        logger.info("Installing Atomic Red Team...")
        install_script = (
            "Set-ExecutionPolicy Unrestricted -Force; "
            "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force; "
            "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/"
            "master/install-atomicredteam.ps1' -UseBasicParsing); "
            "Install-AtomicRedTeam -getAtomics -Force"
        )
        result = self._run_ps(install_script)
        if result.status_code != 0:
            error = result.std_err.decode()
            raise AtomicInstallError(f"Atomic install failed: {error}")

        return True

    def run_technique(self, technique_id: str) -> dict[str, Any]:
        """Execute an Atomic test for a specific technique.

        Returns dict with output, status_code, and error.
        """
        script = (
            "Import-Module C:/AtomicRedTeam/invoke-atomicredteam/"
            "Invoke-AtomicRedTeam.psm1; "
            f"Invoke-AtomicTest -AtomicTechnique {technique_id} -Confirm:$false"
        )
        result = self._run_ps(script)
        return {
            "output": result.std_out.decode(),
            "status_code": result.status_code,
            "error": result.std_err.decode() if result.status_code != 0 else None,
        }

    def check_technique_available(self, technique_id: str) -> bool:
        """Check if the technique's atomic directory exists."""
        result = self._run_ps(f"Test-Path C:/AtomicRedTeam/atomics/{technique_id}")
        return "True" in result.std_out.decode()
