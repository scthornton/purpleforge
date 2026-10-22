"""WinRM-based Atomic Red Team runner for authorized lab purple-team exercises."""

from __future__ import annotations

import logging
from typing import Any

import winrm

logger = logging.getLogger(__name__)

# Pinned release of the Atomic Red Team installer. Pinning avoids running
# whatever currently sits on the upstream default branch. Override through
# settings when a different vetted release is required.
DEFAULT_INSTALLER_REF = "v2.3.0"

ATOMIC_ROOT = "C:/AtomicRedTeam"


class WinRMConnectionError(Exception):
    """Raised when the WinRM connection fails."""


class AtomicInstallError(Exception):
    """Raised when Atomic Red Team installation fails."""


class AtomicExecutionError(Exception):
    """Raised when an Atomic test execution fails."""


class AtomicRunner:
    """Execute Atomic Red Team tests on a Windows host via WinRM.

    Planning (reachability checks) is read-only. Installing the framework is an
    explicit operator action, never a side effect of resolution.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 5985,
        transport: str = "ntlm",
        use_https: bool = False,
        server_cert_validation: str = "validate",
        ca_trust_path: str | None = None,
        installer_ref: str = DEFAULT_INSTALLER_REF,
    ) -> None:
        # Use TLS when asked, or when the standard WinRM HTTPS port is set.
        scheme = "https" if (use_https or port == 5986) else "http"
        self._url = f"{scheme}://{host}:{port}/wsman"
        self._installer_ref = installer_ref
        session_kwargs: dict[str, Any] = {
            "auth": (user, password),
            "transport": transport,
        }
        if scheme == "https":
            session_kwargs["server_cert_validation"] = server_cert_validation
            if ca_trust_path:
                session_kwargs["ca_trust_path"] = ca_trust_path
        self._session = winrm.Session(self._url, **session_kwargs)

    def _run_ps(self, script: str) -> winrm.Response:
        """Run a PowerShell script via WinRM."""
        try:
            return self._session.run_ps(script)
        except Exception as e:
            raise WinRMConnectionError(f"WinRM connection failed: {e}") from e

    def check_connection(self) -> bool:
        """Confirm the host is reachable over WinRM. Read-only, installs nothing.

        Raises:
            WinRMConnectionError: If the host cannot be reached or the command fails.
        """
        result = self._run_ps("$PSVersionTable.PSVersion.Major")
        if result.status_code != 0:
            raise WinRMConnectionError(f"WinRM probe failed: {result.std_err.decode(errors='replace')}")
        return True

    def ensure_atomic_installed(self) -> bool:
        """Install Atomic Red Team from the pinned installer release, if absent.

        This reaches out to the pinned upstream installer at the configured
        release ref and runs it on the target. Run it only against a host you
        own or are authorized to test, as an explicit operator action, never as
        part of planning. The execution policy change is scoped to the current
        process only.
        """
        result = self._run_ps(f"Test-Path {ATOMIC_ROOT}")
        if "True" in result.std_out.decode():
            logger.info("Atomic Red Team already installed")
            return True

        logger.info("Installing Atomic Red Team from %s", self._installer_ref)
        installer_url = (
            "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/"
            f"{self._installer_ref}/install-atomicredteam.ps1"
        )
        install_script = (
            "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; "
            "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force; "
            f"IEX (IWR '{installer_url}' -UseBasicParsing); "
            "Install-AtomicRedTeam -getAtomics -Force"
        )
        result = self._run_ps(install_script)
        if result.status_code != 0:
            error = result.std_err.decode(errors="replace")
            raise AtomicInstallError(f"Atomic install failed: {error}")

        return True

    def run_technique(
        self,
        technique_id: str,
        test_numbers: list[int] | None = None,
        timeout_seconds: int = 120,
    ) -> dict[str, Any]:
        """Execute Atomic tests for a technique, bounded by a timeout.

        Args:
            technique_id: The ATT&CK technique to run.
            test_numbers: Specific test numbers to run; all tests when None.
            timeout_seconds: Per-test timeout passed to Invoke-AtomicTest.

        Returns a dict with output, status_code, and error.
        """
        script = self._invoke_command(technique_id, test_numbers, timeout_seconds=timeout_seconds)
        result = self._run_ps(script)
        return {
            "output": result.std_out.decode(errors="replace"),
            "status_code": result.status_code,
            "error": result.std_err.decode(errors="replace") if result.status_code != 0 else None,
        }

    def cleanup_technique(
        self,
        technique_id: str,
        test_numbers: list[int] | None = None,
    ) -> dict[str, Any]:
        """Run the cleanup commands for a technique's Atomic tests.

        Removes persistence artifacts (run keys, scheduled tasks, dropped files)
        left by run_technique. Returns a dict with output, status_code, and error.
        """
        script = self._invoke_command(technique_id, test_numbers, cleanup=True)
        result = self._run_ps(script)
        return {
            "output": result.std_out.decode(errors="replace"),
            "status_code": result.status_code,
            "error": result.std_err.decode(errors="replace") if result.status_code != 0 else None,
        }

    def check_technique_available(self, technique_id: str) -> bool:
        """Check whether the technique's atomic directory exists. Read-only."""
        result = self._run_ps(f"Test-Path {ATOMIC_ROOT}/atomics/{technique_id}")
        return "True" in result.std_out.decode()

    def _invoke_command(
        self,
        technique_id: str,
        test_numbers: list[int] | None,
        cleanup: bool = False,
        timeout_seconds: int | None = None,
    ) -> str:
        """Build an Invoke-AtomicTest command string."""
        parts = [
            f"Import-Module {ATOMIC_ROOT}/invoke-atomicredteam/Invoke-AtomicRedTeam.psm1; ",
            f"Invoke-AtomicTest {technique_id} -Confirm:$false",
        ]
        if test_numbers:
            parts.append(" -TestNumbers " + ",".join(str(n) for n in test_numbers))
        if cleanup:
            parts.append(" -Cleanup")
        elif timeout_seconds is not None:
            parts.append(f" -TimeoutSeconds {timeout_seconds}")
        return "".join(parts)
