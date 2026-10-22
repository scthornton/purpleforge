"""Tests for the Atomic Red Team runner: TLS, pinned install, timeouts, cleanup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from purpleforge.clients.atomic_runner import (
    DEFAULT_INSTALLER_REF,
    AtomicInstallError,
    AtomicRunner,
    WinRMConnectionError,
)


def _response(stdout: bytes = b"", status_code: int = 0, stderr: bytes = b"") -> MagicMock:
    resp = MagicMock()
    resp.std_out = stdout
    resp.std_err = stderr
    resp.status_code = status_code
    return resp


@pytest.fixture
def session() -> MagicMock:
    return MagicMock()


def _runner(session: MagicMock, **kwargs: object) -> AtomicRunner:
    with patch("winrm.Session", return_value=session):
        return AtomicRunner(host="10.0.0.5", user="Administrator", password="pw", **kwargs)  # type: ignore[arg-type]


class TestTransport:
    def test_http_by_default(self, session: MagicMock) -> None:
        with patch("winrm.Session", return_value=session) as sess:
            AtomicRunner(host="h", user="u", password="p", port=5985)
        assert sess.call_args.args[0] == "http://h:5985/wsman"

    def test_https_on_5986(self, session: MagicMock) -> None:
        with patch("winrm.Session", return_value=session) as sess:
            AtomicRunner(host="h", user="u", password="p", port=5986)
        assert sess.call_args.args[0] == "https://h:5986/wsman"
        assert sess.call_args.kwargs["server_cert_validation"] == "validate"

    def test_https_when_requested(self, session: MagicMock) -> None:
        with patch("winrm.Session", return_value=session) as sess:
            AtomicRunner(host="h", user="u", password="p", port=5999, use_https=True)
        assert sess.call_args.args[0].startswith("https://")


class TestCheckConnection:
    def test_returns_true_on_success(self, session: MagicMock) -> None:
        session.run_ps.return_value = _response(stdout=b"7", status_code=0)
        assert _runner(session).check_connection() is True

    def test_raises_on_failure(self, session: MagicMock) -> None:
        session.run_ps.return_value = _response(status_code=1, stderr=b"denied")
        with pytest.raises(WinRMConnectionError):
            _runner(session).check_connection()

    def test_raises_on_transport_error(self, session: MagicMock) -> None:
        session.run_ps.side_effect = OSError("no route")
        with pytest.raises(WinRMConnectionError):
            _runner(session).check_connection()


class TestInstall:
    def test_pinned_ref_and_no_unrestricted(self, session: MagicMock) -> None:
        # First call: Test-Path returns False; second call: install succeeds.
        session.run_ps.side_effect = [_response(stdout=b"False"), _response(status_code=0)]
        _runner(session).ensure_atomic_installed()
        install_script = session.run_ps.call_args_list[1].args[0]
        assert DEFAULT_INSTALLER_REF in install_script
        assert "master" not in install_script
        assert "Unrestricted" not in install_script
        assert "-Scope Process" in install_script

    def test_custom_ref(self, session: MagicMock) -> None:
        session.run_ps.side_effect = [_response(stdout=b"False"), _response(status_code=0)]
        _runner(session, installer_ref="v2.2.0").ensure_atomic_installed()
        assert "v2.2.0" in session.run_ps.call_args_list[1].args[0]

    def test_skips_when_present(self, session: MagicMock) -> None:
        session.run_ps.return_value = _response(stdout=b"True")
        assert _runner(session).ensure_atomic_installed() is True
        assert session.run_ps.call_count == 1

    def test_install_failure_raises(self, session: MagicMock) -> None:
        session.run_ps.side_effect = [_response(stdout=b"False"), _response(status_code=1, stderr=b"boom")]
        with pytest.raises(AtomicInstallError):
            _runner(session).ensure_atomic_installed()


class TestRunAndCleanup:
    def test_run_passes_timeout(self, session: MagicMock) -> None:
        session.run_ps.return_value = _response(stdout=b"ok", status_code=0)
        _runner(session).run_technique("T1059.001", timeout_seconds=45)
        script = session.run_ps.call_args.args[0]
        assert "-TimeoutSeconds 45" in script
        assert "-Cleanup" not in script

    def test_run_passes_test_numbers(self, session: MagicMock) -> None:
        session.run_ps.return_value = _response(stdout=b"ok", status_code=0)
        _runner(session).run_technique("T1059.001", test_numbers=[1, 3])
        assert "-TestNumbers 1,3" in session.run_ps.call_args.args[0]

    def test_cleanup_issues_cleanup_flag(self, session: MagicMock) -> None:
        session.run_ps.return_value = _response(status_code=0)
        _runner(session).cleanup_technique("T1059.001")
        script = session.run_ps.call_args.args[0]
        assert "-Cleanup" in script
        assert "-TimeoutSeconds" not in script
