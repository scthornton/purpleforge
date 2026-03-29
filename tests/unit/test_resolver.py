"""Tests for technique resolver."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from purpleforge.models.emulation import EmulationMethod
from purpleforge.models.extraction import NormalizedTechnique
from purpleforge.resolve.resolver import Resolver

FIXTURES = Path(__file__).parent.parent / "fixtures"
ABILITIES = json.loads((FIXTURES / "mock_caldera_abilities.json").read_text())


@pytest.fixture
def mock_caldera() -> MagicMock:
    client = MagicMock()
    client.get_abilities.return_value = ABILITIES
    return client


@pytest.fixture
def mock_atomic() -> MagicMock:
    runner = MagicMock()
    runner.ensure_atomic_installed.return_value = True
    return runner


def _technique(tid: str, name: str) -> NormalizedTechnique:
    return NormalizedTechnique(
        technique_id=tid,
        technique_name=name,
        tactic="test",
        description="test",
    )


class TestResolver:
    def test_exact_caldera_match(self, mock_caldera: MagicMock, mock_atomic: MagicMock) -> None:
        resolver = Resolver(mock_caldera, mock_atomic)
        plan = resolver.resolve([_technique("T1059.001", "PowerShell")], "test-run")

        assert len(plan.techniques) == 1
        assert plan.techniques[0].method == EmulationMethod.CALDERA
        assert plan.techniques[0].ability_id == "abc-002"
        assert plan.techniques[0].parent_match is False
        assert plan.caldera_count == 1

    def test_parent_caldera_match(self, mock_caldera: MagicMock, mock_atomic: MagicMock) -> None:
        """T1059.003 doesn't exist but T1059 does — parent match."""
        resolver = Resolver(mock_caldera, mock_atomic)
        plan = resolver.resolve([_technique("T1059.003", "Windows Command Shell")], "test-run")

        assert plan.techniques[0].method == EmulationMethod.CALDERA
        assert plan.techniques[0].parent_match is True
        assert plan.techniques[0].ability_id == "abc-001"

    def test_atomic_fallback(self, mock_caldera: MagicMock, mock_atomic: MagicMock) -> None:
        """No Caldera match, but Atomic test exists."""
        mock_atomic.check_technique_available.return_value = True
        resolver = Resolver(mock_caldera, mock_atomic)
        plan = resolver.resolve([_technique("T1003.001", "LSASS Memory")], "test-run")

        assert plan.techniques[0].method == EmulationMethod.ATOMIC
        assert plan.atomic_count == 1

    def test_skip_when_nothing_available(self, mock_caldera: MagicMock, mock_atomic: MagicMock) -> None:
        """No Caldera or Atomic match — skip."""
        mock_atomic.check_technique_available.return_value = False
        resolver = Resolver(mock_caldera, mock_atomic)
        plan = resolver.resolve([_technique("T9999", "Unknown")], "test-run")

        assert plan.techniques[0].method == EmulationMethod.SKIP
        assert plan.techniques[0].skip_reason is not None
        assert plan.skip_count == 1

    def test_mixed_resolution(self, mock_caldera: MagicMock, mock_atomic: MagicMock) -> None:
        """Multiple techniques with mixed resolution results."""
        mock_atomic.check_technique_available.side_effect = lambda tid: tid == "T1003.001"

        techniques = [
            _technique("T1059.001", "PowerShell"),      # Exact Caldera match
            _technique("T1003.001", "LSASS Memory"),     # Atomic fallback
            _technique("T9999", "Unknown"),               # Skip
        ]
        resolver = Resolver(mock_caldera, mock_atomic)
        plan = resolver.resolve(techniques, "test-run")

        assert plan.caldera_count == 1
        assert plan.atomic_count == 1
        assert plan.skip_count == 1
        assert len(plan.techniques) == 3

    def test_winrm_unreachable_skips_atomic(self, mock_caldera: MagicMock, mock_atomic: MagicMock) -> None:
        """If WinRM is unreachable, all Atomic candidates become skips."""
        from purpleforge.clients.atomic_runner import WinRMConnectionError

        mock_atomic.ensure_atomic_installed.side_effect = WinRMConnectionError("unreachable")

        resolver = Resolver(mock_caldera, mock_atomic)
        plan = resolver.resolve([_technique("T1003.001", "LSASS Memory")], "test-run")

        assert plan.techniques[0].method == EmulationMethod.SKIP
