"""Tests for Caldera REST API client with mocked HTTP."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from purpleforge.clients.caldera_client import CalderaClient, CalderaConnectionError

FIXTURES = Path(__file__).parent.parent / "fixtures"
ABILITIES = json.loads((FIXTURES / "mock_caldera_abilities.json").read_text())


@pytest.fixture
def caldera() -> CalderaClient:
    return CalderaClient(base_url="http://localhost:8888", api_key="TEST123")


class TestCalderaGetAbilities:
    @respx.mock
    def test_returns_abilities(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/abilities").mock(
            return_value=httpx.Response(200, json=ABILITIES)
        )
        result = caldera.get_abilities()
        assert len(result) == 10
        assert result[0]["ability_id"] == "abc-001"

    @respx.mock
    def test_connection_error(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/abilities").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        with pytest.raises(CalderaConnectionError):
            caldera.get_abilities()


class TestCalderaFindAbilities:
    @respx.mock
    def test_exact_match(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/abilities").mock(
            return_value=httpx.Response(200, json=ABILITIES)
        )
        result = caldera.find_abilities_by_technique("T1059.001")
        assert len(result) == 1
        assert result[0]["ability_id"] == "abc-002"

    @respx.mock
    def test_parent_fallback(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/abilities").mock(
            return_value=httpx.Response(200, json=ABILITIES)
        )
        # T1003.001 doesn't exist, but T1003 doesn't either in our fixture
        # T1059.003 doesn't exist, but T1059 does
        result = caldera.find_abilities_by_technique("T1059.003")
        assert len(result) == 1
        assert result[0]["technique_id"] == "T1059"

    @respx.mock
    def test_no_match(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/abilities").mock(
            return_value=httpx.Response(200, json=ABILITIES)
        )
        result = caldera.find_abilities_by_technique("T9999")
        assert len(result) == 0


class TestCalderaOperations:
    @respx.mock
    def test_create_adversary(self, caldera: CalderaClient) -> None:
        respx.post("http://localhost:8888/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-001"})
        )
        result = caldera.create_adversary("test-adv", ["abc-001"])
        assert result["adversary_id"] == "adv-001"

    @respx.mock
    def test_create_operation(self, caldera: CalderaClient) -> None:
        respx.post("http://localhost:8888/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-001", "state": "running"})
        )
        result = caldera.create_operation("test-op", "adv-001")
        assert result["id"] == "op-001"

    @respx.mock
    def test_list_operations(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/operations").mock(
            return_value=httpx.Response(200, json=[{"id": "op-001", "name": "test"}])
        )
        result = caldera.list_operations()
        assert len(result) == 1

    @respx.mock
    def test_wait_for_operation_already_finished(self, caldera: CalderaClient) -> None:
        respx.get("http://localhost:8888/api/v2/operations/op-001").mock(
            return_value=httpx.Response(200, json={"id": "op-001", "state": "finished", "chain": []})
        )
        result = caldera.wait_for_operation("op-001", timeout=10)
        assert result["state"] == "finished"
