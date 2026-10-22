"""Tests for the Caldera v2 REST API client with mocked HTTP."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
import respx

from purpleforge.clients.caldera_client import (
    CalderaAPIError,
    CalderaAuthError,
    CalderaClient,
    CalderaConnectionError,
    CalderaNoAgentsError,
    decode_link_output,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
ABILITIES = json.loads((FIXTURES / "mock_caldera_abilities.json").read_text())
BASE = "http://localhost:8888"


@pytest.fixture
def caldera() -> CalderaClient:
    client = CalderaClient(base_url=BASE, api_key="TEST123")
    # Make retries instant so tests do not wait on exponential backoff.
    client._send.retry.sleep = lambda _seconds: None  # type: ignore[attr-defined]
    return client


class TestCalderaGetAbilities:
    @respx.mock
    def test_returns_abilities(self, caldera: CalderaClient) -> None:
        respx.get(f"{BASE}/api/v2/abilities").mock(return_value=httpx.Response(200, json=ABILITIES))
        result = caldera.get_abilities()
        assert len(result) == 10
        assert result[0]["ability_id"] == "abc-001"

    @respx.mock
    def test_connection_error_after_retries(self, caldera: CalderaClient) -> None:
        route = respx.get(f"{BASE}/api/v2/abilities").mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(CalderaConnectionError):
            caldera.get_abilities()
        assert route.call_count == 3


class TestCalderaRetryPolicy:
    @respx.mock
    def test_auth_error_is_not_retried(self, caldera: CalderaClient) -> None:
        route = respx.get(f"{BASE}/api/v2/abilities").mock(return_value=httpx.Response(401))
        with pytest.raises(CalderaAuthError) as exc:
            caldera.get_abilities()
        assert exc.value.status_code == 401
        assert route.call_count == 1

    @respx.mock
    def test_client_error_is_not_retried(self, caldera: CalderaClient) -> None:
        route = respx.get(f"{BASE}/api/v2/abilities").mock(return_value=httpx.Response(404, text="missing"))
        with pytest.raises(CalderaAPIError):
            caldera.get_abilities()
        assert route.call_count == 1

    @respx.mock
    def test_server_error_is_retried(self, caldera: CalderaClient) -> None:
        route = respx.get(f"{BASE}/api/v2/abilities").mock(return_value=httpx.Response(503))
        with pytest.raises(CalderaAPIError):
            caldera.get_abilities()
        assert route.call_count == 3

    @respx.mock
    def test_rate_limit_is_retried(self, caldera: CalderaClient) -> None:
        route = respx.get(f"{BASE}/api/v2/abilities").mock(return_value=httpx.Response(429))
        with pytest.raises(CalderaAPIError):
            caldera.get_abilities()
        assert route.call_count == 3

    @respx.mock
    def test_timeout_is_retried(self, caldera: CalderaClient) -> None:
        route = respx.get(f"{BASE}/api/v2/abilities").mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(CalderaConnectionError):
            caldera.get_abilities()
        assert route.call_count == 3


class TestCalderaAgents:
    @respx.mock
    def test_find_agents_returns_trusted_in_group(self, caldera: CalderaClient) -> None:
        respx.get(f"{BASE}/api/v2/agents").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"paw": "a1", "group": "red", "trusted": True, "platform": "windows"},
                    {"paw": "a2", "group": "blue", "trusted": True, "platform": "windows"},
                ],
            )
        )
        matching = caldera.find_agents("red")
        assert [a["paw"] for a in matching] == ["a1"]

    @respx.mock
    def test_find_agents_raises_when_none_match(self, caldera: CalderaClient) -> None:
        respx.get(f"{BASE}/api/v2/agents").mock(
            return_value=httpx.Response(200, json=[{"paw": "a2", "group": "blue", "trusted": True}])
        )
        with pytest.raises(CalderaNoAgentsError, match="blue"):
            caldera.find_agents("red")


class TestCalderaOperations:
    @respx.mock
    def test_create_adversary(self, caldera: CalderaClient) -> None:
        respx.post(f"{BASE}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"adversary_id": "adv-001"})
        )
        result = caldera.create_adversary("test-adv", ["abc-001"])
        assert result["adversary_id"] == "adv-001"

    @respx.mock
    def test_delete_adversary(self, caldera: CalderaClient) -> None:
        route = respx.delete(f"{BASE}/api/v2/adversaries/adv-001").mock(return_value=httpx.Response(204))
        caldera.delete_adversary("adv-001")
        assert route.called

    @respx.mock
    def test_create_operation_sends_group(self, caldera: CalderaClient) -> None:
        route = respx.post(f"{BASE}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-001", "state": "running"})
        )
        result = caldera.create_operation("test-op", "adv-001", group="red")
        assert result["id"] == "op-001"
        assert json.loads(route.calls.last.request.content)["group"] == "red"

    @respx.mock
    def test_list_operations(self, caldera: CalderaClient) -> None:
        respx.get(f"{BASE}/api/v2/operations").mock(
            return_value=httpx.Response(200, json=[{"id": "op-001", "name": "test"}])
        )
        assert len(caldera.list_operations()) == 1

    @respx.mock
    def test_wait_for_operation_already_finished(self, caldera: CalderaClient) -> None:
        respx.get(f"{BASE}/api/v2/operations/op-001").mock(
            return_value=httpx.Response(200, json={"id": "op-001", "state": "finished", "chain": []})
        )
        assert caldera.wait_for_operation("op-001", timeout=10)["state"] == "finished"


class TestCalderaLinkResult:
    @respx.mock
    def test_get_link_result_decodes_base64(self, caldera: CalderaClient) -> None:
        encoded = base64.b64encode(b"whoami\nnt authority\\system").decode()
        respx.get(f"{BASE}/api/v2/operations/op-1/links/l-1/result").mock(
            return_value=httpx.Response(200, json={"link": {}, "result": encoded})
        )
        assert "nt authority" in caldera.get_link_result("op-1", "l-1")

    @respx.mock
    def test_get_link_result_empty_when_missing(self, caldera: CalderaClient) -> None:
        respx.get(f"{BASE}/api/v2/operations/op-1/links/l-1/result").mock(return_value=httpx.Response(404))
        assert caldera.get_link_result("op-1", "l-1") == ""


class TestDecodeLinkOutput:
    def test_plain_text(self) -> None:
        assert decode_link_output(base64.b64encode(b"hello").decode()) == "hello"

    def test_json_stdout_stderr(self) -> None:
        payload = base64.b64encode(json.dumps({"stdout": "out", "stderr": "err", "exit_code": 0}).encode()).decode()
        result = decode_link_output(payload)
        assert "out" in result and "err" in result

    def test_non_base64_returned_unchanged(self) -> None:
        assert decode_link_output("not base64 !!!") == "not base64 !!!"

    def test_empty(self) -> None:
        assert decode_link_output("") == ""
