"""Tests for the LimaCharlie REST API client with mocked HTTP."""

from __future__ import annotations

import base64
import gzip
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from purpleforge.clients.limacharlie_client import (
    LimaCharlieAPIError,
    LimaCharlieAuthError,
    LimaCharlieClient,
    LimaCharlieConnectionError,
    technique_ids_in,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"
DETECTIONS = json.loads((FIXTURES / "mock_limacharlie_detections.json").read_text())

JWT_URL = "https://jwt.limacharlie.io"
DETECTIONS_URL = "https://api.limacharlie.io/v1/insight/test-org/detections"
# Fixture timestamps: 1711900000, 1711900100, 1711900200, 1711900300, 1711900400
WINDOW_START = datetime.fromtimestamp(1711899000, tz=UTC)
WINDOW_END = datetime.fromtimestamp(1711901000, tz=UTC)


def _jwt(exp_offset: int = 3600) -> str:
    """Build an unsigned JWT-shaped token with an exp claim."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    claims = json.dumps({"exp": int(time.time()) + exp_offset}).encode()
    payload = base64.urlsafe_b64encode(claims).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


def _mock_jwt(token: str | None = None, status: int = 200) -> respx.Route:
    body: dict[str, Any] = {"jwt": token or _jwt()} if status == 200 else {"error": "unauthorized"}
    return respx.post(JWT_URL).mock(return_value=httpx.Response(status, json=body))


def _mock_detections(detects: Any = None, **extra: Any) -> respx.Route:
    payload = {"detects": DETECTIONS if detects is None else detects, **extra}
    return respx.get(DETECTIONS_URL).mock(return_value=httpx.Response(200, json=payload))


def _ok(detects: Any = None, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"detects": DETECTIONS if detects is None else detects, **extra})


@pytest.fixture(autouse=True)
def no_retry_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make tenacity backoff instant so retry tests do not wait."""
    monkeypatch.setattr(LimaCharlieClient._send.retry, "sleep", lambda _: None)


@pytest.fixture
def lc() -> LimaCharlieClient:
    return LimaCharlieClient(api_key="lc-test", org_id="test-org")


class TestJwtExchange:
    @respx.mock
    def test_posts_oid_and_secret_as_form(self, lc: LimaCharlieClient) -> None:
        token = _jwt()
        jwt_route = _mock_jwt(token)
        det_route = _mock_detections()

        lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert jwt_route.call_count == 1
        request = jwt_route.calls[0].request
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        body = parse_qs(request.content.decode())
        assert body == {"oid": ["test-org"], "secret": ["lc-test"]}
        assert det_route.calls[0].request.headers["authorization"] == f"Bearer {token}"

    @respx.mock
    def test_token_cached_across_calls(self, lc: LimaCharlieClient) -> None:
        jwt_route = _mock_jwt()
        _mock_detections()

        lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert jwt_route.call_count == 1

    @respx.mock
    def test_token_refreshed_near_expiry(self, lc: LimaCharlieClient) -> None:
        jwt_route = _mock_jwt(_jwt(exp_offset=60))
        _mock_detections()

        lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert jwt_route.call_count == 2

    @respx.mock
    def test_rejected_credentials_raise_auth_error(self, lc: LimaCharlieClient) -> None:
        _mock_jwt(status=401)
        det_route = _mock_detections()

        with pytest.raises(LimaCharlieAuthError, match="LC_API_KEY and LC_ORG_ID"):
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        assert det_route.call_count == 0

    @respx.mock
    def test_missing_token_in_response_raises_auth_error(self, lc: LimaCharlieClient) -> None:
        respx.post(JWT_URL).mock(return_value=httpx.Response(200, json={"unexpected": True}))

        with pytest.raises(LimaCharlieAuthError, match="did not contain a token"):
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

    @respx.mock
    def test_unauthorized_response_refreshes_once_then_succeeds(self, lc: LimaCharlieClient) -> None:
        jwt_route = _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(side_effect=[httpx.Response(401), _ok()])

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5
        assert det_route.call_count == 2
        assert jwt_route.call_count == 2

    @respx.mock
    def test_unauthorized_twice_raises_auth_error(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(return_value=httpx.Response(401))

        with pytest.raises(LimaCharlieAuthError, match="LC_API_KEY and LC_ORG_ID"):
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        assert det_route.call_count == 2

    @respx.mock
    def test_forbidden_raises_auth_error_without_retry(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(return_value=httpx.Response(403, json={"error": "denied"}))

        with pytest.raises(LimaCharlieAuthError, match="403"):
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        assert det_route.call_count == 1


class TestDetectionsQuery:
    @respx.mock
    def test_query_uses_insight_endpoint_with_seconds(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = _mock_detections()

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5
        params = det_route.calls[0].request.url.params
        assert params["start"] == "1711899000"
        assert params["end"] == "1711901000"
        assert params["cursor"] == "-"
        assert "is_compressed" not in params
        assert "limit" not in params

    @respx.mock
    def test_limit_and_category_are_forwarded(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = _mock_detections()

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END, limit=2, category="powershell")

        params = det_route.calls[0].request.url.params
        assert params["limit"] == "2"
        assert params["cat"] == "powershell"
        assert len(result) == 2

    @respx.mock
    def test_follows_next_cursor(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(
            side_effect=[_ok(DETECTIONS[:2], next_cursor="page-2"), _ok(DETECTIONS[2:])]
        )

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5
        assert det_route.call_count == 2
        assert det_route.calls[1].request.url.params["cursor"] == "page-2"

    @respx.mock
    def test_stops_paging_when_limit_reached(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(
            side_effect=[_ok(DETECTIONS[:3], next_cursor="page-2"), _ok(DETECTIONS[3:])]
        )

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END, limit=3)

        assert len(result) == 3
        assert det_route.call_count == 1

    @respx.mock
    def test_compressed_payload_is_unwrapped(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        blob = base64.b64encode(gzip.compress(json.dumps(DETECTIONS).encode())).decode()
        _mock_detections(detects=blob)

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5

    @respx.mock
    def test_client_side_range_check_drops_out_of_window(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        stray = {**DETECTIONS[0], "detect_id": "stray", "ts": 1711990000}
        _mock_detections(detects=[*DETECTIONS, stray])

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert [d["detect_id"] for d in result] == [d["detect_id"] for d in DETECTIONS]

    @respx.mock
    def test_millisecond_timestamps_pass_range_check(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        _mock_detections(detects=[{**d, "ts": d["ts"] * 1000} for d in DETECTIONS])

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5

    def test_end_before_start_is_rejected(self, lc: LimaCharlieClient) -> None:
        with pytest.raises(ValueError, match="before start"):
            lc.get_detections_by_time_range(WINDOW_END, WINDOW_START)


class TestRetryPolicy:
    @respx.mock
    def test_server_error_is_retried(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(side_effect=[httpx.Response(503), httpx.Response(502), _ok()])

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5
        assert det_route.call_count == 3

    @respx.mock
    def test_rate_limit_is_retried(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(side_effect=[httpx.Response(429), _ok()])

        lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert det_route.call_count == 2

    @respx.mock
    def test_read_timeout_is_retried(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(side_effect=[httpx.ReadTimeout("slow"), _ok()])

        result = lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)

        assert len(result) == 5
        assert det_route.call_count == 2

    @respx.mock
    def test_connect_errors_exhaust_into_connection_error(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(side_effect=httpx.ConnectError("refused"))

        with pytest.raises(LimaCharlieConnectionError):
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        assert det_route.call_count == 5

    @respx.mock
    def test_jwt_endpoint_unreachable_raises_connection_error(self, lc: LimaCharlieClient) -> None:
        jwt_route = respx.post(JWT_URL).mock(side_effect=httpx.ConnectError("refused"))

        with pytest.raises(LimaCharlieConnectionError, match="JWT endpoint"):
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        assert jwt_route.call_count == 5

    @respx.mock
    def test_not_found_is_not_retried(self, lc: LimaCharlieClient) -> None:
        _mock_jwt()
        det_route = respx.get(DETECTIONS_URL).mock(return_value=httpx.Response(404, json={"error": "nope"}))

        with pytest.raises(LimaCharlieAPIError) as excinfo:
            lc.get_detections_by_time_range(WINDOW_START, WINDOW_END)
        assert excinfo.value.status_code == 404
        assert not isinstance(excinfo.value, LimaCharlieAuthError)
        assert det_route.call_count == 1


class TestTechniqueTags:
    def test_extracts_ids_from_prefixed_tags(self) -> None:
        assert technique_ids_in("attack.t1059.001") == ["T1059.001"]
        assert technique_ids_in("ATTACK.T1059") == ["T1059"]
        assert technique_ids_in("attack.execution") == []
        assert technique_ids_in("T10590") == []


class TestSearchByTechnique:
    def _detection(self, tags: list[str], **extra: Any) -> dict[str, Any]:
        return {"detect_id": "x", "ts": 1711900000, "detect_mtd": {"description": "d", "tags": tags}, **extra}

    def test_exact_match_from_fixture(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T1059.001", DETECTIONS)
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "exact_technique"
        assert matches[0]["detect_id"] == "lc-detect-001"

    def test_parent_match_from_fixture(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T1003.001", DETECTIONS)
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "parent_technique"
        assert matches[0]["detect_id"] == "lc-detect-003"

    def test_no_match(self, lc: LimaCharlieClient) -> None:
        assert lc.search_detections_by_technique("T9999", DETECTIONS) == []

    def test_case_insensitive(self, lc: LimaCharlieClient) -> None:
        assert len(lc.search_detections_by_technique("t1083", DETECTIONS)) == 1

    def test_tagless_detection_not_matched(self, lc: LimaCharlieClient) -> None:
        assert lc.search_detections_by_technique("T1071", DETECTIONS) == []

    @pytest.mark.parametrize("tag", ["t1059.001", "attack.t1059.001", "T1059.001", "ATTACK.T1059.001"])
    def test_exact_match_tag_formats(self, lc: LimaCharlieClient, tag: str) -> None:
        matches = lc.search_detections_by_technique("T1059.001", [self._detection([tag])])
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "exact_technique"
        assert matches[0]["_matched_tag"] == tag

    def test_parent_match_with_prefixed_tag(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique(
            "T1059.001", [self._detection(["attack.execution", "attack.t1059"])]
        )
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "parent_technique"
        assert matches[0]["_matched_tag"] == "attack.t1059"

    def test_child_match_when_emulating_parent(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T1059", [self._detection(["attack.t1059.001"])])
        assert len(matches) == 1
        assert matches[0]["_match_type"] == "child_technique"
        assert matches[0]["_matched_tag"] == "attack.t1059.001"

    def test_exact_beats_child_when_both_present(self, lc: LimaCharlieClient) -> None:
        matches = lc.search_detections_by_technique("T1059", [self._detection(["t1059.001", "t1059"])])
        assert matches[0]["_match_type"] == "exact_technique"

    def test_sub_technique_does_not_child_match(self, lc: LimaCharlieClient) -> None:
        # Emulating a sub-technique never matches a sibling sub-technique
        assert lc.search_detections_by_technique("T1059.003", [self._detection(["t1059.001"])]) == []

    def test_category_is_a_tag_source(self, lc: LimaCharlieClient) -> None:
        detection = self._detection([], cat="ATT&CK T1059.001 PowerShell")
        matches = lc.search_detections_by_technique("T1059.001", [detection])
        assert len(matches) == 1
        assert matches[0]["_matched_tag"] == "ATT&CK T1059.001 PowerShell"

    def test_missing_detect_mtd_is_tolerated(self, lc: LimaCharlieClient) -> None:
        assert lc.search_detections_by_technique("T1059.001", [{"detect_id": "bare", "ts": 1}]) == []
