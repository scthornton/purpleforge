"""Caldera v2 REST API client."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import time
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class CalderaConnectionError(Exception):
    """Raised when Caldera cannot be reached after retries."""


class CalderaOperationTimeoutError(Exception):
    """Raised when a Caldera operation exceeds the timeout."""


class CalderaAPIError(Exception):
    """Raised on an API error that is not retried."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"Caldera API returned {status_code}: {message}")


class CalderaAuthError(CalderaAPIError):
    """Raised on 401 or 403. Check CALDERA_API_KEY and its permissions."""


class CalderaNoAgentsError(Exception):
    """Raised when no trusted agent is in the configured group."""


class _RetryableError(Exception):
    """Internal: a 429 or 5xx response that tenacity should retry."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"{status_code}: {message}")


def decode_link_output(encoded: str) -> str:
    """Decode a link result: base64 text that may wrap a JSON object with stdout and stderr.

    Returns the input unchanged when it is not valid base64.
    """
    if not encoded:
        return ""
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return encoded
    try:
        parsed = json.loads(raw)
    except ValueError:
        return raw
    if isinstance(parsed, dict) and ("stdout" in parsed or "stderr" in parsed):
        parts = [str(parsed.get("stdout") or ""), str(parsed.get("stderr") or "")]
        exit_code = parsed.get("exit_code")
        if exit_code not in (None, "", 0, "0"):
            parts.append(f"exit_code: {exit_code}")
        return "\n".join(p for p in parts if p)
    return raw


class CalderaClient:
    """Synchronous Caldera v2 REST API client using httpx."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 10) -> None:
        self._base_url = base_url
        self._client = httpx.Client(
            base_url=base_url,
            headers={"KEY": api_key},
            timeout=timeout,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=10),
        retry=retry_if_exception_type((httpx.TransportError, _RetryableError)),
        reraise=True,
    )
    def _send(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        resp = self._client.request(method, path, **kwargs)
        status = resp.status_code
        if status == 429 or status >= 500:
            raise _RetryableError(status, resp.text[:200])
        if status in (401, 403):
            raise CalderaAuthError(status, "request rejected; check CALDERA_API_KEY and its permissions")
        if status >= 400:
            raise CalderaAPIError(status, resp.text[:200])
        return resp

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Send a request. Transport errors, 429, and 5xx are retried; other 4xx fail at once."""
        try:
            return self._send(method, path, **kwargs)
        except httpx.TransportError as e:
            raise CalderaConnectionError(f"Cannot reach Caldera at {self._base_url}: {e}") from e
        except _RetryableError as e:
            raise CalderaAPIError(e.status_code, f"{e.message} (gave up after retries)") from e

    def get_abilities(self) -> list[dict[str, Any]]:
        """GET /api/v2/abilities: list all abilities."""
        data: list[dict[str, Any]] = self._request("GET", "/api/v2/abilities").json()
        return data

    def get_agents(self) -> list[dict[str, Any]]:
        """GET /api/v2/agents: list every agent known to the server."""
        data: list[dict[str, Any]] = self._request("GET", "/api/v2/agents").json()
        return data

    def find_agents(self, group: str) -> list[dict[str, Any]]:
        """Return the trusted agents in a group, or raise CalderaNoAgentsError."""
        agents = self.get_agents()
        matching = [a for a in agents if a.get("group") == group and a.get("trusted", True)]
        if not matching:
            groups = sorted({str(a.get("group", "")) for a in agents}) or ["none"]
            raise CalderaNoAgentsError(
                f"No trusted Caldera agent in group '{group}'. Groups with agents: {', '.join(groups)}. "
                "Set CALDERA_GROUP to a group that has a trusted agent."
            )
        return matching

    def create_adversary(self, name: str, ability_ids: list[str], description: str = "") -> dict[str, Any]:
        """POST /api/v2/adversaries: create an adversary profile."""
        payload = {
            "name": name,
            "description": description or f"PurpleForge adversary: {name}",
            "atomic_ordering": ability_ids,
        }
        data: dict[str, Any] = self._request("POST", "/api/v2/adversaries", json=payload).json()
        return data

    def delete_adversary(self, adversary_id: str) -> None:
        """DELETE /api/v2/adversaries/{id}: remove an adversary profile."""
        self._request("DELETE", f"/api/v2/adversaries/{adversary_id}")

    def list_operations(self) -> list[dict[str, Any]]:
        """GET /api/v2/operations: list all operations."""
        data: list[dict[str, Any]] = self._request("GET", "/api/v2/operations").json()
        return data

    def create_operation(self, name: str, adversary_id: str, group: str) -> dict[str, Any]:
        """POST /api/v2/operations: create and start an operation against an agent group."""
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "auto_close": True,
            "state": "running",
        }
        data: dict[str, Any] = self._request("POST", "/api/v2/operations", json=payload).json()
        return data

    def get_operation(self, operation_id: str) -> dict[str, Any]:
        """GET /api/v2/operations/{id}: operation details including the link chain."""
        data: dict[str, Any] = self._request("GET", f"/api/v2/operations/{operation_id}").json()
        return data

    def get_link_result(self, operation_id: str, link_id: str) -> str:
        """GET /api/v2/operations/{id}/links/{link_id}/result: decoded command output, or empty."""
        try:
            resp = self._request("GET", f"/api/v2/operations/{operation_id}/links/{link_id}/result")
        except CalderaAPIError as e:
            if e.status_code == 404:
                return ""
            raise
        data = resp.json()
        return decode_link_output(str(data.get("result") or ""))

    def wait_for_operation(self, operation_id: str, timeout: int = 300, poll_interval: int = 5) -> dict[str, Any]:
        """Poll an operation until its state is finished or the timeout elapses."""
        start = time.monotonic()
        while True:
            op = self.get_operation(operation_id)
            state = op.get("state", "")
            if state == "finished":
                return op
            elapsed = time.monotonic() - start
            if elapsed >= timeout:
                raise CalderaOperationTimeoutError(
                    f"Operation {operation_id} timed out after {timeout}s (state: {state})"
                )
            time.sleep(poll_interval)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
