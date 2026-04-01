"""Caldera REST API client."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)


class CalderaConnectionError(Exception):
    """Raised when Caldera is unreachable."""


class CalderaOperationTimeoutError(Exception):
    """Raised when a Caldera operation exceeds the timeout."""


class CalderaAPIError(Exception):
    """Raised on unexpected Caldera API errors."""


class CalderaClient:
    """Synchronous Caldera REST API client using httpx."""

    def __init__(self, base_url: str, api_key: str, timeout: int = 10) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            headers={"KEY": api_key},
            timeout=timeout,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(min=1, max=10),
        retry=retry_if_exception_type(httpx.HTTPStatusError),
    )
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            resp = self._client.request(method, path, **kwargs)
            resp.raise_for_status()
            return resp
        except httpx.ConnectError as e:
            raise CalderaConnectionError(f"Cannot connect to Caldera: {e}") from e

    def get_abilities(self) -> list[dict[str, Any]]:
        """GET /api/v2/abilities — list all abilities."""
        resp = self._request("GET", "/api/v2/abilities")
        return resp.json()  # type: ignore[no-any-return]

    def find_abilities_by_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Find abilities matching a technique ID (exact match, then parent match)."""
        abilities = self.get_abilities()

        # Exact match
        exact = [a for a in abilities if a.get("technique_id") == technique_id]
        if exact:
            return exact

        # Parent match (first 5 chars: T1059 for T1059.001)
        parent_id = technique_id[:5]
        return [a for a in abilities if a.get("technique_id") == parent_id]

    def create_adversary(self, name: str, ability_ids: list[str], description: str = "") -> dict[str, Any]:
        """POST /api/v2/adversaries — create an adversary profile."""
        payload = {
            "name": name,
            "description": description or f"PurpleForge adversary: {name}",
            "atomic_ordering": ability_ids,
        }
        resp = self._request("POST", "/api/v2/adversaries", json=payload)
        return resp.json()  # type: ignore[no-any-return]

    def list_operations(self) -> list[dict[str, Any]]:
        """GET /api/v2/operations — list all operations."""
        resp = self._request("GET", "/api/v2/operations")
        return resp.json()  # type: ignore[no-any-return]

    def create_operation(
        self, name: str, adversary_id: str, group: str = "purple_team"
    ) -> dict[str, Any]:
        """POST /api/v2/operations — create and start an operation."""
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "auto_close": True,
            "state": "running",
        }
        resp = self._request("POST", "/api/v2/operations", json=payload)
        return resp.json()  # type: ignore[no-any-return]

    def get_operation(self, operation_id: str) -> dict[str, Any]:
        """GET /api/v2/operations/{id} — get operation details."""
        resp = self._request("GET", f"/api/v2/operations/{operation_id}")
        return resp.json()  # type: ignore[no-any-return]

    def wait_for_operation(
        self, operation_id: str, timeout: int = 300, poll_interval: int = 5
    ) -> dict[str, Any]:
        """Poll operation until state=finished or timeout."""
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
