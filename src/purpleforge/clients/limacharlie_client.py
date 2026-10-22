"""LimaCharlie REST API client.

Authentication follows the vendor SDK: the organization ID and API key are exchanged
for a short-lived JWT at the JWT endpoint, and the JWT is sent as a Bearer token to
the REST API. Detections are read from the Insight historic detections endpoint with
a server-side time window and cursor pagination.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import math
import re
import time
import zlib
from datetime import datetime
from typing import Any

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from purpleforge.timeutil import parse_timestamp

logger = logging.getLogger(__name__)

# Technique IDs embedded in tags or categories, for example "attack.t1059.001" or "T1059".
TECHNIQUE_TAG_PATTERN = re.compile(r"\bt\d{4}(\.\d{3})?\b", re.IGNORECASE)

DEFAULT_BASE_URL = "https://api.limacharlie.io/v1"
DEFAULT_JWT_URL = "https://jwt.limacharlie.io"
JWT_DEFAULT_LIFETIME_SECONDS = 3600
JWT_REFRESH_MARGIN_SECONDS = 300
MAX_DETECTION_PAGES = 1000
RETRY_ATTEMPTS = 5


class LimaCharlieConnectionError(Exception):
    """Raised when LimaCharlie is unreachable after retries."""


class LimaCharlieAPIError(Exception):
    """Raised on an API error that will not be retried."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class LimaCharlieAuthError(LimaCharlieAPIError):
    """Raised when the API key or organization ID is rejected."""


class LimaCharlieRetryableError(LimaCharlieAPIError):
    """Raised on 429 and 5xx responses. Retried with backoff before surfacing."""


class LimaCharlieRateLimitError(LimaCharlieRetryableError):
    """Raised on rate limit (429)."""


def technique_ids_in(text: str) -> list[str]:
    """Extract upper-case technique IDs from a tag or category string."""
    return [m.group(0).upper() for m in TECHNIQUE_TAG_PATTERN.finditer(text)]


def _excerpt(resp: httpx.Response, limit: int = 200) -> str:
    return resp.text.strip().replace("\n", " ")[:limit]


def _decode_jwt_exp(token: str) -> float | None:
    """Read the exp claim from a JWT payload without verifying the signature."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except (IndexError, ValueError, TypeError, AttributeError, binascii.Error):
        return None


def _unwrap_detects(value: Any) -> list[dict[str, Any]]:
    """Return the detections list, decoding the base64 gzip form the API uses when compressing."""
    if isinstance(value, list):
        return [d for d in value if isinstance(d, dict)]
    if isinstance(value, str) and value:
        try:
            decoded = json.loads(zlib.decompress(base64.b64decode(value), 16 + zlib.MAX_WBITS))
        except (binascii.Error, zlib.error, ValueError) as e:
            raise LimaCharlieAPIError(f"Could not decode compressed detections payload: {e}") from e
        if isinstance(decoded, list):
            return [d for d in decoded if isinstance(d, dict)]
    return []


class LimaCharlieClient:
    """Synchronous LimaCharlie REST API client using httpx."""

    BASE_URL = DEFAULT_BASE_URL
    JWT_URL = DEFAULT_JWT_URL

    def __init__(
        self,
        api_key: str,
        org_id: str,
        timeout: int = 15,
        base_url: str = DEFAULT_BASE_URL,
        jwt_url: str = DEFAULT_JWT_URL,
    ) -> None:
        self._api_key = api_key
        self._org_id = org_id
        self._jwt_url = jwt_url
        self._client = httpx.Client(base_url=base_url, timeout=timeout)
        self._jwt: str | None = None
        self._jwt_expires_at: float = 0.0

    # Authentication

    def _token(self, force_refresh: bool = False) -> str:
        """Return a valid JWT, exchanging the API key when none is cached or it is near expiry."""
        refresh_at = self._jwt_expires_at - JWT_REFRESH_MARGIN_SECONDS
        if force_refresh or self._jwt is None or time.time() >= refresh_at:
            self._jwt = self._fetch_jwt()
            exp = _decode_jwt_exp(self._jwt)
            self._jwt_expires_at = exp if exp is not None else time.time() + JWT_DEFAULT_LIFETIME_SECONDS
        return self._jwt

    def _fetch_jwt(self) -> str:
        """POST oid and secret to the JWT endpoint and return the token."""
        logger.debug("Requesting LimaCharlie JWT for organization %s", self._org_id)
        try:
            resp = self._send("POST", self._jwt_url, data={"oid": self._org_id, "secret": self._api_key})
        except httpx.TransportError as e:
            raise LimaCharlieConnectionError(f"Cannot reach LimaCharlie JWT endpoint {self._jwt_url}: {e}") from e
        if resp.status_code in (400, 401, 403):
            raise LimaCharlieAuthError(
                f"LimaCharlie rejected the credentials for organization {self._org_id} "
                f"(HTTP {resp.status_code}). Check LC_API_KEY and LC_ORG_ID.",
                status_code=resp.status_code,
            )
        if resp.status_code >= 400:
            raise LimaCharlieAPIError(
                f"LimaCharlie JWT request failed (HTTP {resp.status_code}): {_excerpt(resp)}",
                status_code=resp.status_code,
            )
        try:
            token = resp.json()["jwt"]
        except (ValueError, KeyError, TypeError) as e:
            raise LimaCharlieAuthError("LimaCharlie JWT response did not contain a token") from e
        if not isinstance(token, str) or not token:
            raise LimaCharlieAuthError("LimaCharlie JWT response did not contain a token")
        return token

    def _auth_headers(self, force_refresh: bool = False) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token(force_refresh=force_refresh)}"}

    # Transport

    @retry(
        stop=stop_after_attempt(RETRY_ATTEMPTS),
        wait=wait_exponential(min=1, max=30),
        retry=retry_if_exception_type((httpx.TransportError, LimaCharlieRetryableError)),
        reraise=True,
    )
    def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send one request. Transport errors, 429, and 5xx are retried; other responses return."""
        resp = self._client.request(method, url, **kwargs)
        if resp.status_code == 429:
            raise LimaCharlieRateLimitError("Rate limited by LimaCharlie API (HTTP 429)", status_code=429)
        if resp.status_code >= 500:
            raise LimaCharlieRetryableError(
                f"LimaCharlie server error (HTTP {resp.status_code}): {_excerpt(resp)}",
                status_code=resp.status_code,
            )
        return resp

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Authenticated request with one JWT refresh on 401 and fail-fast on other 4xx."""
        try:
            resp = self._send(method, path, headers=self._auth_headers(), **kwargs)
            if resp.status_code == 401:
                logger.info("LimaCharlie returned 401; refreshing the JWT once")
                resp = self._send(method, path, headers=self._auth_headers(force_refresh=True), **kwargs)
        except httpx.TransportError as e:
            raise LimaCharlieConnectionError(f"Cannot reach LimaCharlie API: {e}") from e

        if resp.status_code == 401:
            raise LimaCharlieAuthError(
                "LimaCharlie still returned 401 after refreshing the token. Check LC_API_KEY and LC_ORG_ID.",
                status_code=401,
            )
        if resp.status_code == 403:
            raise LimaCharlieAuthError(
                f"LimaCharlie denied {method} {path} (HTTP 403). The API key lacks a permission "
                "required for this organization. Check LC_API_KEY and LC_ORG_ID.",
                status_code=403,
            )
        if resp.status_code >= 400:
            raise LimaCharlieAPIError(
                f"LimaCharlie API error (HTTP {resp.status_code}) for {method} {path}: {_excerpt(resp)}",
                status_code=resp.status_code,
            )
        return resp

    # Detections

    def get_detections_by_time_range(
        self,
        start: datetime,
        end: datetime,
        limit: int | None = None,
        category: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch historic detections inside [start, end].

        Calls GET /insight/{oid}/detections with start and end in epoch seconds and
        follows next_cursor until the server reports no more pages. A client-side range
        check is kept as a safety net against server-side window differences.
        """
        start_utc = parse_timestamp(start)
        end_utc = parse_timestamp(end)
        if end_utc < start_utc:
            raise ValueError(f"Detection window end {end_utc.isoformat()} is before start {start_utc.isoformat()}")
        start_s = int(math.floor(start_utc.timestamp()))
        end_s = int(math.ceil(end_utc.timestamp()))

        detections: list[dict[str, Any]] = []
        cursor = "-"
        for _ in range(MAX_DETECTION_PAGES):
            params: dict[str, str] = {"start": str(start_s), "end": str(end_s), "cursor": cursor}
            if limit is not None:
                params["limit"] = str(limit)
            if category:
                params["cat"] = category
            resp = self._request("GET", f"/insight/{self._org_id}/detections", params=params)
            data = resp.json()
            if not isinstance(data, dict):
                raise LimaCharlieAPIError("Unexpected detections response shape (expected a JSON object)")
            detections.extend(_unwrap_detects(data.get("detects", [])))
            next_cursor = str(data.get("next_cursor") or "")
            if not next_cursor or next_cursor == cursor:
                break
            if limit is not None and len(detections) >= limit:
                break
            cursor = next_cursor
        else:
            logger.warning("Stopped after %d detection pages; results may be incomplete", MAX_DETECTION_PAGES)

        if limit is not None:
            detections = detections[:limit]
        in_range = [d for d in detections if self._detection_in_range(d, start_utc, end_utc)]
        if len(in_range) != len(detections):
            logger.debug("Dropped %d detections outside the requested window", len(detections) - len(in_range))
        logger.info("Fetched %d detections between %s and %s", len(in_range), start_utc, end_utc)
        return in_range

    def search_detections_by_technique(
        self, technique_id: str, detections: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Filter detections whose tags or category name the technique.

        Technique IDs are extracted from each tag and from the detection category with
        TECHNIQUE_TAG_PATTERN, so "t1059.001", "attack.t1059.001", and "T1059.001" all
        match. Match types in priority order: exact_technique; child_technique when the
        emulated technique is a parent and a tag names one of its sub-techniques;
        parent_technique when the emulated technique is a sub-technique and a tag names
        its parent. Matching is case-insensitive.
        """
        wanted = technique_id.upper()
        parent = wanted.split(".")[0]
        is_sub_technique = "." in wanted
        matches: list[dict[str, Any]] = []

        for detection in detections:
            labeled = self._technique_labels(detection)
            exact = next((label for label, tid in labeled if tid == wanted), None)
            if exact is not None:
                matches.append({**detection, "_match_type": "exact_technique", "_matched_tag": exact})
                continue
            if is_sub_technique:
                parent_label = next((label for label, tid in labeled if tid == parent), None)
                if parent_label is not None:
                    matches.append({**detection, "_match_type": "parent_technique", "_matched_tag": parent_label})
                continue
            child_label = next((label for label, tid in labeled if tid.startswith(wanted + ".")), None)
            if child_label is not None:
                matches.append({**detection, "_match_type": "child_technique", "_matched_tag": child_label})

        return matches

    @staticmethod
    def _technique_labels(detection: dict[str, Any]) -> list[tuple[str, str]]:
        """Return (source label, technique id) pairs from the detection tags and category."""
        mtd = detection.get("detect_mtd") or {}
        sources = [str(tag) for tag in (mtd.get("tags") or [])]
        for cat in (detection.get("cat"), mtd.get("cat")):
            if cat:
                sources.append(str(cat))
        return [(source, tid) for source in sources for tid in technique_ids_in(source)]

    @staticmethod
    def _detection_in_range(detection: dict[str, Any], start: datetime, end: datetime) -> bool:
        """Check if a detection timestamp falls within [start, end]."""
        ts = detection.get("ts")
        if ts is None:
            return False
        try:
            det_time = parse_timestamp(ts)
        except ValueError:
            return False
        return parse_timestamp(start) <= det_time <= parse_timestamp(end)

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()
