"""Timestamp parsing shared by API clients and the detection validator."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# Epoch values above this are treated as milliseconds. 1e11 seconds is the year 5138
# and 1e11 milliseconds is March 1973, so the threshold cannot misclassify real data.
MILLISECOND_THRESHOLD = 1e11


def parse_timestamp(value: Any) -> datetime:
    """Return an aware UTC datetime for an epoch number, ISO 8601 string, or datetime.

    Accepts epoch seconds (int or float), epoch milliseconds (values above 1e11),
    numeric strings, ISO strings with a zone offset or a trailing Z, and naive ISO
    strings, which are assumed to be UTC. Raises ValueError for anything else.
    """
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if value is None or isinstance(value, bool):
        raise ValueError(f"Cannot parse timestamp from {value!r}")
    if isinstance(value, int | float):
        return _from_epoch(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Cannot parse timestamp from an empty string")
        try:
            return _from_epoch(float(text))
        except ValueError:
            pass
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as e:
            raise ValueError(f"Cannot parse timestamp from {value!r}") from e
        return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise ValueError(f"Cannot parse timestamp from {value!r}")


def _from_epoch(epoch: float) -> datetime:
    if epoch > MILLISECOND_THRESHOLD:
        epoch = epoch / 1000.0
    return datetime.fromtimestamp(epoch, tz=UTC)
