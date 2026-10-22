"""Tests for tolerant timestamp parsing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from purpleforge.timeutil import parse_timestamp

# 1711900000 seconds since the epoch
EXPECTED = datetime(2024, 3, 31, 15, 46, 40, tzinfo=UTC)


class TestParseTimestamp:
    def test_epoch_seconds_int(self) -> None:
        assert parse_timestamp(1711900000) == EXPECTED

    def test_epoch_seconds_float(self) -> None:
        assert parse_timestamp(1711900000.5) == EXPECTED + timedelta(milliseconds=500)

    def test_epoch_milliseconds(self) -> None:
        assert parse_timestamp(1711900000000) == EXPECTED

    def test_epoch_milliseconds_float(self) -> None:
        assert parse_timestamp(1711900000250.0) == EXPECTED + timedelta(milliseconds=250)

    def test_numeric_string_seconds(self) -> None:
        assert parse_timestamp("1711900000") == EXPECTED

    def test_numeric_string_milliseconds(self) -> None:
        assert parse_timestamp("1711900000000") == EXPECTED

    def test_iso_with_z_suffix(self) -> None:
        assert parse_timestamp("2024-03-31T15:46:40Z") == EXPECTED

    def test_iso_with_offset_is_normalized_to_utc(self) -> None:
        parsed = parse_timestamp("2024-03-31T17:46:40+02:00")
        assert parsed == EXPECTED
        assert parsed.utcoffset() == timedelta(0)

    def test_naive_iso_assumed_utc(self) -> None:
        assert parse_timestamp("2024-03-31T15:46:40") == EXPECTED

    def test_iso_with_fractional_seconds(self) -> None:
        assert parse_timestamp("2024-03-31T15:46:40.250Z") == EXPECTED + timedelta(milliseconds=250)

    def test_aware_datetime_passthrough(self) -> None:
        aware = datetime(2024, 3, 31, 17, 46, 40, tzinfo=timezone(timedelta(hours=2)))
        assert parse_timestamp(aware) == EXPECTED

    def test_naive_datetime_assumed_utc(self) -> None:
        assert parse_timestamp(datetime(2024, 3, 31, 15, 46, 40)) == EXPECTED

    @pytest.mark.parametrize("bad", [None, "", "   ", "not a time", True, False, [], {}, object()])
    def test_invalid_values_raise(self, bad: Any) -> None:
        with pytest.raises(ValueError):
            parse_timestamp(bad)
