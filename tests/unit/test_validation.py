"""Tests for identifier validation guards."""

from __future__ import annotations

import click
import pytest

from purpleforge.validation import validate_run_id, validate_technique_id


class TestValidateRunId:
    def test_accepts_valid(self) -> None:
        assert validate_run_id("0123abcd4567") == "0123abcd4567"

    @pytest.mark.parametrize(
        "bad",
        ["../../../../etc", "ABCDEF012345", "0123abcd456", "0123abcd45678", "0123abcd/567", ""],
    )
    def test_rejects_bad(self, bad: str) -> None:
        with pytest.raises(click.BadParameter):
            validate_run_id(bad)


class TestValidateTechniqueId:
    @pytest.mark.parametrize("good", ["T1059", "T1059.001", "T1003.001"])
    def test_accepts_valid(self, good: str) -> None:
        assert validate_technique_id(good) == good

    @pytest.mark.parametrize("bad", ["passwd", "../../etc", "T105", "t1059", "T1059.1", "T1059.0011"])
    def test_rejects_bad(self, bad: str) -> None:
        with pytest.raises(click.BadParameter):
            validate_technique_id(bad)
