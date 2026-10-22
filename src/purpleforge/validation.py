"""Validate user-supplied identifiers before they are used to build file paths."""

from __future__ import annotations

import re

import click

RUN_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_run_id(run_id: str) -> str:
    """Return the run id if it is well formed, else raise click.BadParameter.

    A run id is 12 lowercase hex characters, the format RunStore generates.
    Rejecting anything else keeps a value like '../../etc' out of a path.
    """
    if not RUN_ID_PATTERN.match(run_id):
        raise click.BadParameter(f"Invalid run id: {run_id!r}. Expected 12 hex characters.")
    return run_id


def validate_technique_id(technique: str) -> str:
    """Return the technique id if it is a valid ATT&CK id, else raise click.BadParameter."""
    if not TECHNIQUE_ID_PATTERN.match(technique):
        raise click.BadParameter(f"Invalid technique id: {technique!r}. Expected the form T1059 or T1059.001.")
    return technique
