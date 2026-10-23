"""Execution-time Atomic Red Team fallback for failed Caldera emulations.

The resolver already falls back to Atomic at planning time when no Caldera
ability exists for a technique. This module covers the other case the live lab
surfaced: a Caldera ability was selected and ran, but the stock ability was
broken and returned a non-zero status on a healthy host and agent. When that
happens, the same technique is re-run through Atomic Red Team and whichever
result actually executed is kept, so coverage is not dragged down by a
vendor-shipped command that never worked.

The functions here are pure: they decide which techniques to retry and how to
merge the two result sets. The orchestrator owns the I/O (building the runner
and executing).
"""

from __future__ import annotations

from purpleforge.models.emulation import (
    EmulationMethod,
    EmulationRecord,
    EmulationStatus,
    ResolvedTechnique,
)


def select_fallback_targets(
    caldera_records: list[EmulationRecord],
    caldera_techs: list[ResolvedTechnique],
) -> list[ResolvedTechnique]:
    """Return an Atomic-method technique for each Caldera record that failed.

    Only ``FAILED`` records are retried. A timeout or error is a different
    problem (the operation never finished, or the host was unreachable), not a
    broken ability, so it is left alone. The technique name is carried over from
    the original Caldera plan entry.
    """
    name_by_tid = {t.technique_id: t.technique_name for t in caldera_techs}
    targets: list[ResolvedTechnique] = []
    for record in caldera_records:
        if record.status != EmulationStatus.FAILED:
            continue
        targets.append(
            ResolvedTechnique(
                technique_id=record.technique_id,
                technique_name=name_by_tid.get(record.technique_id, record.technique_id),
                method=EmulationMethod.ATOMIC,
            )
        )
    return targets


def merge_fallback_results(
    caldera_records: list[EmulationRecord],
    atomic_records: list[EmulationRecord],
) -> list[EmulationRecord]:
    """Merge Atomic retries into the Caldera results, one record per technique.

    For a failed Caldera technique whose Atomic retry succeeded, the Atomic
    record replaces the Caldera failure, so the technique counts as executed and
    is validated against detections. When the Atomic retry did not succeed
    either, the Caldera failure is kept with a note that the fallback was tried
    and also failed. Records that did not fail, and techniques with no retry, are
    passed through unchanged. Order is preserved.
    """
    atomic_by_tid = {r.technique_id: r for r in atomic_records}
    merged: list[EmulationRecord] = []
    for record in caldera_records:
        atomic = atomic_by_tid.get(record.technique_id)
        if record.status == EmulationStatus.FAILED and atomic is not None:
            if atomic.status == EmulationStatus.SUCCESS:
                merged.append(atomic)
            else:
                merged.append(_note_fallback_failed(record, atomic))
            continue
        merged.append(record)
    return merged


def _note_fallback_failed(caldera: EmulationRecord, atomic: EmulationRecord) -> EmulationRecord:
    """Return the Caldera failure annotated that the Atomic fallback also failed."""
    note = f"Atomic Red Team fallback also did not succeed (status {atomic.status.value})"
    base = caldera.error_message
    return caldera.model_copy(update={"error_message": f"{base}; {note}" if base else note})
