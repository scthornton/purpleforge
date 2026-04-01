"""Technique resolver: maps techniques to execution methods (Caldera-first, Atomic fallback)."""

from __future__ import annotations

import logging
from typing import Any

from purpleforge.clients.atomic_runner import AtomicRunner, WinRMConnectionError
from purpleforge.clients.caldera_client import CalderaClient
from purpleforge.models.emulation import EmulationMethod, ExecutionPlan, ResolvedTechnique
from purpleforge.models.extraction import NormalizedTechnique

logger = logging.getLogger(__name__)


class Resolver:
    """For each technique, determine execution method and record ability/test IDs."""

    def __init__(self, caldera: CalderaClient, atomic: AtomicRunner) -> None:
        self._caldera = caldera
        self._atomic = atomic

    def resolve(self, techniques: list[NormalizedTechnique], run_id: str) -> ExecutionPlan:
        """Resolve all techniques to execution methods.

        Priority: Caldera exact match → Caldera parent match → Atomic → Skip
        """
        # Fetch all abilities once
        abilities = self._caldera.get_abilities()
        ability_index: dict[str, list[dict[str, Any]]] = {}
        for ability in abilities:
            tid = ability.get("technique_id", "")
            ability_index.setdefault(tid, []).append(ability)

        # Check if Atomic is reachable
        atomic_available = True
        try:
            self._atomic.ensure_atomic_installed()
        except WinRMConnectionError:
            logger.warning("WinRM unreachable — Atomic tests unavailable")
            atomic_available = False

        resolved: list[ResolvedTechnique] = []
        caldera_count = 0
        atomic_count = 0
        skip_count = 0

        for technique in techniques:
            tid = technique.technique_id
            parent_tid = tid[:5] if "." in tid else tid

            # Try exact Caldera match
            exact_abilities = ability_index.get(tid, [])
            if exact_abilities:
                resolved.append(ResolvedTechnique(
                    technique_id=tid,
                    technique_name=technique.technique_name,
                    method=EmulationMethod.CALDERA,
                    ability_id=exact_abilities[0].get("ability_id", ""),
                ))
                caldera_count += 1
                continue

            # Try parent Caldera match
            parent_abilities = ability_index.get(parent_tid, [])
            if parent_abilities and parent_tid != tid:
                resolved.append(ResolvedTechnique(
                    technique_id=tid,
                    technique_name=technique.technique_name,
                    method=EmulationMethod.CALDERA,
                    ability_id=parent_abilities[0].get("ability_id", ""),
                    parent_match=True,
                ))
                caldera_count += 1
                continue

            # Try Atomic fallback
            if atomic_available:
                try:
                    if self._atomic.check_technique_available(tid):
                        resolved.append(ResolvedTechnique(
                            technique_id=tid,
                            technique_name=technique.technique_name,
                            method=EmulationMethod.ATOMIC,
                        ))
                        atomic_count += 1
                        continue
                except WinRMConnectionError:
                    atomic_available = False
                    logger.warning("WinRM connection lost during resolution")

            # Skip
            resolved.append(ResolvedTechnique(
                technique_id=tid,
                technique_name=technique.technique_name,
                method=EmulationMethod.SKIP,
                skip_reason=f"No emulation available for {tid}",
            ))
            skip_count += 1

        return ExecutionPlan(
            run_id=run_id,
            techniques=resolved,
            caldera_count=caldera_count,
            atomic_count=atomic_count,
            skip_count=skip_count,
        )
