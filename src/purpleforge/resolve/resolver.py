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

        Priority: Caldera exact match, then Caldera parent match, then Atomic, then skip.
        A Caldera ability is only selected when it can run on a connected agent's
        platform, so a Linux-only ability is not chosen for a Windows agent.
        """
        # Fetch all abilities once
        abilities = self._caldera.get_abilities()
        ability_index: dict[str, list[dict[str, Any]]] = {}
        for ability in abilities:
            tid = ability.get("technique_id", "")
            ability_index.setdefault(tid, []).append(ability)

        # Platforms of the connected agents. None means unknown, in which case
        # abilities are not filtered by platform (first-match behavior).
        agent_platforms = self._agent_platforms()

        # Check if Atomic is reachable. RESOLVE is read-only: it probes the host
        # but never installs the framework or runs a test.
        atomic_available = True
        try:
            self._atomic.check_connection()
        except WinRMConnectionError:
            logger.warning("WinRM unreachable, Atomic tests unavailable")
            atomic_available = False

        resolved: list[ResolvedTechnique] = []
        caldera_count = 0
        atomic_count = 0
        skip_count = 0

        for technique in techniques:
            tid = technique.technique_id
            parent_tid = tid[:5] if "." in tid else tid

            # Try exact Caldera match, picking an ability the agents can run.
            exact = self._select_ability(ability_index.get(tid, []), agent_platforms)
            if exact:
                resolved.append(
                    ResolvedTechnique(
                        technique_id=tid,
                        technique_name=technique.technique_name,
                        method=EmulationMethod.CALDERA,
                        ability_id=exact.get("ability_id", ""),
                    )
                )
                caldera_count += 1
                continue

            # Try parent Caldera match.
            if parent_tid != tid:
                parent = self._select_ability(ability_index.get(parent_tid, []), agent_platforms)
                if parent:
                    resolved.append(
                        ResolvedTechnique(
                            technique_id=tid,
                            technique_name=technique.technique_name,
                            method=EmulationMethod.CALDERA,
                            ability_id=parent.get("ability_id", ""),
                            parent_match=True,
                        )
                    )
                    caldera_count += 1
                    continue

            # Try Atomic fallback
            if atomic_available:
                try:
                    if self._atomic.check_technique_available(tid):
                        resolved.append(
                            ResolvedTechnique(
                                technique_id=tid,
                                technique_name=technique.technique_name,
                                method=EmulationMethod.ATOMIC,
                            )
                        )
                        atomic_count += 1
                        continue
                except WinRMConnectionError:
                    atomic_available = False
                    logger.warning("WinRM connection lost during resolution")

            # Skip
            resolved.append(
                ResolvedTechnique(
                    technique_id=tid,
                    technique_name=technique.technique_name,
                    method=EmulationMethod.SKIP,
                    skip_reason=f"No emulation available for {tid}",
                )
            )
            skip_count += 1

        return ExecutionPlan(
            run_id=run_id,
            techniques=resolved,
            caldera_count=caldera_count,
            atomic_count=atomic_count,
            skip_count=skip_count,
        )

    def _agent_platforms(self) -> set[str] | None:
        """Return the set of platforms of the connected agents, or None when unknown."""
        try:
            agents = self._caldera.get_agents()
            found: set[str] = {str(p) for a in agents if isinstance(a, dict) and (p := a.get("platform"))}
        except Exception:
            # Agents unavailable: treat platforms as unknown and do not filter.
            return None
        return found or None

    def _select_ability(
        self, abilities: list[dict[str, Any]], agent_platforms: set[str] | None
    ) -> dict[str, Any] | None:
        """Return the first ability that can run on a connected agent, or None."""
        for ability in abilities:
            if self._runs_on(ability, agent_platforms):
                return ability
        return None

    @staticmethod
    def _runs_on(ability: dict[str, Any], agent_platforms: set[str] | None) -> bool:
        """Whether an ability can run on a connected agent's platform.

        Unknown agent platforms, or an ability with no executor platform data,
        are accepted so resolution does not regress on simplified inputs.
        """
        if agent_platforms is None:
            return True
        executors = ability.get("executors")
        if not executors:
            return True
        ability_platforms = {e.get("platform") for e in executors if isinstance(e, dict) and e.get("platform")}
        if not ability_platforms:
            return True
        return bool(ability_platforms & agent_platforms)
