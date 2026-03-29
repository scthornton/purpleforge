"""Pipeline orchestrator — state machine coordinating all pipeline steps."""

from __future__ import annotations

import logging
import time
from pathlib import Path

import yaml

from purpleforge.clients.atomic_runner import AtomicRunner
from purpleforge.clients.caldera_client import CalderaClient
from purpleforge.config import PurpleForgeSettings
from purpleforge.execute.atomic_executor import AtomicExecutor
from purpleforge.execute.caldera_executor import CalderaExecutor
from purpleforge.ingest.pdf_loader import chunk_documents, load_pdf
from purpleforge.ingest.ttp_extractor import TTPExtractor
from purpleforge.ingest.vector_store import VectorStore
from purpleforge.models.emulation import EmulationMethod, EmulationRecord
from purpleforge.models.extraction import NormalizedTechnique
from purpleforge.models.pipeline import RunStatus
from purpleforge.pipeline.run_store import RunStore
from purpleforge.resolve.resolver import Resolver

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """State machine: INGEST → REVIEW → RESOLVE → EXECUTE → WAIT → VALIDATE → REPORT → ADVISE."""

    def __init__(self, settings: PurpleForgeSettings) -> None:
        self.settings = settings
        self.store = RunStore(settings.run_base_dir)

    def start_run(self, source_path: str) -> str:
        """Start a new pipeline run: create run, execute INGEST, pause at AWAITING_REVIEW.

        Returns the run_id.
        """
        run = self.store.create_run(
            source_path=source_path,
            config_snapshot={
                "openai_model": self.settings.openai_model,
                "detection_wait_seconds": self.settings.detection_wait_seconds,
                "caldera_operation_timeout": self.settings.caldera_operation_timeout,
            },
        )
        run_id = run.run_id

        try:
            self._step_ingest(run_id, source_path)
        except Exception as e:
            self.store.fail_step(run_id, "INGEST", str(e))
            raise

        return run_id

    def confirm_run(self, run_id: str, ttps_file: str | None = None) -> None:
        """Confirm extracted TTPs and proceed through remaining pipeline steps.

        Loads TTPs from file (operator may have edited), then runs:
        RESOLVE → EXECUTE → WAIT → VALIDATE → REPORT → ADVISE
        """
        run = self.store.load_run(run_id)

        if run.status != RunStatus.AWAITING_REVIEW:
            raise PipelineError(
                f"Run {run_id} is in state '{run.status.value}', expected 'awaiting_review'. "
                f"Only runs in AWAITING_REVIEW can be confirmed."
            )

        # Load TTPs (operator may have edited the YAML)
        if ttps_file:
            ttps_path = Path(ttps_file)
        else:
            ttps_path = Path(self.settings.run_base_dir) / run_id / "extracted_ttps.yaml"

        if not ttps_path.exists():
            raise PipelineError(f"TTPs file not found: {ttps_path}")

        ttps_data = yaml.safe_load(ttps_path.read_text())
        techniques = [NormalizedTechnique.model_validate(t) for t in ttps_data.get("techniques", [])]

        if not techniques:
            raise PipelineError("No techniques found in TTPs file")

        logger.info("Confirmed %d techniques for run %s", len(techniques), run_id)

        # Store confirmed techniques
        self.store.write_artifact(
            run_id,
            "confirmed_ttps.yaml",
            {"techniques": [t.model_dump() for t in techniques]},
        )

        # RESOLVE → EXECUTE → WAIT
        try:
            execution_plan = self._step_resolve(run_id, techniques)
        except Exception as e:
            self.store.fail_step(run_id, "RESOLVE", str(e))
            raise

        try:
            self._step_execute(run_id, execution_plan)
        except Exception as e:
            self.store.fail_step(run_id, "EXECUTE", str(e))
            raise

        self._step_wait(run_id)

        # TODO: Phase 4 will wire VALIDATE → REPORT → ADVISE
        self.store.update_status(run_id, RunStatus.COMPLETE)

    def _step_ingest(self, run_id: str, source_path: str) -> None:
        """INGEST step: load PDF → chunk → embed → extract TTPs."""
        self.store.update_status(run_id, RunStatus.INGESTING)
        self.store.start_step(run_id, "INGEST")

        # Load and chunk PDF
        documents = load_pdf(source_path)
        chunks = chunk_documents(documents)
        logger.info("Loaded %d pages, %d chunks from %s", len(documents), len(chunks), source_path)

        # Embed into ChromaDB
        vector_store = VectorStore(
            run_id=run_id,
            api_key=self.settings.openai_api_key.get_secret_value(),
            persist_dir=self.settings.chroma_persist_dir,
        )
        vector_store.add_documents(chunks)

        # RAG retrieval for extraction context
        from purpleforge.ingest.ttp_extractor import RAG_QUERY

        relevant_chunks = vector_store.similarity_search(RAG_QUERY, k=10)

        # LLM extraction
        extractor = TTPExtractor(
            api_key=self.settings.openai_api_key.get_secret_value(),
            model=self.settings.openai_model,
        )
        ttps = extractor.extract(relevant_chunks)
        logger.info("Extracted %d techniques", len(ttps))

        # Write extracted TTPs as operator-reviewable YAML
        ttps_data = {
            "techniques": [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": t.tactic,
                    "description": t.description,
                    "operator_notes": "",
                }
                for t in ttps
            ]
        }

        # Add header comment by writing manually
        run_dir = Path(self.settings.run_base_dir) / run_id
        ttps_path = run_dir / "extracted_ttps.yaml"
        header = (
            f"# PurpleForge Extracted TTPs\n"
            f"# Run ID: {run_id}\n"
            f"# Source: {source_path}\n"
            f"#\n"
            f"# REVIEW INSTRUCTIONS:\n"
            f"# - Edit, add, or remove techniques as needed\n"
            f"# - Ensure technique_ids match T####.### format\n"
            f"# - When ready: purpleforge confirm --run-id {run_id}\n\n"
        )
        yaml_content = yaml.dump(ttps_data, default_flow_style=False, sort_keys=False)
        ttps_path.write_text(header + yaml_content)

        # Update state
        self.store.complete_step(run_id, "INGEST", artifact_path="extracted_ttps.yaml")
        self.store.update_status(run_id, RunStatus.AWAITING_REVIEW)

    def _step_resolve(self, run_id: str, techniques: list[NormalizedTechnique]) -> list[dict]:
        """RESOLVE step: map techniques to Caldera abilities or Atomic tests."""
        self.store.update_status(run_id, RunStatus.RESOLVING)
        self.store.start_step(run_id, "RESOLVE")

        caldera = CalderaClient(
            base_url=self.settings.caldera_url,
            api_key=self.settings.caldera_api_key.get_secret_value(),
        )
        atomic = AtomicRunner(
            host=self.settings.winrm_host,
            user=self.settings.winrm_user,
            password=self.settings.winrm_password.get_secret_value(),
            port=self.settings.winrm_port,
            transport=self.settings.winrm_transport,
        )

        resolver = Resolver(caldera=caldera, atomic=atomic)
        plan = resolver.resolve(techniques, run_id)

        # Write execution plan
        plan_data = plan.model_dump()
        self.store.write_artifact(run_id, "execution_plan.yaml", plan_data)
        self.store.complete_step(run_id, "RESOLVE", artifact_path="execution_plan.yaml")

        logger.info(
            "Resolved: %d caldera, %d atomic, %d skipped",
            plan.caldera_count, plan.atomic_count, plan.skip_count,
        )

        return plan_data["techniques"]

    def _step_execute(self, run_id: str, resolved_techniques: list[dict]) -> list[EmulationRecord]:
        """EXECUTE step: run Caldera operations and Atomic tests."""
        self.store.update_status(run_id, RunStatus.EXECUTING)
        self.store.start_step(run_id, "EXECUTE")

        from purpleforge.models.emulation import ResolvedTechnique

        techniques = [ResolvedTechnique.model_validate(t) for t in resolved_techniques]
        caldera_techs = [t for t in techniques if t.method == EmulationMethod.CALDERA]
        atomic_techs = [t for t in techniques if t.method == EmulationMethod.ATOMIC]

        all_records: list[EmulationRecord] = []

        # Execute Caldera batch
        if caldera_techs:
            caldera = CalderaClient(
                base_url=self.settings.caldera_url,
                api_key=self.settings.caldera_api_key.get_secret_value(),
            )
            executor = CalderaExecutor(
                client=caldera,
                run_id=run_id,
                timeout=self.settings.caldera_operation_timeout,
                poll_interval=self.settings.caldera_poll_interval,
            )
            all_records.extend(executor.execute(caldera_techs))

        # Execute Atomic tests sequentially
        if atomic_techs:
            runner = AtomicRunner(
                host=self.settings.winrm_host,
                user=self.settings.winrm_user,
                password=self.settings.winrm_password.get_secret_value(),
                port=self.settings.winrm_port,
                transport=self.settings.winrm_transport,
            )
            executor_atomic = AtomicExecutor(runner)
            all_records.extend(executor_atomic.execute(atomic_techs))

        # Write results
        results_data = [r.model_dump() for r in all_records]
        self.store.write_artifact(run_id, "emulation_results.yaml", {"records": results_data})
        self.store.complete_step(run_id, "EXECUTE", artifact_path="emulation_results.yaml")

        logger.info("Executed %d techniques", len(all_records))
        return all_records

    def _step_wait(self, run_id: str) -> None:
        """WAIT step: sleep for detection propagation delay."""
        self.store.update_status(run_id, RunStatus.WAITING)
        self.store.start_step(run_id, "WAIT")

        wait_seconds = self.settings.detection_wait_seconds
        logger.info("Waiting %ds for detection propagation...", wait_seconds)
        time.sleep(wait_seconds)

        self.store.complete_step(run_id, "WAIT")


class PipelineError(Exception):
    """Raised when the pipeline encounters a recoverable error."""
