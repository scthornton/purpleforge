"""Pipeline orchestrator: state machine coordinating all pipeline steps."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import yaml

from purpleforge.clients.atomic_runner import AtomicRunner
from purpleforge.clients.caldera_client import CalderaClient
from purpleforge.clients.limacharlie_client import LimaCharlieClient
from purpleforge.config import PurpleForgeSettings
from purpleforge.execute.atomic_executor import AtomicExecutor
from purpleforge.execute.caldera_executor import CalderaExecutor
from purpleforge.ingest.pdf_loader import chunk_documents, load_pdf
from purpleforge.ingest.ttp_extractor import TTPExtractor
from purpleforge.models.emulation import EmulationMethod, EmulationRecord
from purpleforge.models.extraction import NormalizedTechnique
from purpleforge.models.pipeline import RunStatus
from purpleforge.pipeline.run_store import RunStore
from purpleforge.report.advisory_generator import AdvisoryGenerator
from purpleforge.report.coverage_analyzer import CoverageAnalyzer
from purpleforge.report.heatmap_generator import HeatmapGenerator
from purpleforge.report.html_renderer import HtmlRenderer
from purpleforge.resolve.resolver import Resolver
from purpleforge.validate.detection_validator import DetectionValidator

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """State machine: INGEST → REVIEW → RESOLVE → EXECUTE → WAIT → VALIDATE → REPORT → ADVISE."""

    def __init__(self, settings: PurpleForgeSettings, skip_advise: bool = False) -> None:
        self.settings = settings
        self.store = RunStore(settings.run_base_dir)
        self.skip_advise = skip_advise

    def start_run(self, source_path: str) -> str:
        """Start a new pipeline run: create run, execute INGEST, pause at AWAITING_REVIEW.

        Returns the run_id.
        """
        self.settings.require_openai()
        run = self.store.create_run(
            source_path=source_path,
            config_snapshot={
                "openai_model": self.settings.openai_model,
                "detection_wait_seconds": self.settings.detection_wait_seconds,
                "caldera_operation_timeout": self.settings.caldera_operation_timeout,
                "skip_advise": self.skip_advise,
            },
        )
        run_id = run.run_id

        try:
            self._step_ingest(run_id, source_path)
        except Exception as e:
            self.store.fail_step(run_id, "INGEST", str(e))
            raise

        return run_id

    def start_run_from_ttps(self, ttps_path: str) -> str:
        """Create a run from an operator-provided technique list, skipping LLM extraction.

        The YAML must be a mapping with a non-empty 'techniques' list, each item
        carrying at least technique_id, technique_name, tactic, and description.
        Extra keys (confidence, source_chunk, page, operator_notes) are preserved
        for the review gate. Returns the run_id; the run pauses at AWAITING_REVIEW.
        """
        path = Path(ttps_path)
        if not path.exists():
            raise PipelineError(f"TTPs file not found: {path}")

        data = yaml.safe_load(path.read_text())
        techniques = data.get("techniques") if isinstance(data, dict) else None
        if not isinstance(techniques, list) or not techniques:
            raise PipelineError("TTPs file must be a mapping with a non-empty 'techniques' list")

        # Validate each entry has the required fields and a valid technique id.
        for item in techniques:
            NormalizedTechnique.model_validate(item)

        run = self.store.create_run(
            source_path=str(path),
            config_snapshot={
                "source": "provided_ttps",
                "detection_wait_seconds": self.settings.detection_wait_seconds,
                "caldera_operation_timeout": self.settings.caldera_operation_timeout,
                "skip_advise": self.skip_advise,
            },
        )
        run_id = run.run_id

        self.store.update_status(run_id, RunStatus.INGESTING)
        self.store.start_step(run_id, "INGEST")

        techniques_out = []
        for item in techniques:
            entry = dict(item)
            entry.setdefault("operator_notes", "")
            techniques_out.append(entry)

        run_dir = Path(self.settings.run_base_dir) / run_id
        ttps_file = run_dir / "extracted_ttps.yaml"
        header = (
            f"# PurpleForge Extracted TTPs\n"
            f"# Run ID: {run_id}\n"
            f"# Source: {path} (operator-provided technique list)\n"
            f"#\n"
            f"# REVIEW INSTRUCTIONS:\n"
            f"# - Edit, add, or remove techniques as needed\n"
            f"# - Ensure technique_ids match T####.### format\n"
            f"# - When ready: purpleforge confirm --run-id {run_id}\n\n"
        )
        yaml_content = yaml.dump({"techniques": techniques_out}, default_flow_style=False, sort_keys=False)
        ttps_file.write_text(header + yaml_content)

        self.store.complete_step(run_id, "INGEST", artifact_path="extracted_ttps.yaml")
        self.store.update_status(run_id, RunStatus.AWAITING_REVIEW)
        return run_id

    def confirm_run(self, run_id: str, ttps_file: str | None = None) -> None:
        """Confirm extracted TTPs and proceed through remaining pipeline steps.

        Loads TTPs from file (operator may have edited), then runs:
        RESOLVE → EXECUTE → WAIT → VALIDATE → REPORT → ADVISE
        """
        self.settings.require_caldera()
        self.settings.require_limacharlie()
        self.settings.require_winrm()
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
            {"techniques": [t.model_dump(mode="json") for t in techniques]},
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

        # VALIDATE → REPORT
        try:
            self._step_validate(run_id)
        except Exception as e:
            self.store.fail_step(run_id, "VALIDATE", str(e))
            raise

        try:
            self._step_report(run_id)
        except Exception as e:
            self.store.fail_step(run_id, "REPORT", str(e))
            raise

        # ADVISE (optional, check both instance flag and persisted config)
        skip = self.skip_advise or run.config_snapshot.get("skip_advise", False)
        if not skip:
            try:
                self._step_advise(run_id)
            except Exception as e:
                # Advisory failures are non-fatal
                logger.warning("Advisory generation failed: %s", e)

        self.store.update_status(run_id, RunStatus.COMPLETE)

    def _step_ingest(self, run_id: str, source_path: str) -> None:
        """INGEST step: load the PDF, chunk it, and extract TTPs for operator review."""
        self.store.update_status(run_id, RunStatus.INGESTING)
        self.store.start_step(run_id, "INGEST")

        # Load and chunk the PDF
        pages = load_pdf(source_path)
        chunks = chunk_documents(pages)
        logger.info("Loaded %d pages, %d chunks from %s", len(pages), len(chunks), source_path)

        # LLM extraction over the whole report (map-reduce, no vector store)
        extractor = TTPExtractor(
            api_key=self.settings.openai_key(),
            model=self.settings.openai_model,
            base_url=self.settings.openai_base_url,
        )
        ttps = extractor.extract(chunks)
        logger.info("Extracted %d techniques", len(ttps))

        # Write extracted TTPs as operator-reviewable YAML, with the signals a
        # reviewer needs: the model's confidence and a source excerpt.
        ttps_data = {
            "techniques": [
                {
                    "technique_id": t.technique_id,
                    "technique_name": t.technique_name,
                    "tactic": t.tactic,
                    "description": t.description,
                    "confidence": t.confidence.value,
                    "source_chunk": t.source_chunk,
                    "page": t.page,
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

    def _step_resolve(self, run_id: str, techniques: list[NormalizedTechnique]) -> list[dict[str, Any]]:
        """RESOLVE step: map techniques to Caldera abilities or Atomic tests."""
        self.store.update_status(run_id, RunStatus.RESOLVING)
        self.store.start_step(run_id, "RESOLVE")

        caldera = CalderaClient(
            base_url=self.settings.caldera_url,
            api_key=self.settings.caldera_key(),
        )
        atomic = AtomicRunner(
            host=self.settings.winrm_host_value(),
            user=self.settings.winrm_user,
            password=self.settings.winrm_pass(),
            port=self.settings.winrm_port,
            transport=self.settings.winrm_transport,
            use_https=self.settings.winrm_use_https,
            server_cert_validation=self.settings.winrm_cert_validation,
            ca_trust_path=self.settings.winrm_ca_trust_path,
            installer_ref=self.settings.atomic_installer_ref,
        )

        resolver = Resolver(caldera=caldera, atomic=atomic)
        plan = resolver.resolve(techniques, run_id)

        # Write execution plan
        plan_data = plan.model_dump(mode="json")
        self.store.write_artifact(run_id, "execution_plan.yaml", plan_data)
        self.store.complete_step(run_id, "RESOLVE", artifact_path="execution_plan.yaml")

        logger.info(
            "Resolved: %d caldera, %d atomic, %d skipped",
            plan.caldera_count,
            plan.atomic_count,
            plan.skip_count,
        )

        return list(plan_data["techniques"])

    def _step_execute(self, run_id: str, resolved_techniques: list[dict[str, Any]]) -> list[EmulationRecord]:
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
                api_key=self.settings.caldera_key(),
            )
            executor = CalderaExecutor(
                client=caldera,
                run_id=run_id,
                timeout=self.settings.caldera_operation_timeout,
                poll_interval=self.settings.caldera_poll_interval,
                group=self.settings.caldera_group,
            )
            all_records.extend(executor.execute(caldera_techs))

        # Execute Atomic tests sequentially
        if atomic_techs:
            runner = AtomicRunner(
                host=self.settings.winrm_host_value(),
                user=self.settings.winrm_user,
                password=self.settings.winrm_pass(),
                port=self.settings.winrm_port,
                transport=self.settings.winrm_transport,
                use_https=self.settings.winrm_use_https,
                server_cert_validation=self.settings.winrm_cert_validation,
                ca_trust_path=self.settings.winrm_ca_trust_path,
                installer_ref=self.settings.atomic_installer_ref,
            )
            executor_atomic = AtomicExecutor(runner, test_timeout=self.settings.atomic_test_timeout)
            all_records.extend(executor_atomic.execute(atomic_techs))

        # Write results
        results_data = [r.model_dump(mode="json") for r in all_records]
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

    def _step_validate(self, run_id: str) -> None:
        """VALIDATE step: query LimaCharlie detections and build evidence chains."""
        self.store.update_status(run_id, RunStatus.VALIDATING)
        self.store.start_step(run_id, "VALIDATE")

        # Load emulation results
        results_data = self.store.read_artifact(run_id, "emulation_results.yaml")
        records = [EmulationRecord.model_validate(r) for r in results_data.get("records", [])]

        # Build technique metadata lookup from confirmed TTPs
        technique_metadata: dict[str, dict[str, str]] = {}
        try:
            ttps_data = self.store.read_artifact(run_id, "confirmed_ttps.yaml")
            for t in ttps_data.get("techniques", []):
                technique_metadata[t["technique_id"]] = {
                    "name": t.get("technique_name", ""),
                    "tactic": t.get("tactic", ""),
                }
        except FileNotFoundError:
            logger.warning("confirmed_ttps.yaml not found; evidence chains will lack metadata")

        # Query LimaCharlie
        lc = LimaCharlieClient(
            api_key=self.settings.lc_key(),
            org_id=self.settings.lc_org(),
        )
        validator = DetectionValidator(
            client=lc,
            query_buffer=self.settings.detection_query_buffer,
        )
        chains = validator.validate(
            records,
            detection_wait=self.settings.detection_wait_seconds,
            technique_metadata=technique_metadata,
        )

        # Persist the raw detections fetched for the window so a "missed" claim can
        # be re-audited offline later without tenant access.
        self.store.write_artifact(run_id, "detections_snapshot.json", validator.fetched_detections)

        # Write evidence chains
        chains_data = [json.loads(c.model_dump_json()) for c in chains]
        self.store.write_artifact(run_id, "evidence_chains.json", chains_data)
        self.store.complete_step(run_id, "VALIDATE", artifact_path="evidence_chains.json")

        logger.info("Validated %d techniques", len(chains))

    def _step_report(self, run_id: str) -> None:
        """REPORT step: generate coverage report, HTML, and Navigator JSON."""
        import json as json_mod

        self.store.update_status(run_id, RunStatus.REPORTING)
        self.store.start_step(run_id, "REPORT")

        # Load evidence chains
        from purpleforge.models.evidence import EvidenceChain

        chains_data = self.store.read_artifact(run_id, "evidence_chains.json")
        chains = [EvidenceChain.model_validate(c) for c in chains_data]

        # Load execution plan to find skipped techniques
        plan_data = self.store.read_artifact(run_id, "execution_plan.yaml")
        skipped = [t["technique_id"] for t in plan_data.get("techniques", []) if t.get("method") == "skip"]

        # Coverage analysis
        analyzer = CoverageAnalyzer()
        result = analyzer.analyze(chains, run_id, skipped_techniques=skipped)

        # Write coverage report JSON
        self.store.write_artifact(
            run_id,
            "coverage_report.json",
            json_mod.loads(result.model_dump_json()),
        )

        # Generate HTML report
        renderer = HtmlRenderer()
        html = renderer.render(result)
        run_dir = Path(self.settings.run_base_dir) / run_id
        (run_dir / "coverage_report.html").write_text(html)

        # Generate Navigator layer
        heatmap = HeatmapGenerator()
        layer = heatmap.generate(result)
        self.store.write_artifact(run_id, "navigator_layer.json", layer)

        self.store.complete_step(run_id, "REPORT", artifact_path="coverage_report.json")
        logger.info(
            "Report: coverage=%.1f%% (D:%d P:%d M:%d I:%d S:%d)",
            result.coverage_pct,
            result.detected_count,
            result.partial_count,
            result.missed_count,
            result.inconclusive_count,
            result.skipped_count,
        )

    def _step_advise(self, run_id: str) -> None:
        """ADVISE step: generate Sigma rule drafts for missed techniques."""
        self.store.update_status(run_id, RunStatus.ADVISING)
        self.store.start_step(run_id, "ADVISE")

        # Load evidence chains to find missed techniques
        chains_data = self.store.read_artifact(run_id, "evidence_chains.json")
        missed = [c for c in chains_data if c.get("status") == "missed"]

        if not missed:
            logger.info("No missed techniques, skipping advisory generation")
            self.store.complete_step(run_id, "ADVISE")
            return

        # Report context for each technique, so the prompt knows what was observed
        descriptions: dict[str, str] = {}
        try:
            ttps_data = self.store.read_artifact(run_id, "confirmed_ttps.yaml")
            for t in ttps_data.get("techniques", []):
                descriptions[t["technique_id"]] = t.get("description", "")
        except FileNotFoundError:
            logger.warning("confirmed_ttps.yaml not found; advisory prompts will lack report context")

        generator = AdvisoryGenerator(
            api_key=self.settings.openai_key(),
            model=self.settings.openai_model,
            base_url=self.settings.openai_base_url,
        )

        missed_input = [
            {
                "technique_id": m["technique_id"],
                "technique_name": m.get("technique_name", ""),
                "tactic": m.get("tactic", ""),
                "description": descriptions.get(m["technique_id"], ""),
            }
            for m in missed
        ]

        rules = generator.generate_batch(missed_input)

        # Write drafts
        run_dir = Path(self.settings.run_base_dir) / run_id / "drafts"
        run_dir.mkdir(parents=True, exist_ok=True)

        for rule in rules:
            # Write Sigma YAML
            (run_dir / f"{rule.technique_id}_sigma_draft.yaml").write_text(rule.rule_yaml)
            # Write advisory metadata
            self.store.write_artifact(
                run_id,
                f"drafts/{rule.technique_id}_advisory.json",
                json.loads(rule.model_dump_json()),
            )

        self.store.complete_step(run_id, "ADVISE", artifact_path="drafts/")
        logger.info("Generated %d advisory drafts for missed techniques", len(rules))


class PipelineError(Exception):
    """Raised when the pipeline encounters a recoverable error."""
