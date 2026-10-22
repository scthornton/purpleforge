"""Tests for run audit fields, the evidence manifest, and logging setup."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from purpleforge import __version__
from purpleforge.logging_config import PACKAGE_LOGGER, setup_logging
from purpleforge.pipeline.run_store import RunStore


class TestAuditFields:
    def test_create_run_records_audit_fields(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        assert run.schema_version == "1"
        assert run.tool_version == __version__
        assert run.host  # hostname is non-empty on a normal machine
        assert isinstance(run.operator, str)  # may be empty in a userless container

    def test_audit_fields_persist(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        loaded = run_store.load_run(run.run_id)
        assert loaded.tool_version == run.tool_version
        assert loaded.host == run.host


class TestManifest:
    def test_manifest_hashes_and_excludes(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        run_store.write_artifact(run.run_id, "coverage_report.json", {"coverage_pct": 50.0})
        run_dir = Path(run_store.base_dir) / run.run_id
        run_store.acquire_lock(run.run_id)
        (run_dir / "run.log").write_text("log line\n")
        (run_dir / "stale.tmp").write_text("partial")

        manifest = json.loads(run_store.write_manifest(run.run_id).read_text())
        by_name = {f["name"]: f for f in manifest["files"]}

        assert "run_state.yaml" in by_name
        assert "coverage_report.json" in by_name
        assert ".lock" not in by_name
        assert "run.log" not in by_name
        assert "stale.tmp" not in by_name
        assert "manifest.json" not in by_name

        expected = hashlib.sha256((run_dir / "coverage_report.json").read_bytes()).hexdigest()
        assert by_name["coverage_report.json"]["sha256"] == expected
        assert by_name["coverage_report.json"]["size"] > 0
        assert manifest["tool_version"] == __version__
        assert manifest["schema_version"] == "1"

    def test_manifest_is_sorted(self, run_store: RunStore) -> None:
        run = run_store.create_run("/tmp/test.pdf")
        for name in ("c.json", "a.json", "b.json"):
            run_store.write_artifact(run.run_id, name, {"x": 1})
        manifest = json.loads(run_store.write_manifest(run.run_id).read_text())
        names = [f["name"] for f in manifest["files"]]
        assert names == sorted(names)


class TestLoggingSetup:
    def test_levels(self) -> None:
        logger = logging.getLogger(PACKAGE_LOGGER)
        setup_logging(verbose=True)
        assert logger.level == logging.DEBUG
        setup_logging(quiet=True)
        assert logger.level == logging.WARNING
        setup_logging()
        assert logger.level == logging.INFO

    def test_quiet_wins_over_verbose(self) -> None:
        setup_logging(verbose=True, quiet=True)
        assert logging.getLogger(PACKAGE_LOGGER).level == logging.WARNING

    def test_does_not_stack_console_handlers(self) -> None:
        logger = logging.getLogger(PACKAGE_LOGGER)
        # Reset shared global logging state so this test does not depend on order.
        logger.handlers.clear()
        setup_logging()
        setup_logging()
        setup_logging()
        stream_handlers = [
            h
            for h in logger.handlers
            if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        ]
        assert len(stream_handlers) == 1
