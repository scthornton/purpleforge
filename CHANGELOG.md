# Changelog

All notable changes to PurpleForge are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Enterprise readiness assessment and hardening roadmap under `docs/`.
- Continuous integration: lint, format, type check, and tests on Python 3.11 to 3.13, plus a wheel build and install smoke test. Dependabot and pre-commit configured.
- End-to-end integration test that drives `confirm` through resolve, execute, validate, and report with mocked integrations.
- Caldera client methods for agents, link results, and adversary cleanup; a configurable agent group (`CALDERA_GROUP`).
- `purpleforge install-atomic`, an explicit operator command that installs the Atomic Red Team framework from a pinned release, so installation is never a side effect of planning.
- An `inconclusive` coverage status for emulations that did not run, reported and counted separately from detection gaps.
- A raw detections snapshot (`detections_snapshot.json`) saved per run so coverage claims can be re-audited offline.
- Support for a custom OpenAI base URL (`OPENAI_BASE_URL`) so extraction and advisory calls can go through an enterprise gateway.

### Removed

- LangChain and ChromaDB, replaced by a direct OpenAI SDK call with structured output. Runtime dependencies drop from about 136 packages to 40, and the five chromadb advisories no longer apply. The unused `mitreattack-python` dependency is gone.
- The on-disk vector store. Extraction now reads the whole report in batches (map-reduce) instead of a similarity search over a subset.

### Fixed

- Pipeline artifacts now round-trip through YAML. Enum fields were written with Python object tags that `safe_load` refused, so every run failed at validate. Artifacts are written in JSON-compatible mode and state files use atomic replace.
- LimaCharlie client authenticates by exchanging the organization ID and API key for a short-lived JWT, and queries the historic detections endpoint with an explicit time window instead of fetching recent detections and filtering client side.
- Timestamps in seconds, milliseconds, or ISO form are parsed consistently; millisecond epochs no longer crash the validator.
- Retry policy now retries only transport errors, HTTP 429, and 5xx, and fails fast on authentication and other client errors.
- Detection tags in `attack.tXXXX` and `ATT&CK` forms are normalized, and a sub-technique alert can match an emulated parent technique.
- The HTML report template is packaged inside the wheel, so reports render from an installed package, not only an editable checkout.
- Caldera evidence uses each link's own start and finish times and fetches decoded command output; a reused operation is no longer stamped with the current time.
- AI-generated Sigma drafts are validated (structure and required fields) and their confidence is restricted to high, medium, or low before a draft is saved.
- Time correlation no longer counts toward coverage. A technique detected only by nearby, unrelated alerts is reported as missed, with those alerts attached as unattributed context rather than credited to the technique.
- Failed, timed-out, and errored emulations are no longer reported as detection gaps; they are inconclusive and excluded from the coverage numerator and denominator.
- The Atomic runner uses a per-test timeout, runs cleanup after each test to remove persistence artifacts, pins the installer to a release instead of the upstream default branch, scopes the PowerShell execution policy change to the current process, and uses TLS on the WinRM HTTPS port.
- Technique resolution is read-only and never installs software or runs a test.
- The review gate now shows each extracted technique's confidence and a source excerpt, so an operator can see why a technique was proposed before approving execution.

### Changed

- The project version is single-sourced from the package and no longer duplicated in packaging metadata or the report footer.

## [0.1.0] - 2026-10-21

Initial release: ingest, review gate, resolve, execute, validate, report, advise.
