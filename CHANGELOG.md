# Changelog

All notable changes to PurpleForge are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Enterprise readiness assessment and hardening roadmap under `docs/`.
- Continuous integration: lint, format, type check, and tests on Python 3.11 to 3.13, plus a wheel build and install smoke test. Dependabot and pre-commit configured.
- End-to-end integration test that drives `confirm` through resolve, execute, validate, and report with mocked integrations.
- Caldera client methods for agents, link results, and adversary cleanup; a configurable agent group (`CALDERA_GROUP`).

### Fixed

- Pipeline artifacts now round-trip through YAML. Enum fields were written with Python object tags that `safe_load` refused, so every run failed at validate. Artifacts are written in JSON-compatible mode and state files use atomic replace.
- LimaCharlie client authenticates by exchanging the organization ID and API key for a short-lived JWT, and queries the historic detections endpoint with an explicit time window instead of fetching recent detections and filtering client side.
- Timestamps in seconds, milliseconds, or ISO form are parsed consistently; millisecond epochs no longer crash the validator.
- Retry policy now retries only transport errors, HTTP 429, and 5xx, and fails fast on authentication and other client errors.
- Detection tags in `attack.tXXXX` and `ATT&CK` forms are normalized, and a sub-technique alert can match an emulated parent technique.
- The HTML report template is packaged inside the wheel, so reports render from an installed package, not only an editable checkout.
- Caldera evidence uses each link's own start and finish times and fetches decoded command output; a reused operation is no longer stamped with the current time.
- AI-generated Sigma drafts are validated (structure and required fields) and their confidence is restricted to high, medium, or low before a draft is saved.

### Changed

- The project version is single-sourced from the package and no longer duplicated in packaging metadata or the report footer.

## [0.1.0] - 2026-10-21

Initial release: ingest, review gate, resolve, execute, validate, report, advise.
