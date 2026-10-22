# PurpleForge Hardening Roadmap

Living tracker for the enterprise hardening plan in [assessment-2026-10-22.md](assessment-2026-10-22.md).
Finding numbers (F1 to F26) refer to that document. Each item links to the PR that closed it.

Design rule for every phase: a CLI plus files, one detection backend proven end to end, no web UI,
no database, no plugin framework, no agent framework.

## Phase 0: make it run

| Item | Finding | Status | PR |
|---|---|---|---|
| CI with lint, format, type check, tests; version single-sourced | F24 (part) | open | |
| Run artifacts round-trip through YAML; integration test for `confirm` | F1 | open | |
| Atomic file writes use `Path.replace` | F7 | open | |
| LimaCharlie JWT exchange and historic detections endpoint | F2 | open | |
| Tolerant timestamp parsing (seconds, milliseconds, ISO) | F5 | open | |
| Retry only transport errors, 429, and 5xx | F6 | open | |
| Tag normalization for `attack.tXXXX` style tags | F12 | open | |
| HTML template packaged in the wheel | F3 | open | |
| Advisory confidence as `Literal`; Sigma YAML validated | F14 | open | |
| Configurable Caldera agent group; fail when no agents match | F8 | open | |
| Real Caldera timestamps and link output | F4 | open | |

Exit criterion: a full `run` and `confirm` completes against the lab from a wheel install.

## Phase 1: trustworthy evidence, lean core

| Item | Finding | Status | PR |
|---|---|---|---|
| Time correlation removed from coverage math | F9 | open | |
| `INCONCLUSIVE` status for failed emulations | F10 | open | |
| Raw detections snapshot and operation report persisted | F21 | open | |
| Review YAML carries confidence and source excerpt | F11 | open | |
| Drop langchain, chromadb, mitreattack-python; OpenAI SDK direct | F18 | open | |
| Atomic hygiene: read-only RESOLVE, pinned installer, timeouts, cleanup, https | F13 | open | |
| Test depth for executors, renderer, generator, CLI | F23 | open | |

Exit criterion: every coverage number can be defended from the run directory; under 50 runtime packages.

## Phase 2: enterprise operability

| Item | Finding | Status | PR |
|---|---|---|---|
| Settings split, no silent fallback, `purpleforge doctor` | F16 | open | |
| Identifier validation in CLI | F15 | open | |
| Logging, audit fields, `schema_version`, manifest | F20 | open | |
| Per-step resume and lock file | F19 | open | |
| `run --ttps` input; LLM optional | F22 | open | |
| GitHub Enterprise, base branch, update-or-create | F17 | open | |
| `--min-coverage` gate and `--json` outputs | new | open | |
| Lockfile, pip-audit in CI, Dependabot, pre-commit | F24 (rest) | open | |
| README rewrite, threat model, operations guide | F25 | open | |
| Remove `demo` command | F26 | open | |

## Progress log

| Date | PR | Summary |
|---|---|---|
