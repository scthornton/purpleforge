# PurpleForge Hardening Roadmap

Living tracker for the enterprise hardening plan in [assessment-2026-10-22.md](assessment-2026-10-22.md).
Finding numbers (F1 to F26) refer to that document. Each item links to the PR that closed it.

Design rule for every phase: a CLI plus files, one detection backend proven end to end, no web UI,
no database, no plugin framework, no agent framework.

## Phase 0: make it run

| Item | Finding | Status | PR |
|---|---|---|---|
| CI with lint, format, type check, tests; version single-sourced | F24 (part) | done | #12 |
| Run artifacts round-trip through YAML; integration test for `confirm` | F1 | done | #15 |
| Atomic file writes use `Path.replace` | F7 | done | #15 |
| LimaCharlie JWT exchange and historic detections endpoint | F2 | done | #17 |
| Tolerant timestamp parsing (seconds, milliseconds, ISO) | F5 | done | #17 |
| Retry only transport errors, 429, and 5xx | F6 | done | #17, #18 |
| Tag normalization for `attack.tXXXX` style tags | F12 | done | #17 |
| HTML template packaged in the wheel | F3 | done | #16 |
| Advisory confidence as `Literal`; Sigma YAML validated | F14 | done | #16 |
| Configurable Caldera agent group; fail when no agents match | F8 | done | #18 |
| Real Caldera timestamps and link output | F4 | done | #18 |

Exit criterion: a full `run` and `confirm` completes against the lab from a wheel install.

Phase 0 code is merged. The pipeline now round-trips its artifacts and completes end to end
against mocked integrations (integration test in `tests/integration/test_confirm_pipeline.py`).
The remaining exit step, a live lab run from a wheel install, needs a Caldera server, a
LimaCharlie organization, and a Windows WinRM target, so it stays open until that run is done.
The LimaCharlie endpoint and auth flow were built from the vendor SDK source, not verified
against a live tenant. Still open from Phase 0 scope: platform-aware Caldera ability selection
(noted under F8).

## Phase 1: trustworthy evidence, lean core

| Item | Finding | Status | PR |
|---|---|---|---|
| Time correlation removed from coverage math | F9 | done | #21 |
| `INCONCLUSIVE` status for failed emulations | F10 | done | #21 |
| Raw detections snapshot persisted; operation report deferred | F21 | partial | #21 |
| Review YAML carries confidence and source excerpt | F11 | done | #22 |
| Drop langchain, chromadb, mitreattack-python; OpenAI SDK direct | F18 | done | #22 |
| Atomic hygiene: read-only RESOLVE, pinned installer, timeouts, cleanup, https | F13 | done | #20 |
| Test depth for executors, renderer, generator, CLI | F23 | partial | #20, #21, #22 |

Exit criterion: every coverage number can be defended from the run directory; under 50 runtime packages.

Phase 1 code is merged. Coverage math now excludes time-correlated and inconclusive results, so
every number traces to a tag match in the run directory, and the raw detections for the query
window are saved as `detections_snapshot.json`. Runtime packages dropped from 136 to 40 and the
five chromadb advisories no longer apply (pip-audit clean). Still open from Phase 1 scope: the
Caldera operation report is not yet persisted (the validate step does not receive the operation
object), and test depth for the CLI plus a higher coverage gate are folded into Phase 2.

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
| Test depth for the CLI; raise coverage gate toward 85% | F23 (rest) | open | |
| Persist the Caldera operation report | F21 (rest) | open | |
| Platform-aware Caldera ability selection | F8 (rest) | open | |
| README rewrite, threat model, operations guide | F25 | open | |
| Remove `demo` command | F26 | open | |

## Progress log

| Date | PR | Summary |
|---|---|---|
| 2026-10-22 | #11 | Assessment, roadmap, and changelog added. |
| 2026-10-22 | #12 | CI (lint, format, mypy, tests on 3.11 to 3.13, wheel smoke test); version single-sourced; Dependabot and pre-commit. |
| 2026-10-22 | #15 | YAML artifacts round-trip with `model_dump(mode="json")`; `Path.replace` for atomic writes; end-to-end integration test. |
| 2026-10-22 | #17 | LimaCharlie JWT auth, insight detections query, tolerant timestamps, correct retry policy, tag normalization. |
| 2026-10-22 | #18 | Caldera retry policy, configurable agent group with fail-fast, real link timestamps and output, adversary cleanup. |
| 2026-10-22 | #16 | Report template packaged in the wheel; Sigma draft validation and typed confidence. |
| 2026-10-22 | #13, #14 | Dependabot bumped the GitHub Actions `checkout` and `setup-uv` versions. |
| 2026-10-22 | #20 | Atomic runner hardened: pinned opt-in installer, read-only resolve, per-test timeout, cleanup after each test, TLS transport. |
| 2026-10-22 | #21 | Time correlation and failed emulations no longer inflate coverage; inconclusive status added; raw detections snapshot persisted. |
| 2026-10-22 | #22 | LangChain and ChromaDB replaced with the OpenAI SDK (136 to 40 runtime packages); extraction confidence and source excerpt reach the review gate. |
