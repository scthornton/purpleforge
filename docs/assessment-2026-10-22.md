# PurpleForge Enterprise Readiness Assessment

Date: 2026-10-22
Scope: `main` at 066df3a (v0.1.0), every source, test, template, and config file.
Method: read the full codebase; ran the test suite with coverage, ruff, and mypy; built the wheel and installed it into a clean environment; audited the resolved dependency tree; ran targeted probe scripts against suspected defects using mocked integrations. No external service was contacted and no code in the repository was changed.

## 1. Verdict

PurpleForge has the right shape for an enterprise purple-team tool: a fixed state machine instead of an agent loop, a human gate before anything executes, evidence chains as the core data structure, crash-safe file-based state, and advisory-only Sigma drafts. The Pydantic models are clean and well tested, and the design principles in the README are the right ones.

It is not usable today. The `confirm` pipeline cannot complete: two artifacts are written as YAML with Python object tags and cannot be read back, so every run fails at VALIDATE. The LimaCharlie client cannot authenticate as written. The HTML report cannot render from a normal (non-editable) install. Around those are weaker but important problems in the evidence semantics (time correlation inflates coverage with other techniques' alerts) and a dependency tree roughly ten times heavier than the tool needs, carrying five known CVEs in a package the tool barely uses.

The fixes are small and local. The architecture does not need to change. The work splits into three phases: make it run, make the evidence trustworthy and cut the bloat, make it operable in an enterprise.

## 2. What was measured

| Check | Result |
|---|---|
| Unit tests | 116 passed in 14.9 s |
| Line coverage | 59% overall. `cli.py` 0%, `caldera_executor.py` 19%, `atomic_executor.py` 43%, `github_client.py` 0%, `orchestrator.py` 50% |
| ruff check | clean |
| ruff format | 14 of 48 files would be reformatted (formatting is not enforced) |
| mypy strict | 1 error when the `github` extra is installed (unused `type: ignore` in `github_client.py`), so `make all` fails in a full dev environment |
| Wheel contents | 38 files, no `templates/` directory |
| Runtime dependencies | 136 packages, 554 MB of site-packages (Python 3.12, dev and github extras excluded) |
| Lean equivalent | 39 packages, 51 MB (openai, pypdf, httpx, pydantic, pydantic-settings, pywinrm, click, rich, jinja2, pyyaml, tenacity) |
| pip-audit | 5 known vulnerabilities, all in chromadb 1.5.9 (PYSEC-2026-311, PYSEC-2026-3813, PYSEC-2026-3814, PYSEC-2026-3815) |
| Import time | `purpleforge.cli` 0.08 s, `purpleforge.pipeline.orchestrator` 1.34 s |
| Working tree | clean, no CI workflow, no lockfile |

Note: `.env.example` could not be read in this session (blocked by local permission settings). Configuration findings are based on `src/purpleforge/config.py`.

## 3. Findings

Severity scale: P0 blocks real use or makes evidence wrong. P1 materially weakens trust or security. P2 is operability, quality, and documentation.

### P0: blocks real use or corrupts evidence

**F1. The pipeline cannot pass VALIDATE: YAML artifacts contain Python object tags.**
`_step_resolve` and `_step_execute` write `plan.model_dump()` and `r.model_dump()` through `RunStore.write_artifact`, which calls `yaml.dump`. StrEnum fields serialize as `!!python/object/apply:purpleforge.models.emulation.EmulationMethod`. `read_artifact` uses `yaml.safe_load`, which refuses those tags. `_step_validate` reads `emulation_results.yaml` and fails on every run. `_step_report` and the `report` command fail on `execution_plan.yaml` the same way.
Reproduced end to end with mocked clients: RESOLVE, EXECUTE, and WAIT complete, VALIDATE fails with `ConstructorError`, run state becomes `failed`. No existing test catches this because `test_confirm_with_valid_ttps` mocks every step.
Fix: `model_dump(mode="json")` at `pipeline/orchestrator.py:231` and `:282` (and anywhere else a model is written to YAML), a round-trip test on `RunStore`, and an integration test of `confirm_run` with mocked clients.

**F2. The LimaCharlie client cannot authenticate.**
`clients/limacharlie_client.py:39` sends the raw API key as `Authorization: Bearer`. LimaCharlie requires exchanging the organization ID and API key for a one-hour JWT at `https://jwt.limacharlie.io` and sending that JWT. The detections call at `:62` (`GET /v1/detects?oid=...&limit=...`) also does not match the SDK's documented historic-detections flow (`getHistoricDetections(start, end, limit, cat)`, Insight-backed, server-side time window, timestamps in seconds). Even with a working token, fetching "the most recent 1000" and filtering client-side will miss the window on a busy tenant and report false misses.
Fix: implement the JWT exchange with caching and refresh, call the historic detections endpoint with `start` and `end`, page through results, and verify against a live organization before anything else in Phase 1 is built on it.

**F3. The HTML report cannot render from an installed wheel.**
`report/html_renderer.py:11` computes `TEMPLATE_DIR` as four parents up from the module, which only lands on the repository root in an editable install. The wheel does not include `templates/`. Reproduced: installed the built wheel into a clean environment, `HtmlRenderer()` raised `TemplateNotFound`.
Fix: move the template to `src/purpleforge/templates/`, load it with `jinja2.PackageLoader("purpleforge", "templates")`, and add a test that renders with the default loader. Also drop the hard-coded `v0.1.0` in the template footer and pass `__version__` in.

**F4. Caldera evidence timestamps are wrong in the reuse path, and command output is never captured.**
When an operation named `purpleforge-<run>` already exists and is finished, `execute/caldera_executor.py:41` calls `_extract_results` without `start_time`, so `execution_timestamp` and `execution_end_timestamp` become "now". The detection query window is then built around the wrong time, which guarantees a miss or a spurious time-correlation match. Caldera returns `start` on the operation and `decide`/`finish` on each link; use them for every path, not just reuse. `raw_output` at `:121` reads `link["output"]`, which in the v2 API is a flag rather than the command output. Output must be fetched from the link result endpoint and base64-decoded (confirm the exact path against your server's `/api/docs`).
Reproduced: a finished operation from 2026-10-01 produced a record stamped 2026-10-22 with empty `raw_output`.

**F5. Millisecond timestamps crash the validator.**
`validate/detection_validator.py:122`, `:146`, `:232` and `clients/limacharlie_client.py:106` call `datetime.fromtimestamp(ts)`. A millisecond epoch such as `1711900000000` raises `ValueError: year 56217 is out of range`. The fixtures use seconds, so the tests pass.
Fix: treat `ts > 1e11` as milliseconds, assume UTC for naive ISO strings, and add a fixture in milliseconds.

**F6. The retry policy is inverted.**
Both clients retry on `httpx.HTTPStatusError`, which includes 401, 403, and 404, and do not retry on transport errors or timeouts (`ConnectError` is converted and re-raised, `ReadTimeout` propagates on the first attempt). Reproduced: a 401 from Caldera is attempted 3 times, from LimaCharlie 5 times (about 15 s of backoff on a bad key); a `ReadTimeout` is attempted once.
Fix at `clients/caldera_client.py:37-40` and `clients/limacharlie_client.py:45-48`: retry on `httpx.TransportError`, 429, and 5xx; fail fast on other 4xx with a clear message.

**F7. Atomic writes break on Windows.**
`pipeline/run_store.py:111` and `:149` use `Path.rename`, which raises `FileExistsError` on Windows when the target exists. The second state write fails on a Windows operator workstation. Use `Path.replace`.

**F8. The Caldera agent group is hard-coded to `purple_team`.**
`clients/caldera_client.py:84`. Agents deployed with Caldera's default group are excluded, the operation has no agents, finishes immediately with an empty chain, and every technique is recorded FAILED with "No matching link in operation chain". Make the group a setting and fail before creating the operation when zero trusted agents match. Related: `resolve/resolver.py:53` takes the first ability for a technique without filtering by platform or executor, so a Linux-only ability can be selected for a Windows agent; and a new adversary object is created per run and never cleaned up.

### P1: evidence semantics and security

**F9. Time correlation inflates coverage with other techniques' alerts.**
`validate/detection_validator.py:141`: if a technique has no tag match but any detection exists in its window, it becomes PARTIAL and the first three alerts in the window are recorded as its evidence. All Caldera techniques in one operation share the same window. In the end-to-end probe, one detection tagged `t1059.001` makes T1053.005 and T1003.001 PARTIAL, each citing the T1059.001 alert ID. That is exactly the untrustworthy claim the README says the tool prevents.
Recommendation: time correlation must not count toward coverage. Keep it as `unattributed_activity` context on the chain, restricted to detections that did not match any emulated technique, from the same sensor or host, inside a per-technique window derived from link timestamps.

**F10. Failed emulations are reported as detection gaps.**
`validate/detection_validator.py:186`: FAILED, TIMEOUT, and ERROR emulations become MISSED. That is conservative, but it conflates "the control did not fire" with "we never tested the control", and `pipeline/orchestrator.py:399` then spends LLM calls writing Sigma rules for techniques that were never executed.
Recommendation: add `INCONCLUSIVE` as a distinct status. Exclude it from the detected numerator, report it separately, and never send it to ADVISE.

**F11. The human gate is missing the signals a reviewer needs.**
`pipeline/orchestrator.py:177-184` writes `extracted_ttps.yaml` without the LLM `confidence`, and `source_chunk` is never set by the extractor, so the `run` table's Confidence column (`cli.py:77`) is always empty and the operator cannot see why a technique was extracted. The PDF is untrusted input whose processing ends in adversary execution; this gate is the main prompt-injection control. Give it confidence, page numbers, and the supporting excerpt.

**F12. Tag matching misses common tag formats.**
Only a bare `t1059.001` matches. Sigma and ATT&CK style tags (`attack.t1059.001`) and detections tagged with the parent (`attack.t1059`) do not. `TECHNIQUE_TAG_PATTERN` at `clients/limacharlie_client.py:16` is defined and never used. Normalize tags with the regex, also consider the detection category/name, and treat a sub-technique tag as a child match when the emulated technique is the parent.

**F13. Atomic Red Team runner: supply chain, hygiene, and transport.**
`resolve/resolver.py:38` calls `ensure_atomic_installed` during RESOLVE, a planning step, and `clients/atomic_runner.py:62` will run `Set-ExecutionPolicy Unrestricted -Force` and `IEX (IWR ...master/install-atomicredteam.ps1)` on the target: unpinned remote code execution as a side effect of planning. `:83` runs every test for the technique with no `-TimeoutSeconds` and no `-TestNumbers`, and `-Cleanup` is never run, so persistence artifacts (run keys, scheduled tasks) remain on the host after the run. `:36` forces `http://` regardless of port, and a `basic` transport would send credentials in clear text.
Fix: installation becomes an explicit opt-in command pinned to a release tag with a hash check; RESOLVE is read-only; execute specific test numbers with a timeout; run cleanup after VALIDATE; support `https` and certificate validation; record the Atomic execution-log GUID as `emulation_step_id` instead of the synthetic `atomic-<id>`.

**F14. Advisory generation fails on non-canonical confidence.**
`report/advisory_generator.py:32` types `confidence` as a free string; `RuleConfidence("High")` raises and the draft is silently dropped by `generate_batch`. Use `Literal["high", "medium", "low"]` so structured output enforces it. Also validate that the generated YAML parses and has `title`, `logsource`, `detection`, and `condition` before saving, and pass the technique description from the confirmed TTPs into the prompt (today it is never supplied).

**F15. No validation of identifiers used in paths.**
`cli.py:277` and the other commands join `run_id` and `technique` into paths without validation; `deploy-draft --run-id ../../../../etc --technique passwd` is accepted and attempted. Low impact for a local CLI and trivial to fix with `^[0-9a-f]{12}$` and the technique regex.

**F16. Configuration coupling and silent fallback.**
Every command constructs the full settings object. `run` (ingest only) refuses to start without WinRM, Caldera, and LimaCharlie credentials. `list`, `status`, `report`, and `deploy-draft` swallow the validation error and silently fall back to `./data/runs` (`cli.py:150`, `:202`, `:273`, `:341`). Reproduced: with `RUN_BASE_DIR` set but one unrelated variable missing, `list` reports "No runs found" while a run exists in the configured directory; `list` also creates `./data/runs` in the current directory as a side effect.
Fix: split settings into a small base (paths, logging) and per-integration groups validated when a step needs them; never fall back silently; use a `PURPLEFORGE_` prefix so `OPENAI_API_KEY` and `LC_API_KEY` do not collide with other tools.

**F17. GitHub deployment assumptions.**
Base branch `main` is hard-coded, `create_file` fails if the path already exists (re-runs), branch creation fails if the branch exists, and there is no `base_url` for GitHub Enterprise Server.

### P2: operability, quality, and documentation

**F18. Dependency bloat that also hurts extraction quality.**
chromadb brings 137 transitive packages (onnxruntime, kubernetes, grpc, opentelemetry, uvicorn, tokenizers) and the four langchain packages add more, all to serve two structured-output LLM calls and one similarity search over roughly 50 chunks. `mitreattack-python` (47 transitive packages including pandas) is not imported anywhere. `python-dotenv` is only needed transitively. The RAG step also reduces extraction recall: it keeps the top 10 chunks for one generic query and discards the rest of the report, when a typical report fits in a single context window. Persisting those embeddings under `./data/chroma` forever is also a data-retention liability for internal incident reports.
Recommendation: drop langchain, chromadb, and mitreattack-python. Call the OpenAI SDK directly with structured outputs and `base_url` support, replace the splitter with a small recursive splitter, extract over all chunks in batches and dedupe (map-reduce), and fall back to embedding retrieval only for very large documents. Result: 136 packages and 554 MB become about 39 packages and 51 MB, no vector store on disk, and the five chromadb CVEs disappear.

**F19. No resumability, despite the README claim.**
`confirm_run` only accepts `awaiting_review`. A failure in RESOLVE, EXECUTE, VALIDATE, or REPORT leaves the run `failed` with no retry path; Ctrl-C during WAIT leaves it `waiting`. Two concurrent `confirm` invocations on one run are not prevented.
Recommendation: per-step commands (`resolve`, `execute`, `validate`, `report`, `advise`) gated by the state machine, `confirm` as "run all remaining steps", `resume --run-id` from the last completed step, and a lock file per run.

**F20. No logging or audit trail.**
Loggers are used throughout but never configured, so nothing is emitted. Add `--verbose` and `--quiet`, JSON logs, a `run.log` inside the run directory, and record tool version, operator, host, and config snapshot in `run_state.yaml`. Add `schema_version` to every JSON artifact and a SHA-256 manifest so the evidence set is tamper-evident.

**F21. Evidence is not reproducible offline.**
Only matched alerts are kept. Persist the raw detections snapshot for the query window, the ability or test identity and command for each technique, and the Caldera operation report. A "missed" claim should be re-auditable later without tenant access.

**F22. The LLM is mandatory for the core pipeline.**
Extraction and advisory are the only LLM uses; resolve, execute, validate, and report need none. Add `run --ttps file.yaml` (bring your own technique list, no OpenAI), make advisory opt-in, and support `OPENAI_BASE_URL` so calls can go through an enterprise gateway or Azure. This also unblocks air-gapped and regulated environments.

**F23. Test depth.**
116 tests, but 0% of the CLI, 19% of the Caldera executor, and no tests for the Atomic executor, HTML renderer, advisory generator, GitHub client, or any orchestrator step after INGEST. `test_invalid_ids_dropped` builds an invalid record and never passes it to the extractor, so it asserts nothing about invalid IDs. The end-to-end probe used for F1 should become `tests/integration/test_confirm_pipeline.py`.

**F24. Build and CI hygiene.**
No CI workflow, no lockfile, no Dependabot, no pre-commit, `ruff format` not enforced, ruff `target-version` is py312 while `requires-python` is 3.11, mypy fails with the `github` extra installed, and `pyproject.toml` lacks license, readme, classifiers, and URLs. The version string lives in three places (`__init__.py`, `pyproject.toml`, the HTML template footer).

**F25. Documentation accuracy and framing.**
The README claims resumability (false), that raw emulation output is captured and truncated (never captured for Caldera), and frames the project as a SANS SEC598 artifact. For enterprise positioning it needs an architecture and threat-model page (untrusted PDF, LLM output treated as data not instructions, human gate, drafts-only rules), an operations guide listing the permissions required in Caldera, LimaCharlie, WinRM, and GitHub, and a corrected feature list.

**F26. The `demo` command.**
150 lines of hard-coded fake results compiled into the product CLI. Move the screenshot to docs and remove the command; fabricated output in a security tool invites misuse in screenshots and reports.

Dead code to delete: `CalderaClient.find_abilities_by_technique` (the resolver builds its own index), `LimaCharlieClient.get_detection_rules`, the `ThreatReport` model, and `TECHNIQUE_TAG_PATTERN` unless F12 puts it to use.

## 4. Proposed plan

Design rule for every phase: a CLI plus files, one detection backend proven end to end, no web UI, no database, no plugin framework, no agent framework. Enterprise readiness here means correctness, evidence integrity, auditability, secure defaults, and operability, not surface area.

### Phase 0: make it run

- F1: `model_dump(mode="json")`, RunStore round-trip test, integration test of `confirm_run`.
- F2: LimaCharlie JWT exchange and historic detections endpoint, verified against a live organization.
- F3: package the template with `PackageLoader`.
- F5 tolerant timestamp parsing, F6 retry policy, F7 `Path.replace`, F14 `Literal` confidence.
- F8: configurable Caldera group with an explicit "no agents matched" failure.

Exit criterion: a full `run` and `confirm` completes against the lab (Caldera with one Windows agent, plus LimaCharlie) and produces all three reports from a wheel install, not an editable checkout.

### Phase 1: trustworthy evidence, lean core

- F9 time correlation out of the coverage math, F10 `INCONCLUSIVE` status, F4 real Caldera timestamps and link output, F12 tag normalization.
- F11 confidence, source excerpt, and page in the review YAML; the `run` table shows them.
- F21 persist raw detections snapshot, ability or test identity, operation report; F20 `schema_version` and manifest.
- F18 remove langchain, chromadb, mitreattack-python; OpenAI SDK direct with `base_url`; map-reduce extraction over all chunks.
- F13 Atomic hygiene: read-only RESOLVE, opt-in pinned installer, test numbers, timeout, cleanup, https.
- F23 tests for every executor, renderer, generator, and the CLI; coverage gate at 85%.

Exit criterion: every number in the coverage report can be defended line by line from the artifacts in the run directory, and `pip install purpleforge` pulls under 50 packages.

### Phase 2: enterprise operability

- F16 settings split plus `purpleforge doctor` (connectivity and permission checks for each integration).
- F19 per-step commands, `resume`, lock file. F22 `--ttps` input and optional LLM.
- F20 logging and audit fields. F15 identifier validation. F17 GitHub Enterprise, base branch, update-or-create.
- `--min-coverage` threshold with non-zero exit for scheduled regression runs; `list --json` and `status --json` for automation.
- F24 CI (ruff, ruff format, mypy, pytest on 3.11 through 3.13, pip-audit, wheel install smoke test), `uv.lock`, Dependabot, pre-commit, release tagging, SBOM.
- F25 docs: architecture, threat model, operations guide, changelog. F26 remove `demo`.

### Deliberately out of scope

Multiple detection backends, a web dashboard, a scheduler or daemon, multi-tenant state, Linux and macOS atomics, and an LLM agent layer. Each is reasonable later; none is needed for an enterprise to trust and run this tool, and each adds the kind of weight this plan removes.

## 5. Reproduction notes

Probe scripts used for this assessment live in the session scratchpad and are not committed:

- `probe.py`: sections A and B (F1, including the end-to-end failure), D (F4), E (F5), F (F6), G (F12), H (F14).
- `cli_probe.py`: F15 and F16.

Quick checks: `uv build` then `unzip -l dist/*.whl | grep j2` (F3); `uv pip tree --invert --package onnxruntime` (F18); `pip-audit -r <freeze file> --no-deps --disable-pip` (F18).

## Sources

- LimaCharlie API keys and JWT exchange: https://docs.limacharlie.io/docs/api-keys and https://docs.limacharlie.io/apidocs/introduction
- LimaCharlie Python SDK `getHistoricDetections`: https://python-limacharlie.readthedocs.io/en/develop/limacharlie.html
- Caldera REST API v2 documentation is served by the running server under `/api/docs`: https://caldera.readthedocs.io/en/latest/The-REST-API.html
- Python `pathlib.Path.rename` Windows behavior: https://docs.python.org/3/library/pathlib.html#pathlib.Path.rename
