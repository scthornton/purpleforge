# PurpleForge

Evidence-driven purple team pipeline. Turn a threat report into a defensible detection coverage report.

Given a threat report PDF, PurpleForge extracts MITRE ATT&CK techniques, pauses for human review, emulates the approved techniques with Caldera and Atomic Red Team, validates detections against LimaCharlie, and produces a coverage report where every claim is backed by a proof chain.

<p align="center">
  <img src="assets/demo-screenshot.png" alt="PurpleForge coverage output" width="800">
</p>

PurpleForge began as a SANS SEC598 project and is being built into a tool an enterprise can run and trust.

## Why it exists

Purple teaming connects red team emulation to blue team detection. The hard part is proving a coverage claim: "we detect T1059.001" means nothing without evidence. PurpleForge answers each claim with a complete evidence chain, the emulation step that ran, when it ran, the time window searched, and the specific alert IDs that matched.

The workflow is fixed, so the pipeline is a state machine, not an agent loop. A language model is used only where judgment helps, reading a report and drafting rules. Mapping a technique to an emulation is a lookup, and execution follows a set order. See [docs/architecture.md](docs/architecture.md) for the reasoning.

## What it does today

- Completes end to end: ingest, review gate, resolve, execute, wait, validate, report, advise.
- Backs every coverage claim with an `EvidenceChain` (emulation step, timestamps, query window, matching alerts, confidence).
- Keeps untrustworthy signals out of the numbers: time-correlated alerts are shown as context but never counted, and emulations that did not run are inconclusive, not missed.
- Emulates with Caldera abilities first and Atomic Red Team as a fallback, and validates against LimaCharlie.
- Produces a JSON report, a self-contained HTML report, and an ATT&CK Navigator layer.
- Drafts Sigma rules for missed techniques as advisories that are never auto-deployed.
- Runs on a lean dependency set, about 40 runtime packages, with no vector database.

Runs are crash-safe file state on disk. Per-step resume is planned, not yet implemented.

## Architecture

```
purpleforge run --source report.pdf
  |
  |- INGEST     PDF -> chunk -> OpenAI structured extraction of TTPs (map-reduce over the report)
  |- REVIEW     Human gate: operator reviews and edits extracted_ttps.yaml
  |
purpleforge confirm --run-id <id>
  |
  |- RESOLVE    Technique -> Caldera ability? -> Atomic fallback? -> skip
  |- EXECUTE    Caldera operation plus Atomic Red Team via WinRM
  |- WAIT       Detection propagation delay (default 120s)
  |- VALIDATE   Query LimaCharlie, build one evidence chain per technique
  |- REPORT     JSON, HTML, and ATT&CK Navigator layer
  |- ADVISE     Sigma rule drafts for missed techniques (optional)
```

Full detail in [docs/architecture.md](docs/architecture.md). Trust boundaries and controls are in [docs/threat-model.md](docs/threat-model.md). Setup and permissions per integration are in [docs/operations.md](docs/operations.md).

## Repository layout

```
src/purpleforge/
  cli.py                    Click CLI: run, confirm, status, report, deploy-draft, list, install-atomic
  config.py                 Pydantic settings, every env var, secrets as SecretStr
  models/                   Pydantic data models (extraction, emulation, evidence, advisory, pipeline)
  ingest/                   PDF loading, chunking, OpenAI structured TTP extraction
  resolve/                  Caldera-first, Atomic-fallback technique resolution
  execute/                  Caldera operation executor, Atomic WinRM executor
  validate/                 LimaCharlie detection querying, evidence chain builder
  report/                   Coverage analyzer, ATT&CK Navigator heatmap, HTML report, advisory generator
  clients/                  REST and WinRM clients (Caldera, LimaCharlie, Atomic, GitHub)
  pipeline/                 State machine orchestrator, file-based run store
  templates/                Self-contained HTML report template (packaged in the wheel)

tests/
  unit/                     Unit tests with mocked external services
  integration/              End-to-end confirm pipeline with mocked integrations
  fixtures/                 Sample PDF, pre-extracted TTPs, mock API responses

docs/                       Assessment, roadmap, architecture, threat model, operations guide
```

## Quick start

1. Install:

```bash
pip install -e .
cp .env.example .env
# Edit .env with your endpoints and keys. See docs/operations.md for every variable.
```

2. Ingest a threat report and extract techniques:

```bash
purpleforge run --source ~/reports/apt29_report.pdf
```

3. Review the extracted techniques. Open `data/runs/<run-id>/extracted_ttps.yaml` and edit, remove, or add techniques. Each one carries a confidence and a source excerpt so you can see why it was proposed.

4. (Once per target) install Atomic Red Team on the WinRM host, an explicit operator action:

```bash
purpleforge install-atomic
```

5. Confirm and run the rest of the pipeline:

```bash
purpleforge confirm --run-id <id>
```

6. View results:

```bash
purpleforge status --run-id <id>
# Reports at: data/runs/<id>/coverage_report.html
#             data/runs/<id>/navigator_layer.json
```

7. Deploy an advisory draft (optional):

```bash
purpleforge deploy-draft --run-id <id> --technique T1027 --target stdout
purpleforge deploy-draft --run-id <id> --technique T1027 --target github
```

## Requirements

- Python 3.11 or newer
- A [Caldera](https://caldera.mitre.org/) server with an agent in the configured group (adversary emulation)
- A [LimaCharlie](https://limacharlie.io/) organization (detection backend)
- A Windows host with WinRM enabled (Atomic Red Team target)
- An OpenAI-compatible API endpoint (TTP extraction and advisory drafting)
- A GitHub token (optional, only for `deploy-draft --target github`)

## CLI commands

| Command | Description |
|---------|-------------|
| `purpleforge run` | Ingest a threat report PDF, extract TTPs, pause for human review |
| `purpleforge confirm` | Confirm TTPs and run resolve, execute, validate, report, advise |
| `purpleforge status` | Show the current pipeline state and step history |
| `purpleforge list` | List all pipeline runs |
| `purpleforge report` | Regenerate reports from existing evidence (`--format json|html|navigator|all`) |
| `purpleforge deploy-draft` | Deploy an advisory Sigma rule draft (`--target stdout` or `github`) |
| `purpleforge install-atomic` | Install Atomic Red Team on the configured WinRM target (explicit, pinned) |

## Evidence model

The core record is the `EvidenceChain`, one per emulated technique:

| Field | Description |
|-------|-------------|
| `technique_id` | ATT&CK technique (for example T1059.001) |
| `emulation_step_id` | Caldera link ID or Atomic execution ID |
| `execution_timestamp` | When the emulation started |
| `detection_query_window_start` / `_end` | Time range searched for detections |
| `matching_alerts` | Alerts that matched the technique by tag |
| `unattributed_alerts` | Alerts in the window that did not match any emulated technique, kept as context |
| `best_match_type` | `exact_technique`, `child_technique`, `parent_technique`, `time_correlation`, or `none` |
| `confidence` | `high`, `medium`, `low`, or `none` |
| `status` | `detected`, `partial`, `missed`, or `inconclusive` |

Coverage is reported two ways. Skipped techniques were never emulated and inconclusive techniques were emulated but did not run, so neither is in the denominator:

- Lenient: (detected + partial) / (total - skipped - inconclusive)
- Strict: detected / (total - skipped - inconclusive)

## Design principles

The product is the evidence-rich coverage report, not the breadth of integrations. One detection backend proven end to end is worth more than three untested ones.

A human gate sits before execution. Extracted techniques are written to YAML for review before anything runs, so an extraction error never becomes an emulation.

Every claim has a proof chain. A report that says "detected" without an alert ID, a timestamp, and a matching rule is not trustworthy, and PurpleForge does not produce one.

Advisory rules are drafts, never auto-deployed. Generated Sigma rules carry confidence, explanation, and limitation notes, and the `auto_deployed` field is typed `Literal[False]` so it cannot be set true.

State is crash-safe file state. Run state is written to YAML with atomic replace. Resuming a failed run from the last completed step is planned.

## Development

```bash
make install     # pip install -e ".[dev,github]"
make all         # lint, format check, type check, test
make test        # pytest with coverage
make lint        # ruff check
```

Continuous integration runs ruff, ruff format, mypy, and the test suite on Python 3.11 through 3.13, builds the wheel, and smoke-tests the install.

## Contributing

1. Create a feature branch from `main`.
2. Implement the change with tests.
3. Run `make all` to verify lint, format, type check, and tests.
4. Open a PR with a clear description.

## Important notes

- This tool is for authorized lab environments only. It executes adversary techniques on target systems you own or are authorized to test.
- All credentials use `SecretStr` and do not appear in logs or CLI output.
- Caldera operations are idempotent: an operation is named for the run ID and reused if it already exists.
- Raw emulation output is truncated to 5,000 characters in records.
- Extraction uses an OpenAI-compatible structured-output API, and invalid technique IDs are rejected at the Pydantic validation layer.

## Project documents

- [Enterprise readiness assessment](docs/assessment-2026-10-22.md)
- [Hardening roadmap](docs/ROADMAP.md)
- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Operations guide](docs/operations.md)
- [Changelog](CHANGELOG.md)

---

## Contact

**Scott Thornton**, AI Security Researcher

- Website: [perfecxion.ai](https://perfecxion.ai/)
- Email: [scott@perfecxion.ai](mailto:scott@perfecxion.ai)
- LinkedIn: [linkedin.com/in/scthornton](https://www.linkedin.com/in/scthornton)
- ORCID: [0009-0008-0491-0032](https://orcid.org/0009-0008-0491-0032)
- GitHub: [@scthornton](https://github.com/scthornton)

**Security issues**: please report via [SECURITY.md](SECURITY.md)
