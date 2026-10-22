# Architecture

PurpleForge is a fixed-order state machine with a human gate in the middle. It reads a threat report, proposes techniques, waits for a person to approve them, emulates the approved set, checks what the sensors caught, and writes a report where every number traces back to evidence on disk.

## Why a state machine, not an agent loop

The workflow does not change from run to run: extract, review, resolve, execute, wait, validate, report, advise. The order is the same every time, and each step has one job. A fixed state machine makes the run reproducible and auditable, which is the whole point of a coverage report. A language model is used in exactly two places where reading and drafting help: extracting techniques from a report, and drafting candidate Sigma rules. Everything between those, mapping a technique to an emulation and deciding whether a detection fired, is deterministic code, not a judgment call handed to a model.

## The pipeline

```
run --source report.pdf
  INGEST        Load the PDF, split into chunks, extract techniques with
                an OpenAI-compatible structured-output call over the whole
                report (map-reduce across batches, deduped by confidence).
  REVIEW        Writes extracted_ttps.yaml and stops at awaiting_review.
                A person edits the file before anything executes.

confirm --run-id <id>
  RESOLVE       Map each technique to a Caldera ability, else an Atomic
                test, else skip. This step is read-only: it never installs
                software or runs a test.
  EXECUTE       Run one Caldera operation for the Caldera techniques and
                the Atomic tests over WinRM, cleaning up after each test.
  WAIT          Pause for detections to propagate (default 120 seconds).
  VALIDATE      Query LimaCharlie for the window, match detections to
                techniques by tag, and build one evidence chain each.
  REPORT        Aggregate into a coverage report: JSON, HTML, and an
                ATT&CK Navigator layer.
  ADVISE        For missed techniques, draft Sigma rules (optional).
```

The run statuses map to these steps: `created`, `ingesting`, `awaiting_review`, `resolving`, `executing`, `waiting`, `validating`, `reporting`, `advising`, `complete`, and `failed`. A run pauses at `awaiting_review` after ingest and only advances when an operator runs `confirm`.

## The evidence chain

The `EvidenceChain` is the core record, one per emulated technique. It ties an emulation to the detections that did or did not fire:

- `technique_id`, `technique_name`, `tactic`: what was tested.
- `emulation_step_id`, `emulation_method`: the Caldera link or Atomic execution that ran it.
- `execution_timestamp`, `execution_end_timestamp`: when it ran, taken from the emulator's own timestamps.
- `detection_query_window_start` and `_end`: the time range searched in the sensor backend.
- `matching_alerts`: alerts that matched the technique by tag, each with an alert ID, timestamp, rule name, matched tag, and match type.
- `unattributed_alerts`: alerts inside the window that did not match any emulated technique, kept as context and never counted as coverage.
- `best_match_type`: `exact_technique`, `child_technique`, `parent_technique`, `time_correlation`, or `none`.
- `confidence` and `status`: the classification derived from the match.

Coverage status is one of `detected`, `partial`, `missed`, or `inconclusive`. An emulation that failed, timed out, or errored is `inconclusive`: it tells us nothing about the control, so it is excluded from the coverage numerator and denominator rather than counted as a miss. Time correlation never sets status; a technique seen only through nearby unrelated alerts is `missed`, with those alerts attached as context.

## The run store

Run state and every artifact live under `data/runs/<run_id>/`. The store writes with an atomic replace (write a temp file, then replace), so a crash cannot leave a half-written file. A run directory holds:

```
data/runs/<run_id>/
  run_state.yaml           Status, step history, config snapshot, errors
  extracted_ttps.yaml      Techniques from INGEST, for human review
  confirmed_ttps.yaml      Techniques as approved at confirm time
  execution_plan.yaml      Each technique resolved to Caldera, Atomic, or skip
  emulation_results.yaml   Per-technique emulation records
  detections_snapshot.json Raw detections fetched for the query window
  evidence_chains.json     One evidence chain per technique
  coverage_report.json     Aggregated coverage result
  coverage_report.html     Self-contained HTML report
  navigator_layer.json     ATT&CK Navigator layer
  drafts/                  Sigma rule drafts and advisory metadata
```

Because the raw detections snapshot and the per-technique chains are both on disk, a coverage number can be re-audited later without going back to the sensor backend.
