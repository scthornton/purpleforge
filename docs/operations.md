# Operations guide

How to set up each integration, which environment variables PurpleForge reads, and how to drive a run. PurpleForge is a CLI over files, meant for an authorized lab.

## Integrations and permissions

**Caldera.** You need a reachable Caldera server and an API key. At least one agent must be checked in to the group PurpleForge uses (`CALDERA_GROUP`, default `red`). Resolution and execution fail fast with a clear message if no trusted agent is in that group, rather than running an empty operation. The key needs permission to list abilities and agents, create adversaries and operations, read operation links and their results, and delete the one-off adversary a run creates.

**LimaCharlie.** You need the organization ID and an API key. PurpleForge exchanges the org ID and key for a short-lived token and then queries historic detections for the run's time window. The key needs permission to read detections for the organization.

**WinRM target (Atomic Red Team).** You need a Windows host with WinRM enabled and an account that can run PowerShell and the Atomic tests. The default transport is `ntlm` on port 5985. For TLS, set the HTTPS port (5986) or `WINRM_USE_HTTPS`, and keep certificate validation on with a CA trust path for anything beyond an isolated local lab. Install the framework once with `purpleforge install-atomic`; it is never installed automatically.

**Model endpoint.** You need an OpenAI-compatible API key, and optionally a base URL to route through a gateway or a self-hosted endpoint. Only ingest and advise call the model.

**GitHub (optional).** Only needed for `deploy-draft --target github`. You need a token and a target repository. For GitHub Enterprise Server, set the API base URL (`GITHUB_BASE_URL`). The draft is opened as a pull request against the repository's default branch for human review.

## Environment variables

PurpleForge reads configuration from the environment and from a local `.env` file. Required variables have no default.

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENAI_API_KEY` | required | Key for the model endpoint |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model used for extraction and advisories |
| `OPENAI_BASE_URL` | unset | Override the model endpoint (gateway or self-hosted) |
| `CALDERA_URL` | `http://localhost:8888` | Caldera server URL |
| `CALDERA_API_KEY` | required | Caldera API key |
| `CALDERA_GROUP` | `red` | Agent group the operation targets |
| `LC_API_KEY` | required | LimaCharlie API key |
| `LC_ORG_ID` | required | LimaCharlie organization ID |
| `WINRM_HOST` | required | Windows Atomic target host |
| `WINRM_USER` | `Administrator` | WinRM user |
| `WINRM_PASSWORD` | required | WinRM password |
| `WINRM_TRANSPORT` | `ntlm` | WinRM transport |
| `WINRM_PORT` | `5985` | WinRM port (5986 selects TLS) |
| `WINRM_USE_HTTPS` | `false` | Force TLS regardless of port |
| `WINRM_CERT_VALIDATION` | `validate` | Certificate validation mode for TLS |
| `WINRM_CA_TRUST_PATH` | unset | CA bundle path for TLS |
| `ATOMIC_INSTALLER_REF` | `v2.3.0` | Pinned Atomic Red Team installer release |
| `ATOMIC_TEST_TIMEOUT` | `120` | Per-test timeout in seconds |
| `ATOMIC_FALLBACK` | `true` | Retry a failed Caldera technique via Atomic Red Team and keep whichever ran |
| `GITHUB_TOKEN` | unset | Token for deploy-draft to GitHub |
| `DETECTION_REPO` | unset | Target repository for drafts |
| `GITHUB_BASE_URL` | unset | API base URL for GitHub Enterprise Server |
| `DETECTION_WAIT_SECONDS` | `120` | Wait for detection propagation |
| `CALDERA_OPERATION_TIMEOUT` | `300` | Caldera operation timeout |
| `CALDERA_MAX_OPERATION_TIMEOUT` | `1800` | Ceiling for the beacon-aware auto-raise of the operation timeout |
| `CALDERA_POLL_INTERVAL` | `5` | Caldera poll interval |
| `DETECTION_QUERY_BUFFER` | `60` | Seconds of buffer around the query window |
| `RUN_BASE_DIR` | `./data/runs` | Where run state and artifacts are written |

## Running a pipeline

1. Ingest and extract. `purpleforge run --source report.pdf` loads the PDF, extracts techniques, writes `extracted_ttps.yaml`, and stops for review. Options: `--detection-wait`, `--caldera-timeout`, `--skip-advise`.

2. Review. Open `data/runs/<run-id>/extracted_ttps.yaml` and edit the technique list. Each entry shows a confidence and a source excerpt so you can judge why it was proposed. Remove anything you do not want emulated.

3. Install Atomic (once per target). `purpleforge install-atomic` installs the pinned framework on the WinRM host. This is an explicit action and runs nothing from the report.

4. Confirm and run. `purpleforge confirm --run-id <id>` runs resolve, execute, wait, validate, report, and advise. Use `--ttps-file` to point at an edited file elsewhere. A confirm only proceeds for a run that is awaiting review.

5. Check status. `purpleforge status --run-id <id>` shows the run status and step history. `purpleforge list` shows all runs.

6. Reports. The confirm step writes the reports. `purpleforge report --run-id <id> --format all` regenerates them from the stored evidence (`json`, `html`, `navigator`, or `all`), which is useful after a code change without re-emulating.

7. Advisory drafts. `purpleforge deploy-draft --run-id <id> --technique T1027 --target stdout` prints a draft; `--target github` opens a pull request against the detection repository for review.

## Artifacts

Everything a run produces is under `data/runs/<run_id>/`: `run_state.yaml`, the technique YAML files, `execution_plan.yaml`, `emulation_results.yaml`, `detections_snapshot.json`, `evidence_chains.json`, `coverage_report.json`, `coverage_report.html`, `navigator_layer.json`, and a `drafts/` directory. The detections snapshot and the evidence chains together let a coverage number be re-audited offline.
