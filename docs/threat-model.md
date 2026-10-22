# Threat model

PurpleForge reads an untrusted document, calls a language model, and then runs adversary techniques against hosts. This page states the trust boundaries, the controls on each, and the residual risks an operator should keep in mind. It is a lightweight model, not a formal assurance argument.

## Assets

- The target lab hosts and the sensor organization they report to.
- The credentials for Caldera, LimaCharlie, WinRM, the model endpoint, and optionally GitHub.
- The evidence and coverage reports, which may reference internal incident detail.

## Trust boundaries and controls

**The input report is untrusted.** A threat report PDF comes from outside and may contain text crafted to steer extraction. It is treated as data to analyze, never as instructions. The extraction prompt asks only for ATT&CK techniques, output is constrained to a typed schema, and invalid technique IDs are dropped at the Pydantic layer. The main control is the human review gate below.

**Model output is data, not commands.** The techniques the model returns are written to `extracted_ttps.yaml` and go no further on their own. Nothing the model emits is executed, shell-interpolated, or used to choose a target. It is a list of ATT&CK IDs that a person reviews.

**The human gate is the primary control before execution.** After ingest the run stops at `awaiting_review`. An operator reads the proposed techniques, each shown with a confidence and a source excerpt, and edits the file before running `confirm`. An extraction error or an injected technique has to pass a human before any emulation runs.

**Emulation is authorized lab use only.** PurpleForge executes adversary techniques. It is meant for hosts you own or are explicitly authorized to test. Resolution is read-only and never installs software or runs a test; execution happens only after `confirm`.

**The Atomic installer is pinned and opt-in.** Installing the Atomic Red Team framework reaches an upstream installer and runs it on the target. That happens only when an operator runs `install-atomic`, never as a side effect of planning or a normal run. The installer is pinned to a release ref rather than a moving branch, and the PowerShell execution policy change is scoped to the current process. Pin to a release you have vetted.

**Advisory rules are drafts, never deployed automatically.** Generated Sigma rules are stored as advisories with confidence and limitation notes. The `auto_deployed` field is typed `Literal[False]` and cannot be set true. Pushing a draft to a detection repository is a separate, explicit `deploy-draft` action that opens a pull request for human review.

**Secrets stay out of output.** All credentials are `SecretStr`, so they do not render in logs or CLI output. They are read from the environment or a local `.env` file. Keep that file out of version control.

**Transport.** WinRM can use TLS on the HTTPS port with certificate validation and a CA trust path. Plain HTTP with an unauthenticated transport would send credentials in the clear, so prefer HTTPS for any host that is not an isolated local lab.

## Residual risks

- A report can still influence which techniques are proposed. The human gate is the mitigation, so review the list, not just the count, before confirming.
- Emulation changes the state of the target host. Atomic tests run cleanup after each test, but cleanup is best effort; treat targets as disposable lab machines.
- A coverage number is only as good as the sensor coverage and the detection window. The raw detections snapshot is saved so a number can be re-audited, but a missed detection outside the window will read as a gap.
- Credentials are only as safe as the host running PurpleForge and its `.env` file.

## Out of scope

Multi-tenant isolation, a hosted service, and any automatic deployment of detections are deliberately not part of this tool.
