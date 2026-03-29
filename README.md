# PurpleForge

Evidence-driven purple team pipeline for SANS SEC598.

Given a threat report, PurpleForge extracts ATT&CK techniques, executes adversary emulations (Caldera + Atomic Red Team), validates detections (LimaCharlie), and produces a trustworthy coverage report with per-technique evidence chains.

## Quick Start

```bash
# Install
pip install -e ".[dev]"
cp .env.example .env
# Edit .env with your API keys

# Run pipeline
purpleforge run --source report.pdf
# Review extracted TTPs, then:
purpleforge confirm --run-id <id>
```

## Architecture

```
PDF → Extract TTPs → Human Review → Resolve → Execute → Wait → Validate → Report
```

Every "detected" or "missed" claim is backed by a complete evidence chain:
emulation step IDs, timestamps, telemetry query windows, matching alert IDs, and confidence levels.

## Requirements

- Python 3.11+
- Caldera server
- LimaCharlie org
- Windows host with WinRM (for Atomic Red Team)
- OpenAI API key

## Development

```bash
pip install -e ".[dev]"
make all  # lint + typecheck + test
```
