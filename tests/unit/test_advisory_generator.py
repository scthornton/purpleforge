"""Tests for the advisory Sigma draft generator."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from purpleforge.models.advisory import RuleConfidence
from purpleforge.report.advisory_generator import (
    AdvisoryGenerator,
    AdvisoryValidationError,
    SigmaRuleDraft,
    validate_sigma_yaml,
)

VALID_RULE = """\
title: Suspicious PowerShell Encoded Command
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: '-enc'
  condition: selection
falsepositives:
  - Administrative scripts
level: medium
tags:
  - attack.execution
  - attack.t1059.001
"""

NO_CONDITION_RULE = """\
title: Broken rule
logsource:
  product: windows
detection:
  selection:
    Image|endswith: powershell.exe
"""


def _draft(rule_yaml: str = VALID_RULE, confidence: str = "high") -> SigmaRuleDraft:
    return SigmaRuleDraft(
        rule_yaml=rule_yaml,
        confidence=confidence,  # type: ignore[arg-type]
        explanation="Encoded commands are rare in normal use",
        limitations="Misses unencoded payloads",
        false_positive_notes="Some management tooling",
        suggested_log_sources=["Sysmon Event ID 1"],
    )


@pytest.fixture
def generator() -> AdvisoryGenerator:
    with patch("purpleforge.report.advisory_generator.ChatOpenAI"):
        return AdvisoryGenerator(api_key="sk-test")


def _wire(gen: AdvisoryGenerator, outputs: list[SigmaRuleDraft | Exception], prompts: list[str]) -> None:
    """Replace the structured-output model with a callable that records prompts."""
    queue = list(outputs)

    def fake_model(prompt_value: Any) -> SigmaRuleDraft:
        prompts.append(prompt_value.to_string())
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    wired: Callable[[Any], SigmaRuleDraft] = fake_model
    gen._llm.with_structured_output.return_value = wired  # type: ignore[attr-defined]


class TestValidateSigmaYaml:
    def test_valid_rule_parses(self) -> None:
        parsed = validate_sigma_yaml(VALID_RULE)
        assert parsed["title"] == "Suspicious PowerShell Encoded Command"

    def test_missing_condition_rejected(self) -> None:
        with pytest.raises(AdvisoryValidationError, match="condition"):
            validate_sigma_yaml(NO_CONDITION_RULE)

    def test_unparseable_yaml_rejected(self) -> None:
        with pytest.raises(AdvisoryValidationError, match="not valid YAML"):
            validate_sigma_yaml("title: [unclosed")

    def test_non_mapping_rejected(self) -> None:
        with pytest.raises(AdvisoryValidationError, match="mapping"):
            validate_sigma_yaml("- just\n- a list\n")

    def test_missing_required_key_rejected(self) -> None:
        with pytest.raises(AdvisoryValidationError, match="logsource"):
            validate_sigma_yaml("title: x\ndetection:\n  condition: selection\n")


class TestSigmaRuleDraft:
    def test_confidence_is_restricted_to_canonical_values(self) -> None:
        with pytest.raises(ValidationError):
            _draft(confidence="High")

    def test_canonical_confidence_accepted(self) -> None:
        assert _draft(confidence="medium").confidence == "medium"


class TestAdvisoryGenerator:
    def test_valid_draft_becomes_rule(self, generator: AdvisoryGenerator) -> None:
        _wire(generator, [_draft()], [])
        rule = generator.generate("T1059.001", "PowerShell", "Execution", "Encoded loader observed")
        assert rule.technique_id == "T1059.001"
        assert rule.confidence == RuleConfidence.HIGH
        assert rule.rule_yaml == VALID_RULE
        assert rule.auto_deployed is False

    def test_description_reaches_prompt(self, generator: AdvisoryGenerator) -> None:
        prompts: list[str] = []
        _wire(generator, [_draft()], prompts)
        generator.generate("T1059.001", "PowerShell", "Execution", "Report says the loader used -enc")
        assert "Report says the loader used -enc" in prompts[0]
        assert "T1059.001 (PowerShell)" in prompts[0]

    def test_invalid_yaml_raises(self, generator: AdvisoryGenerator) -> None:
        _wire(generator, [_draft(rule_yaml=NO_CONDITION_RULE)], [])
        with pytest.raises(AdvisoryValidationError):
            generator.generate("T1059.001", "PowerShell", "Execution")

    def test_batch_skips_failures_and_keeps_the_rest(self, generator: AdvisoryGenerator) -> None:
        _wire(generator, [_draft(rule_yaml="title: [broken"), RuntimeError("model down"), _draft()], [])
        rules = generator.generate_batch(
            [
                {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "tactic": "Credential Access"},
                {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence"},
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
            ]
        )
        assert [r.technique_id for r in rules] == ["T1059.001"]

    def test_batch_passes_description(self, generator: AdvisoryGenerator) -> None:
        prompts: list[str] = []
        _wire(generator, [_draft()], prompts)
        generator.generate_batch(
            [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                    "tactic": "Execution",
                    "description": "Context from the confirmed TTPs",
                }
            ]
        )
        assert "Context from the confirmed TTPs" in prompts[0]
