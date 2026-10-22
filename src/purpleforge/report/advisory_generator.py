"""Advisory Sigma rule draft generator using LLM structured output."""

from __future__ import annotations

import logging
from typing import Any, Literal

import yaml
from openai import OpenAI
from pydantic import BaseModel, Field

from purpleforge.models.advisory import AdvisoryRule, RuleConfidence

logger = logging.getLogger(__name__)

ADVISORY_SYSTEM_PROMPT = """You are a senior detection engineer. Generate a Sigma detection rule \
for the given MITRE ATT&CK technique. The rule should:
- Have a clear, descriptive title
- Use status: experimental
- Include appropriate logsource (product, service, category)
- Have realistic detection logic (selection + condition)
- Include false positive scenarios
- Include MITRE ATT&CK tags

Also assess your confidence in the rule quality and explain its limitations."""

REQUIRED_SIGMA_KEYS = ("title", "logsource", "detection")


class AdvisoryValidationError(Exception):
    """Raised when a generated draft is not a usable Sigma rule."""


def validate_sigma_yaml(rule_yaml: str) -> dict[str, Any]:
    """Parse a Sigma draft and check the keys a rule cannot work without.

    Returns the parsed mapping. Raises AdvisoryValidationError when the YAML does
    not parse, is not a mapping, lacks title, logsource, or detection, or when the
    detection block has no condition.
    """
    try:
        parsed = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        raise AdvisoryValidationError(f"Sigma draft is not valid YAML: {e}") from e
    if not isinstance(parsed, dict):
        raise AdvisoryValidationError("Sigma draft must be a YAML mapping")
    missing = [key for key in REQUIRED_SIGMA_KEYS if key not in parsed]
    if missing:
        raise AdvisoryValidationError(f"Sigma draft is missing required keys: {', '.join(missing)}")
    detection = parsed["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise AdvisoryValidationError("Sigma draft detection block has no condition")
    return parsed


class SigmaRuleDraft(BaseModel):
    """Structured output for LLM-generated Sigma rule."""

    rule_yaml: str = Field(description="Complete Sigma rule in YAML format")
    confidence: Literal["high", "medium", "low"] = Field(description="Confidence in the rule quality")
    explanation: str = Field(description="Why this detection logic should work")
    limitations: str = Field(description="Known gaps in the rule")
    false_positive_notes: str = Field(description="Expected false positive scenarios")
    suggested_log_sources: list[str] = Field(
        default_factory=list,
        description="Log sources needed for this rule to work",
    )


class AdvisoryGenerator:
    """Generate draft Sigma rules for missed techniques."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str | None = None) -> None:
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model

    def generate(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str = "",
    ) -> AdvisoryRule:
        """Generate a single advisory Sigma rule draft."""
        context = description or f"Technique {technique_id} was emulated but not detected"
        user_prompt = (
            "Generate a Sigma detection rule for:\n"
            f"Technique: {technique_id} ({technique_name})\n"
            f"Tactic: {tactic}\n"
            f"Context from threat report: {context}"
        )
        completion = self._client.beta.chat.completions.parse(
            model=self._model,
            temperature=0.2,
            messages=[
                {"role": "system", "content": ADVISORY_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format=SigmaRuleDraft,
        )
        result = completion.choices[0].message.parsed
        if result is None:
            raise AdvisoryValidationError(f"Model returned no draft for {technique_id}")
        validate_sigma_yaml(result.rule_yaml)

        return AdvisoryRule(
            technique_id=technique_id,
            technique_name=technique_name,
            rule_yaml=result.rule_yaml,
            confidence=RuleConfidence(result.confidence),
            explanation=result.explanation,
            limitations=result.limitations,
            false_positive_notes=result.false_positive_notes,
            suggested_log_sources=result.suggested_log_sources,
        )

    def generate_batch(
        self,
        missed_techniques: list[dict[str, Any]],
    ) -> list[AdvisoryRule]:
        """Generate advisory rules for all missed techniques.

        Generation or validation failures are logged and the technique is skipped.
        """
        rules: list[AdvisoryRule] = []
        for tech in missed_techniques:
            try:
                rule = self.generate(
                    technique_id=tech["technique_id"],
                    technique_name=tech.get("technique_name", ""),
                    tactic=tech.get("tactic", ""),
                    description=tech.get("description", ""),
                )
                rules.append(rule)
            except Exception:
                logger.exception("Failed to generate advisory for %s", tech.get("technique_id"))
        return rules
