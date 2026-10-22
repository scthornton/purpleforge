"""Advisory Sigma rule draft generator using LLM structured output."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
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


class SigmaRuleDraft(BaseModel):
    """Structured output for LLM-generated Sigma rule."""

    rule_yaml: str = Field(description="Complete Sigma rule in YAML format")
    confidence: str = Field(description="high, medium, or low")
    explanation: str = Field(description="Why this detection logic should work")
    limitations: str = Field(description="Known gaps in the rule")
    false_positive_notes: str = Field(description="Expected false positive scenarios")
    suggested_log_sources: list[str] = Field(
        default_factory=list,
        description="Log sources needed for this rule to work",
    )


class AdvisoryGenerator:
    """Generate draft Sigma rules for missed techniques."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        self._llm = ChatOpenAI(
            model=model,
            api_key=api_key,  # type: ignore[arg-type]
            temperature=0.2,
        )
        self._prompt = ChatPromptTemplate.from_messages(
            [
                ("system", ADVISORY_SYSTEM_PROMPT),
                (
                    "human",
                    (
                        "Generate a Sigma detection rule for:\n"
                        "Technique: {technique_id} — {technique_name}\n"
                        "Tactic: {tactic}\n"
                        "Context from threat report: {description}"
                    ),
                ),
            ]
        )

    def generate(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str = "",
    ) -> AdvisoryRule:
        """Generate a single advisory Sigma rule draft."""
        chain = self._prompt | self._llm.with_structured_output(SigmaRuleDraft)
        result: SigmaRuleDraft = chain.invoke(
            {  # type: ignore[assignment]
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": tactic,
                "description": description or f"Technique {technique_id} was emulated but not detected",
            }
        )

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
        """Generate advisory rules for all missed techniques. Failures are logged and skipped."""
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
