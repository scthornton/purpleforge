"""LLM-based TTP extraction with structured output and RAG retrieval."""

from __future__ import annotations

import logging
import re

from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from purpleforge.models.extraction import Confidence, ExtractedTTP, TTPExtractionResult

logger = logging.getLogger(__name__)

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

EXTRACTION_SYSTEM_PROMPT = """You are a senior threat intelligence analyst. Extract all MITRE ATT&CK \
techniques from the provided threat report content. For each technique:
- technique_id: The T-code (e.g., T1059.001). Must match pattern T####.### or T####.
- technique_name: Official ATT&CK name
- tactic: ATT&CK tactic category (e.g., Execution, Persistence)
- description: How this technique appears in the report
- confidence: high (explicitly mentioned by T-code or name), medium (described but \
not named), low (inferred from context)
Only include techniques you can justify from the text. Do not hallucinate techniques."""

RAG_QUERY = "What MITRE ATT&CK techniques, tactics, and procedures are described in this report?"


class TTPExtractor:
    """Extracts ATT&CK techniques from document chunks via RAG + structured LLM output."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        self._llm = ChatOpenAI(
            model=model,
            api_key=api_key,  # type: ignore[arg-type]
            temperature=0,
        )
        self._prompt = ChatPromptTemplate.from_messages([
            ("system", EXTRACTION_SYSTEM_PROMPT),
            ("human", "Threat report content:\n\n{context}"),
        ])

    def extract(self, chunks: list[Document]) -> list[ExtractedTTP]:
        """Extract TTPs from document chunks using structured LLM output.

        Uses a two-pass approach:
        1. Concatenate relevant chunks into context
        2. LLM extracts structured TTPs

        Returns validated and deduplicated TTPs sorted by tactic then technique_id.

        Raises:
            ExtractionError: If no valid techniques are extracted.
        """
        context = "\n\n---\n\n".join(chunk.page_content for chunk in chunks)

        chain = self._prompt | self._llm.with_structured_output(TTPExtractionResult)
        result: TTPExtractionResult = chain.invoke({"context": context})  # type: ignore[assignment]

        valid_ttps = self._validate_and_dedup(result.techniques)

        if not valid_ttps:
            raise ExtractionError("No valid techniques found in document")

        return sorted(valid_ttps, key=lambda t: (t.tactic, t.technique_id))

    def _validate_and_dedup(self, ttps: list[ExtractedTTP]) -> list[ExtractedTTP]:
        """Validate technique IDs and deduplicate (keep highest confidence)."""
        seen: dict[str, ExtractedTTP] = {}
        confidence_order = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}

        for ttp in ttps:
            if not TECHNIQUE_ID_PATTERN.match(ttp.technique_id):
                logger.warning("Dropping invalid technique ID: %s", ttp.technique_id)
                continue

            existing = seen.get(ttp.technique_id)
            if existing is None or confidence_order[ttp.confidence] > confidence_order[existing.confidence]:
                seen[ttp.technique_id] = ttp

        return list(seen.values())


class ExtractionError(Exception):
    """Raised when TTP extraction fails."""
