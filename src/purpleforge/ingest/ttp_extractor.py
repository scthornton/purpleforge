"""LLM-based TTP extraction with structured output over the whole report (map-reduce)."""

from __future__ import annotations

import logging
import re

from openai import OpenAI

from purpleforge.ingest.pdf_loader import Chunk
from purpleforge.models.extraction import Confidence, ExtractedTTP, TTPExtractionResult

logger = logging.getLogger(__name__)

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

# Characters of report text sent to the model per request. A typical report fits
# in one or two batches, so recall does not depend on a similarity search.
BATCH_CHAR_BUDGET = 12000

# Length of the source excerpt stored with each technique for the review gate.
SOURCE_EXCERPT_CHARS = 300

EXTRACTION_SYSTEM_PROMPT = """You are a senior threat intelligence analyst. Extract all MITRE ATT&CK \
techniques from the provided threat report content. For each technique:
- technique_id: The T-code (e.g., T1059.001). Must match pattern T####.### or T####.
- technique_name: Official ATT&CK name
- tactic: ATT&CK tactic category (e.g., Execution, Persistence)
- description: How this technique appears in the report
- confidence: high (explicitly mentioned by T-code or name), medium (described but \
not named), low (inferred from context)
Only include techniques you can justify from the text. Do not hallucinate techniques."""


class ExtractionError(Exception):
    """Raised when TTP extraction fails."""


class TTPExtractor:
    """Extract ATT&CK techniques from report chunks via structured LLM output."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", base_url: str | None = None) -> None:
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model

    def extract(self, chunks: list[Chunk]) -> list[ExtractedTTP]:
        """Extract TTPs across all chunks and return validated, deduplicated results.

        The chunks are grouped into batches that fit a character budget, each batch
        is extracted independently, and the results are merged (highest confidence
        wins per technique). Each technique keeps a short excerpt of its source text.

        Raises:
            ExtractionError: If no valid techniques are extracted.
        """
        collected: list[ExtractedTTP] = []
        for batch_text in self._batch(chunks):
            collected.extend(self._extract_batch(batch_text))

        valid_ttps = self._validate_and_dedup(collected)
        if not valid_ttps:
            raise ExtractionError("No valid techniques found in document")

        return sorted(valid_ttps, key=lambda t: (t.tactic, t.technique_id))

    def _batch(self, chunks: list[Chunk]) -> list[str]:
        """Group chunk texts into batches no larger than the character budget."""
        batches: list[str] = []
        current = ""
        for chunk in chunks:
            text = chunk.text
            if current and len(current) + len(text) + 4 > BATCH_CHAR_BUDGET:
                batches.append(current)
                current = text
            else:
                current = f"{current}\n\n---\n\n{text}" if current else text
        if current.strip():
            batches.append(current)
        return batches

    def _extract_batch(self, batch_text: str) -> list[ExtractedTTP]:
        """Run one structured-output extraction over a batch of report text."""
        completion = self._client.beta.chat.completions.parse(
            model=self._model,
            temperature=0,
            messages=[
                {"role": "system", "content": EXTRACTION_SYSTEM_PROMPT},
                {"role": "user", "content": f"Threat report content:\n\n{batch_text}"},
            ],
            response_format=TTPExtractionResult,
        )
        parsed = completion.choices[0].message.parsed
        if parsed is None:
            return []
        excerpt = batch_text.strip()[:SOURCE_EXCERPT_CHARS]
        for ttp in parsed.techniques:
            if not ttp.source_chunk:
                ttp.source_chunk = excerpt
        return list(parsed.techniques)

    def _validate_and_dedup(self, ttps: list[ExtractedTTP]) -> list[ExtractedTTP]:
        """Drop invalid technique IDs and keep the highest-confidence copy of each."""
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
