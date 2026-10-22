"""Tests for TTP extraction with mocked LLM."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from langchain_core.documents import Document

from purpleforge.ingest.ttp_extractor import ExtractionError, TTPExtractor
from purpleforge.models.extraction import Confidence, ExtractedTTP, TTPExtractionResult


def _make_chunks(texts: list[str]) -> list[Document]:
    return [Document(page_content=t) for t in texts]


def _mock_extraction_result(*ttps: tuple[str, str, str, str, str]) -> TTPExtractionResult:
    """Helper to build a TTPExtractionResult from tuples of (id, name, tactic, desc, confidence)."""
    return TTPExtractionResult(
        techniques=[
            ExtractedTTP(
                technique_id=t[0],
                technique_name=t[1],
                tactic=t[2],
                description=t[3],
                confidence=Confidence(t[4]),
            )
            for t in ttps
        ]
    )


class TestTTPExtractor:
    @patch("purpleforge.ingest.ttp_extractor.ChatOpenAI")
    def test_extract_valid_techniques(self, mock_llm_cls: MagicMock) -> None:
        result = _mock_extraction_result(
            ("T1059.001", "PowerShell", "Execution", "Uses PS", "high"),
            ("T1053.005", "Scheduled Task", "Persistence", "Creates tasks", "medium"),
        )

        mock_chain = MagicMock()
        mock_chain.invoke.return_value = result
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = mock_llm
        mock_llm.__or__ = MagicMock(return_value=mock_chain)
        mock_llm_cls.return_value = mock_llm

        extractor = TTPExtractor(api_key="test-key")
        # Patch the internal chain directly
        extractor._prompt = MagicMock()
        extractor._prompt.__or__ = MagicMock(return_value=mock_chain)

        ttps = extractor.extract(_make_chunks(["PowerShell attack using T1059.001"]))
        assert len(ttps) == 2
        assert ttps[0].technique_id in ("T1053.005", "T1059.001")

    @patch("purpleforge.ingest.ttp_extractor.ChatOpenAI")
    def test_dedup_keeps_highest_confidence(self, mock_llm_cls: MagicMock) -> None:
        result = _mock_extraction_result(
            ("T1059.001", "PowerShell", "Execution", "First mention", "low"),
            ("T1059.001", "PowerShell", "Execution", "Explicit mention", "high"),
        )

        mock_chain = MagicMock()
        mock_chain.invoke.return_value = result
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = mock_llm
        mock_llm_cls.return_value = mock_llm

        extractor = TTPExtractor(api_key="test-key")
        extractor._prompt = MagicMock()
        extractor._prompt.__or__ = MagicMock(return_value=mock_chain)

        ttps = extractor.extract(_make_chunks(["test"]))
        assert len(ttps) == 1
        assert ttps[0].confidence == Confidence.HIGH

    @patch("purpleforge.ingest.ttp_extractor.ChatOpenAI")
    def test_invalid_ids_dropped(self, mock_llm_cls: MagicMock) -> None:
        """An ID that slips past schema validation is dropped by the extractor's regex check."""
        valid = ExtractedTTP(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Valid",
            confidence=Confidence.HIGH,
        )
        # model_construct bypasses Pydantic validation, simulating a malformed LLM response
        invalid = ExtractedTTP.model_construct(
            technique_id="TXXX",
            technique_name="Bad",
            tactic="Execution",
            description="Invalid",
            confidence=Confidence.LOW,
            source_chunk="",
        )
        result = TTPExtractionResult.model_construct(techniques=[valid, invalid])

        mock_chain = MagicMock()
        mock_chain.invoke.return_value = result
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = mock_llm
        mock_llm_cls.return_value = mock_llm

        extractor = TTPExtractor(api_key="test-key")
        extractor._prompt = MagicMock()
        extractor._prompt.__or__ = MagicMock(return_value=mock_chain)

        ttps = extractor.extract(_make_chunks(["test"]))
        assert [t.technique_id for t in ttps] == ["T1059.001"]

    @patch("purpleforge.ingest.ttp_extractor.ChatOpenAI")
    def test_empty_extraction_raises(self, mock_llm_cls: MagicMock) -> None:
        result = TTPExtractionResult(techniques=[])

        mock_chain = MagicMock()
        mock_chain.invoke.return_value = result
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = mock_llm
        mock_llm_cls.return_value = mock_llm

        extractor = TTPExtractor(api_key="test-key")
        extractor._prompt = MagicMock()
        extractor._prompt.__or__ = MagicMock(return_value=mock_chain)

        with pytest.raises(ExtractionError, match="No valid techniques"):
            extractor.extract(_make_chunks(["empty document"]))

    @patch("purpleforge.ingest.ttp_extractor.ChatOpenAI")
    def test_results_sorted_by_tactic_then_id(self, mock_llm_cls: MagicMock) -> None:
        result = _mock_extraction_result(
            ("T1083", "File Discovery", "Discovery", "Enumerates files", "high"),
            ("T1059.001", "PowerShell", "Execution", "Uses PS", "high"),
            ("T1003.001", "LSASS Memory", "Credential Access", "Dumps creds", "medium"),
        )

        mock_chain = MagicMock()
        mock_chain.invoke.return_value = result
        mock_llm = MagicMock()
        mock_llm.with_structured_output.return_value = mock_llm
        mock_llm_cls.return_value = mock_llm

        extractor = TTPExtractor(api_key="test-key")
        extractor._prompt = MagicMock()
        extractor._prompt.__or__ = MagicMock(return_value=mock_chain)

        ttps = extractor.extract(_make_chunks(["test"]))
        tactics = [t.tactic for t in ttps]
        assert tactics == sorted(tactics)
