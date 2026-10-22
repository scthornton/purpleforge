"""Tests for TTP extraction with a mocked OpenAI structured-output call."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from purpleforge.ingest.pdf_loader import Chunk
from purpleforge.ingest.ttp_extractor import TTPExtractor
from purpleforge.models.extraction import Confidence, ExtractedTTP, TTPExtractionResult


def _chunks(texts: list[str]) -> list[Chunk]:
    return [Chunk(text=t, page=i + 1, source="r.pdf") for i, t in enumerate(texts)]


def _result(*ttps: tuple[str, str, str, str, str]) -> TTPExtractionResult:
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


def _completion(parsed: object) -> MagicMock:
    """Shape a stand-in for the OpenAI parse() completion object."""
    message = MagicMock()
    message.parsed = parsed
    choice = MagicMock()
    choice.message = message
    completion = MagicMock()
    completion.choices = [choice]
    return completion


def _extractor_with(parse_returns: list[object]) -> tuple[TTPExtractor, MagicMock]:
    """Build an extractor whose OpenAI client returns the given parsed results in order."""
    with patch("purpleforge.ingest.ttp_extractor.OpenAI") as mock_openai:
        client = MagicMock()
        client.beta.chat.completions.parse.side_effect = [_completion(r) for r in parse_returns]
        mock_openai.return_value = client
        extractor = TTPExtractor(api_key="sk-test")
    return extractor, client


class TestTTPExtractor:
    def test_extract_valid_techniques(self) -> None:
        extractor, _ = _extractor_with(
            [
                _result(
                    ("T1059.001", "PowerShell", "Execution", "Uses PS", "high"),
                    ("T1053.005", "Scheduled Task", "Persistence", "Creates tasks", "medium"),
                )
            ]
        )
        ttps = extractor.extract(_chunks(["PowerShell attack using T1059.001"]))
        assert {t.technique_id for t in ttps} == {"T1059.001", "T1053.005"}

    def test_source_chunk_populated(self) -> None:
        extractor, _ = _extractor_with([_result(("T1059.001", "PowerShell", "Execution", "Uses PS", "high"))])
        ttps = extractor.extract(_chunks(["A report describing a PowerShell loader"]))
        assert ttps[0].source_chunk.startswith("A report describing")

    def test_dedup_keeps_highest_confidence(self) -> None:
        extractor, _ = _extractor_with(
            [
                _result(
                    ("T1059.001", "PowerShell", "Execution", "First", "low"),
                    ("T1059.001", "PowerShell", "Execution", "Explicit", "high"),
                )
            ]
        )
        ttps = extractor.extract(_chunks(["text"]))
        assert len(ttps) == 1
        assert ttps[0].confidence == Confidence.HIGH

    def test_invalid_ids_dropped(self) -> None:
        valid = ExtractedTTP(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            description="Valid",
            confidence=Confidence.HIGH,
        )
        invalid = ExtractedTTP.model_construct(
            technique_id="TXXX",
            technique_name="Bad",
            tactic="Execution",
            description="Invalid",
            confidence=Confidence.LOW,
            source_chunk="",
        )
        result = TTPExtractionResult.model_construct(techniques=[valid, invalid])
        extractor, _ = _extractor_with([result])
        ttps = extractor.extract(_chunks(["text"]))
        assert [t.technique_id for t in ttps] == ["T1059.001"]

    def test_map_reduce_merges_batches(self) -> None:
        # Two batches, each over the budget so they are sent separately, then merged.
        big_a = "A" * 9000
        big_b = "B" * 9000
        extractor, client = _extractor_with(
            [
                _result(("T1059.001", "PowerShell", "Execution", "batch one", "medium")),
                _result(("T1003.001", "LSASS Memory", "Credential Access", "batch two", "high")),
            ]
        )
        ttps = extractor.extract(_chunks([big_a, big_b]))
        assert client.beta.chat.completions.parse.call_count == 2
        assert {t.technique_id for t in ttps} == {"T1059.001", "T1003.001"}

    def test_empty_extraction_raises(self) -> None:
        from purpleforge.ingest.ttp_extractor import ExtractionError

        extractor, _ = _extractor_with([TTPExtractionResult(techniques=[])])
        with pytest.raises(ExtractionError, match="No valid techniques"):
            extractor.extract(_chunks(["empty"]))

    def test_results_sorted_by_tactic_then_id(self) -> None:
        extractor, _ = _extractor_with(
            [
                _result(
                    ("T1083", "File Discovery", "Discovery", "Files", "high"),
                    ("T1059.001", "PowerShell", "Execution", "PS", "high"),
                    ("T1003.001", "LSASS Memory", "Credential Access", "Creds", "medium"),
                )
            ]
        )
        ttps = extractor.extract(_chunks(["text"]))
        tactics = [t.tactic for t in ttps]
        assert tactics == sorted(tactics)
