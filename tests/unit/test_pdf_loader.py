"""Tests for PDF loading and the local text splitter."""

from __future__ import annotations

from pathlib import Path

import pytest

from purpleforge.ingest.pdf_loader import Chunk, chunk_documents, load_pdf

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestLoadPdf:
    def test_load_sample_pdf(self) -> None:
        pages = load_pdf(FIXTURES / "sample_threat_report.pdf")
        assert len(pages) == 3
        assert all(p.text.strip() for p in pages)
        assert all(isinstance(p, Chunk) for p in pages)

    def test_page_numbers(self) -> None:
        pages = load_pdf(FIXTURES / "sample_threat_report.pdf")
        assert [p.page for p in pages] == [1, 2, 3]

    def test_content_contains_techniques(self) -> None:
        pages = load_pdf(FIXTURES / "sample_threat_report.pdf")
        all_text = " ".join(p.text for p in pages)
        assert "T1059.001" in all_text
        assert "T1053.005" in all_text
        assert "T1003.001" in all_text

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            load_pdf("/nonexistent/path.pdf")


class TestChunkDocuments:
    def test_chunks_respect_size(self) -> None:
        pages = load_pdf(FIXTURES / "sample_threat_report.pdf")
        chunks = chunk_documents(pages, chunk_size=500, chunk_overlap=100)
        assert len(chunks) >= len(pages)
        for chunk in chunks:
            assert len(chunk.text) <= 700  # chunk_size plus overlap tolerance

    def test_chunks_preserve_provenance(self) -> None:
        pages = load_pdf(FIXTURES / "sample_threat_report.pdf")
        chunks = chunk_documents(pages)
        for chunk in chunks:
            assert chunk.source
            assert chunk.metadata["source"] == chunk.source

    def test_smaller_size_makes_more_chunks(self) -> None:
        pages = load_pdf(FIXTURES / "sample_threat_report.pdf")
        small = chunk_documents(pages, chunk_size=200, chunk_overlap=50)
        large = chunk_documents(pages, chunk_size=2000, chunk_overlap=200)
        assert len(small) > len(large)

    def test_splitter_handles_text_without_separators(self) -> None:
        blob = Chunk(text="X" * 2500, page=1, source="r.pdf")
        chunks = chunk_documents([blob], chunk_size=1000, chunk_overlap=0)
        assert len(chunks) >= 3
        assert all(len(c.text) <= 1000 for c in chunks)
