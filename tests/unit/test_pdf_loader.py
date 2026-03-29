"""Tests for PDF loading and chunking."""

from __future__ import annotations

from pathlib import Path

import pytest

from purpleforge.ingest.pdf_loader import chunk_documents, load_pdf

FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestLoadPdf:
    def test_load_sample_pdf(self) -> None:
        docs = load_pdf(FIXTURES / "sample_threat_report.pdf")
        assert len(docs) == 3  # 3-page PDF
        assert all(d.page_content.strip() for d in docs)

    def test_metadata_has_page_numbers(self) -> None:
        docs = load_pdf(FIXTURES / "sample_threat_report.pdf")
        pages = [d.metadata["page"] for d in docs]
        assert pages == [1, 2, 3]

    def test_content_contains_techniques(self) -> None:
        docs = load_pdf(FIXTURES / "sample_threat_report.pdf")
        all_text = " ".join(d.page_content for d in docs)
        assert "T1059.001" in all_text
        assert "T1053.005" in all_text
        assert "T1003.001" in all_text

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            load_pdf("/nonexistent/path.pdf")


class TestChunkDocuments:
    def test_chunks_smaller_than_originals(self) -> None:
        docs = load_pdf(FIXTURES / "sample_threat_report.pdf")
        chunks = chunk_documents(docs, chunk_size=500, chunk_overlap=100)
        assert len(chunks) >= len(docs)  # More chunks than pages
        for chunk in chunks:
            assert len(chunk.page_content) <= 600  # Roughly within chunk_size + tolerance

    def test_chunks_preserve_metadata(self) -> None:
        docs = load_pdf(FIXTURES / "sample_threat_report.pdf")
        chunks = chunk_documents(docs)
        for chunk in chunks:
            assert "source" in chunk.metadata

    def test_custom_chunk_params(self) -> None:
        docs = load_pdf(FIXTURES / "sample_threat_report.pdf")
        small_chunks = chunk_documents(docs, chunk_size=200, chunk_overlap=50)
        large_chunks = chunk_documents(docs, chunk_size=2000, chunk_overlap=200)
        assert len(small_chunks) > len(large_chunks)
