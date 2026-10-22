"""PDF loading and chunking using pypdf and a small local text splitter."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pypdf import PdfReader


@dataclass
class Chunk:
    """A span of report text with its provenance."""

    text: str
    page: int | None = None
    source: str = ""
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Keep a metadata view so callers can read source and page uniformly.
        self.metadata.setdefault("source", self.source)
        self.metadata.setdefault("page", self.page)


def load_pdf(path: str | Path) -> list[Chunk]:
    """Load a PDF and return one Chunk per page that has text.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the PDF has no extractable text.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"PDF not found: {path}")

    reader = PdfReader(str(path))
    chunks: list[Chunk] = []

    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        if text.strip():
            chunks.append(Chunk(text=text, page=i + 1, source=str(path)))

    if not chunks:
        raise ValueError(f"PDF has no extractable text: {path}")

    return chunks


# Separators tried in order: paragraph, line, sentence, then a hard character cut.
_SEPARATORS = ["\n\n", "\n", ". ", " "]


def _split_text(text: str, chunk_size: int, chunk_overlap: int) -> list[str]:
    """Recursively split text into pieces no larger than chunk_size, with overlap."""
    text = text.strip()
    if len(text) <= chunk_size:
        return [text] if text else []

    pieces = _recursive_split(text, chunk_size, _SEPARATORS)
    return _merge_with_overlap(pieces, chunk_size, chunk_overlap)


def _recursive_split(text: str, chunk_size: int, separators: list[str]) -> list[str]:
    """Break text on the first separator that helps, falling back to a hard cut."""
    if len(text) <= chunk_size:
        return [text]
    for index, sep in enumerate(separators):
        if sep and sep in text:
            parts = text.split(sep)
            out: list[str] = []
            for part in parts:
                piece = part + sep
                if len(piece) <= chunk_size:
                    out.append(piece)
                else:
                    out.extend(_recursive_split(piece, chunk_size, separators[index + 1 :]))
            return [p for p in out if p.strip()]
    # No usable separator left: cut on character boundaries.
    return [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]


def _merge_with_overlap(pieces: list[str], chunk_size: int, chunk_overlap: int) -> list[str]:
    """Greedily join small pieces up to chunk_size, carrying an overlap tail forward."""
    merged: list[str] = []
    current = ""
    for piece in pieces:
        if not current:
            current = piece
        elif len(current) + len(piece) <= chunk_size:
            current += piece
        else:
            merged.append(current.strip())
            tail = current[-chunk_overlap:] if chunk_overlap else ""
            current = tail + piece
    if current.strip():
        merged.append(current.strip())
    return merged


def chunk_documents(
    chunks: list[Chunk],
    chunk_size: int = 1000,
    chunk_overlap: int = 200,
) -> list[Chunk]:
    """Split page chunks into smaller chunks for extraction, preserving page and source."""
    out: list[Chunk] = []
    for chunk in chunks:
        for piece in _split_text(chunk.text, chunk_size, chunk_overlap):
            out.append(Chunk(text=piece, page=chunk.page, source=chunk.source))
    return out
