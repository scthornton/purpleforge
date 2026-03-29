"""ChromaDB vector store for threat report embeddings."""

from __future__ import annotations

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings


class VectorStore:
    """Manages a per-run ChromaDB collection for RAG retrieval."""

    def __init__(
        self,
        run_id: str,
        api_key: str,
        persist_dir: str = "./data/chroma",
        embedding_model: str = "text-embedding-3-small",
    ) -> None:
        self._embeddings = OpenAIEmbeddings(
            model=embedding_model,
            api_key=api_key,  # type: ignore[arg-type]
        )
        self._collection_name = f"purpleforge_{run_id}"
        self._persist_dir = persist_dir
        self._store: Chroma | None = None

    def add_documents(self, docs: list[Document]) -> None:
        """Embed and store documents in ChromaDB."""
        self._store = Chroma.from_documents(
            documents=docs,
            embedding=self._embeddings,
            collection_name=self._collection_name,
            persist_directory=self._persist_dir,
        )

    def similarity_search(self, query: str, k: int = 10) -> list[Document]:
        """Retrieve the top-k most relevant chunks for a query."""
        if self._store is None:
            self._store = Chroma(
                collection_name=self._collection_name,
                embedding_function=self._embeddings,
                persist_directory=self._persist_dir,
            )
        return self._store.similarity_search(query, k=k)
