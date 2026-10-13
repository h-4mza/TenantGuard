import os
import math
import hashlib
import logging
from typing import List, Dict, Any, Optional

import chromadb
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

logger = logging.getLogger("tenantguard.rag")

# ==============================================================================
# Embedding Function Strategy
# If GEMINI_API_KEY is configured, we can optionally use Gemini embeddings.
# Otherwise, we use a lightweight, deterministic offline embedding function
# to ensure zero network failures and fast startup.
# ==============================================================================
class DeterministicEmbeddingFunction(EmbeddingFunction[Documents]):
    """
    Lightweight, deterministic 128-dimensional embedding function.
    Projects text into vector space using word-hash buckets and term frequencies.
    Allows ChromaDB to run fully offline without downloading heavy models.
    """
    def __init__(self, dim: int = 128):
        self.dim = dim

    def __call__(self, input: Documents) -> Embeddings:
        embeddings: Embeddings = []
        for text in input:
            vector = [0.0] * self.dim
            words = text.lower().split()
            if not words:
                embeddings.append(vector)
                continue

            for word in words:
                # Deterministic hashing into dimension buckets
                h = int(hashlib.md5(word.encode("utf-8")).hexdigest(), 16)
                idx = h % self.dim
                sign = 1.0 if (h >> 8) % 2 == 0 else -1.0
                vector[idx] += sign

            # Cosine normalization
            norm = math.sqrt(sum(v * v for v in vector))
            if norm > 0:
                vector = [v / norm for v in vector]
            embeddings.append(vector)
        return embeddings


class RAGService:
    def __init__(self):
        self.persist_dir = os.getenv("CHROMA_PERSIST_DIR", "/app/chroma_data")
        os.makedirs(self.persist_dir, exist_ok=True)

        self.chroma_client = chromadb.PersistentClient(path=self.persist_dir)
        self.embedding_fn = DeterministicEmbeddingFunction()

        # Get or create collection
        self.collection = self.chroma_client.get_or_create_collection(
            name="tenant_documents",
            embedding_function=self.embedding_fn,
            metadata={"hnsw:space": "cosine"}
        )

        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        self._init_gemini()

    def _init_gemini(self):
        """Initializes Google Gemini client if API key is provided."""
        if self.gemini_api_key and self.gemini_api_key.lower() != "mock":
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.gemini_api_key)
                self.gemini_model = genai.GenerativeModel(self.gemini_model_name)
                logger.info(f"Gemini LLM initialized with model: {self.gemini_model_name}")
            except Exception as e:
                logger.warning(f"Could not configure Gemini LLM ({e}). Falling back to mock stub.")
                self.gemini_model = None
        else:
            logger.info("No GEMINI_API_KEY provided. RAG service running with Mock LLM stub.")
            self.gemini_model = None

    def chunk_text(self, text: str, chunk_size: int = 400, overlap: int = 50) -> List[str]:
        """
        Splits text content into overlapping chunks for vector retrieval.
        - chunk_size: Maximum character length per chunk.
        - overlap: Consecutive overlap to preserve semantic context across chunk boundaries.
        """
        if not text or not text.strip():
            return []

        chunks: List[str] = []
        start = 0
        text_len = len(text)

        while start < text_len:
            end = start + chunk_size
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            start += chunk_size - overlap

        return chunks

    def index_document(self, document_id: int, tenant_id: int, filename: str, content: str):
        """
        Chunks and vectorizes document into ChromaDB.
        Stores tenant_id and document_id in chunk metadata for tenant filtering.
        """
        chunks = self.chunk_text(content)
        if not chunks:
            return

        ids = [f"doc_{document_id}_chunk_{i}" for i in range(len(chunks))]
        metadatas = [
            {
                "document_id": document_id,
                "tenant_id": tenant_id,
                "filename": filename
            }
            for _ in range(len(chunks))
        ]

        self.collection.upsert(
            ids=ids,
            documents=chunks,
            metadatas=metadatas
        )
        logger.info(f"Indexed document_id={document_id} for tenant_id={tenant_id} ({len(chunks)} chunks).")

    def delete_document(self, document_id: int):
        """Deletes all chunks belonging to a document from ChromaDB."""
        try:
            self.collection.delete(where={"document_id": document_id})
            logger.info(f"Deleted vector chunks for document_id={document_id}.")
        except Exception as e:
            logger.warning(f"Error deleting chunks for doc {document_id}: {e}")

    def retrieve(self, query: str, tenant_id: int, n_results: int = 3) -> List[Dict[str, Any]]:
        """
        Retrieves relevant chunks from ChromaDB strictly for the specified tenant.
        REMEDIATION (FINDING-06):
        - tenant_id is mandatory (must be a positive integer).
        - Enforces where={"tenant_id": tenant_id} on all queries. Global searches without
          tenant filtering are strictly prohibited.
        """
        if tenant_id is None or not isinstance(tenant_id, int) or tenant_id <= 0:
            raise ValueError(f"A valid positive integer tenant_id is required for vector retrieval. Got: {tenant_id}")

        where_filter = {"tenant_id": tenant_id}

        results = self.collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter
        )

        retrieved_items = []
        if results and results.get("documents") and results["documents"][0]:
            docs = results["documents"][0]
            metadatas = results["metadatas"][0] if results.get("metadatas") else [{}] * len(docs)
            distances = results["distances"][0] if results.get("distances") else [0.0] * len(docs)

            for doc_text, meta, dist in zip(docs, metadatas, distances):
                retrieved_items.append({
                    "text": doc_text,
                    "metadata": meta,
                    "distance": dist
                })

        return retrieved_items

    def generate_response(self, query: str, context_chunks: List[Dict[str, Any]]) -> str:
        """
        Generates an LLM answer using retrieved context.
        VULNERABILITY 4 (Prompt Injection & Context Leaks):
        - The user query is directly injected into the prompt without sanitization.
        - Malicious instructions ('Ignore previous rules...') can override system instructions.
        """
        # Build context block
        context_parts = []
        for i, chunk in enumerate(context_chunks):
            src = chunk.get("metadata", {}).get("filename", "unknown")
            t_id = chunk.get("metadata", {}).get("tenant_id", "unknown")
            context_parts.append(f"[Document {i+1} | Source: {src} | Tenant: {t_id}]\n{chunk['text']}")

        context_str = "\n\n".join(context_parts) if context_parts else "No relevant documents found."

        # Prompt with NO guardrails
        prompt = (
            f"You are TenantGuard AI, an internal enterprise knowledge assistant.\n"
            f"Use the following context documents to answer the user query.\n\n"
            f"--- CONTEXT START ---\n"
            f"{context_str}\n"
            f"--- CONTEXT END ---\n\n"
            f"User Query: {query}\n\n"
            f"Answer:"
        )

        # If Gemini model is available, invoke it
        if self.gemini_model:
            try:
                response = self.gemini_model.generate_content(prompt)
                return response.text
            except Exception as e:
                logger.error(f"Gemini API invocation failed: {e}. Falling back to mock stub.")

        # Fallback Mock LLM response (reproducible without external API keys)
        mock_reply = (
            f"[MOCK LLM RESPONSE - Gemini API Key not configured]\n"
            f"Synthesizing answer based on {len(context_chunks)} retrieved context chunks:\n\n"
        )
        if context_chunks:
            mock_reply += f"According to internal files ({', '.join(set(c.get('metadata', {}).get('filename', '') for c in context_chunks))}):\n"
            mock_reply += f"{context_chunks[0]['text'][:300]}..."
        else:
            mock_reply += "No document context matched your query."

        return mock_reply

# Singleton instance
rag_service = RAGService()
