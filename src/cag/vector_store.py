"""
Vector store implementation for the CAG system.
"""

import logging
import os
import json
from typing import List, Dict, Any, Optional
import numpy as np

# Optional FAISS import
try:
    import faiss  # type: ignore
    _FAISS_AVAILABLE = True
except ImportError:
    _FAISS_AVAILABLE = False

logger = logging.getLogger("ollama-ghidra-bridge.cag.vector_store")

# Embeddings are now handled by Ollama instead of HuggingFace
EMBEDDINGS_AVAILABLE = True

class SimpleVectorStore:
    """Simple vector store implementation for document search."""
    
    def __init__(self, documents: List[Dict[str, Any]], embeddings: List[np.ndarray]):
        """
        Initialize the vector store.
        
        Args:
            documents: List of document dictionaries
            embeddings: List of document embeddings
        """
        self.documents = documents
        self.embeddings = embeddings

        # Build FAISS index if embeddings available and library present
        self._faiss_index = None
        if _FAISS_AVAILABLE and self.embeddings:
            self._build_faiss_index()
        
        # For compatibility with older code
        self.function_signatures = []
        self.binary_patterns = []
        self.analysis_rules = []
        self.common_workflows = []
        
    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Search the vector store for documents similar to the query.
        
        Args:
            query: The search query
            top_k: Number of top results to return
            
        Returns:
            List of document dictionaries with similarity scores
        """
        if not self.documents or not self.embeddings:
            logger.warning("No documents or embeddings available")
            return []
            
        # Use Ollama embeddings from Bridge class
        try:
            from src.bridge import Bridge
            query_embeddings = Bridge.get_ollama_embeddings([query])
            if not query_embeddings:
                logger.warning("No Ollama embedding model available. Vector search disabled.")
                return []
            query_embedding = np.array(query_embeddings[0])
        except ImportError:
            logger.warning("Bridge not available for embeddings")
            return []
        
        if _FAISS_AVAILABLE and self._faiss_index is not None:
            q = query_embedding.astype('float32').reshape(1, -1)
            faiss.normalize_L2(q)
            sims, idxs = self._faiss_index.search(q, top_k)
            sims = sims[0]
            top_indices = idxs[0]
            similarities = sims
        else:
            # Fallback: brute-force cosine similarity
            similarities = []
            for doc_embedding in self.embeddings:
                similarity = np.dot(query_embedding, doc_embedding) / (
                    np.linalg.norm(query_embedding) * np.linalg.norm(doc_embedding)
                )
                similarities.append(similarity)
            top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        # Return top-k documents with scores
        results = []
        for i, idx in enumerate(top_indices):
            results.append({
                "document": self.documents[idx] if idx >=0 and idx < len(self.documents) else {},
                "score": float(similarities[i])
            })
            
        return results

    def get_relevant_knowledge(self, query: str, token_limit: int = 2000) -> str:
        """
        Get relevant knowledge for a query.
        
        Args:
            query: The query string
            token_limit: Maximum number of tokens to return
            
        Returns:
            Relevant knowledge as a string
        """
        results = self.search(query, top_k=3)
        
        if not results:
            return ""
            
        # Combine results into a single string, respecting token limit
        # Rough estimate: 4 chars = 1 token
        char_limit = token_limit * 4
        relevant_docs = []
        
        total_chars = 0
        for result in results:
            doc = result["document"]
            # Handle both "text" and "content" fields for different document formats
            doc_text = doc.get("text", doc.get("content", ""))
            doc_type = doc.get("type", "unknown")
            doc_name = doc.get("name", doc.get("title", "Unnamed"))
            
            # Add header for the document
            header = f"## {doc_type.upper()}: {doc_name}\n"
            
            # If adding this document would exceed the limit, skip it
            if total_chars + len(header) + len(doc_text) > char_limit:
                if not relevant_docs:  # If no docs added yet, add a truncated version
                    truncated_text = doc_text[:char_limit - len(header) - 3] + "..."
                    relevant_docs.append(f"{header}\n{truncated_text}")
                break
                
            relevant_docs.append(f"{header}\n{doc_text}")
            total_chars += len(header) + len(doc_text)
            
        return "\n\n".join(relevant_docs)

    def _build_faiss_index(self):
        """Internal helper to build FAISS index."""
        if not _FAISS_AVAILABLE or not self.embeddings:
            return
        dim = len(self.embeddings[0])
        self._faiss_index = faiss.IndexFlatIP(dim)
        vecs = np.array(self.embeddings).astype('float32')
        faiss.normalize_L2(vecs)
        self._faiss_index.add(vecs)
        logger.info("CAG FAISS index built with %d documents", len(self.embeddings))

def create_vector_store_from_docs(documents: List[Dict[str, Any]]) -> Optional[SimpleVectorStore]:
    """
    Create a vector store from documents.
    
    Args:
        documents: List of document dictionaries
        
    Returns:
        SimpleVectorStore instance or None if embeddings not available
    """
    if not documents:
        logger.warning("No documents provided for vector store creation")
        return SimpleVectorStore([], [])
        
    try:
        # Use Ollama embeddings from Bridge class
        try:
            from src.bridge import Bridge
            
            # Create embeddings - handle both "text" and "content" fields
            texts = []
            valid_documents = []
            for doc in documents:
                text = doc.get("text", doc.get("content", ""))
                if not text:
                    logger.debug(f"Document {doc.get('id', 'unknown')} has no text content - skipping")
                    continue
                texts.append(text)
                valid_documents.append(doc)
            
            embeddings_list = Bridge.get_ollama_embeddings(texts)
            if not embeddings_list:
                logger.warning("No Ollama embedding model available. Vector store creation disabled.")
                return None
            
            # Convert to numpy arrays
            embeddings = [np.array(emb) for emb in embeddings_list]
            
            # Create vector store with only valid documents
            return SimpleVectorStore(valid_documents, embeddings)
            
        except ImportError:
            logger.warning("Bridge not available for embeddings")
            return None
    except Exception as e:
        logger.error(f"Error creating vector store: {str(e)}")
        return None 