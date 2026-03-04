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
            
        # Use embeddings from Bridge class
        try:
            from src.bridge import Bridge
            query_embeddings = Bridge.get_embeddings([query])
            if not query_embeddings:
                logger.warning("No embedding model available. Vector search disabled.")
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
            
            # Check dimensions first
            query_dim = query_embedding.shape[0]
            valid_indices = []
            
            for i, doc_embedding in enumerate(self.embeddings):
                # Skip if dimension mismatch
                if doc_embedding.shape[0] != query_dim:
                    continue
                    
                similarity = np.dot(query_embedding, doc_embedding) / (
                    np.linalg.norm(query_embedding) * np.linalg.norm(doc_embedding)
                )
                similarities.append(similarity)
                valid_indices.append(i)
                
            if not similarities:
                logger.warning(f"No compatible embeddings found (query dim: {query_dim}). Vectors might need re-indexing.")
                return []
                
            # Map back to original indices
            top_local_indices = np.argsort(similarities)[-top_k:][::-1]
            top_indices = [valid_indices[i] for i in top_local_indices]
        
        # Return top-k documents with scores
        results = []
        for i, idx in enumerate(top_indices):
            results.append({
                "document": self.documents[idx] if idx >=0 and idx < len(self.documents) else {},
                "score": float(similarities[i])
            })
            
        return results
    
    def search_hybrid(self, query: str, top_k: int = 5, use_keywords: bool = True, keyword_weight: float = 0.4) -> List[Dict[str, Any]]:
        """
        Hybrid search combining keyword matching and semantic similarity.
        
        Args:
            query: Search query
            top_k: Number of results to return
            use_keywords: Whether to include keyword search
            keyword_weight: Weight for keyword results (0.0-1.0), semantic gets (1-weight)
            
        Returns:
            List of documents with scores, sorted by combined relevance
        """
        if not self.documents:
            logger.warning("No documents available for search")
            return []
        
        results = []
        
        # 1. Keyword search (grep-style)
        if use_keywords:
            keyword_results = self._keyword_search(query, top_k=top_k*2)
            for result in keyword_results:
                result['search_type'] = 'keyword'
            results.extend(keyword_results)
        
        # 2. Semantic search (embeddings)
        if self.embeddings:
            semantic_results = self.search(query, top_k=top_k*2)
            for result in semantic_results:
                result['search_type'] = 'semantic'
            results.extend(semantic_results)
        
        # 3. Merge and re-rank
        if results:
            return self._merge_and_rerank(results, top_k, keyword_weight)
        
        return []
    
    def _keyword_search(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        """
        Keyword-based search through document text (grep-style).
        
        Args:
            query: Search query
            top_k: Number of results to return
            
        Returns:
            List of documents with keyword match scores
        """
        query_lower = query.lower()
        query_terms = query_lower.split()
        matches = []
        
        for i, doc in enumerate(self.documents):
            # Get document text
            text = doc.get("text", doc.get("content", "")).lower()
            
            if not text:
                continue
            
            # Calculate match score based on term frequency
            score = 0.0
            text_words = text.split()
            text_len = len(text_words)
            
            # Score by term frequency (TF)
            for term in query_terms:
                term_count = text.count(term)
                if term_count > 0:
                    # TF score: occurrences / doc length
                    tf_score = term_count / max(text_len, 1)
                    score += tf_score
            
            # Only include if there's a match
            if score > 0:
                matches.append({
                    "document": doc,
                    "score": score,
                    "search_type": "keyword"
                })
        
        # Sort by score and return top-K
        return sorted(matches, key=lambda x: x["score"], reverse=True)[:top_k]
    
    def _merge_and_rerank(self, results: List[Dict[str, Any]], top_k: int, keyword_weight: float = 0.4) -> List[Dict[str, Any]]:
        """
        Merge keyword and semantic results, removing duplicates and re-ranking.
        
        Args:
            results: Combined results from keyword and semantic search
            top_k: Number of results to return
            keyword_weight: Weight for keyword scores (semantic gets 1-weight)
            
        Returns:
            Merged and re-ranked results
        """
        # Deduplicate by document address/name
        seen = {}
        semantic_weight = 1.0 - keyword_weight
        
        for result in results:
            doc = result["document"]
            # Use address as unique identifier
            doc_id = doc.get("metadata", {}).get("address") or doc.get("name", "") or str(hash(str(doc)))
            
            if doc_id in seen:
                # Document already seen - combine scores
                existing = seen[doc_id]
                search_type = result.get("search_type", "unknown")
                
                # Weight the score based on search type
                if search_type == "keyword":
                    weighted_score = result["score"] * keyword_weight
                else:
                    weighted_score = result["score"] * semantic_weight
                
                existing["combined_score"] += weighted_score
                existing["search_types"].add(search_type)
            else:
                # New document
                search_type = result.get("search_type", "unknown")
                
                # Weight the score
                if search_type == "keyword":
                    weighted_score = result["score"] * keyword_weight
                else:
                    weighted_score = result["score"] * semantic_weight
                
                seen[doc_id] = {
                    "document": doc,
                    "score": result["score"],  # Original score
                    "combined_score": weighted_score,
                    "search_types": {search_type}
                }
        
        # Convert to list and sort by combined score
        merged = list(seen.values())
        merged.sort(key=lambda x: x["combined_score"], reverse=True)
        
        return merged[:top_k]
    
    def search_by_function_name(self, name_pattern: str, exact: bool = False) -> List[Dict[str, Any]]:
        """
        Search for functions by name pattern.
        
        Args:
            name_pattern: Function name or pattern to search for
            exact: If True, require exact match; if False, substring match
            
        Returns:
            List of matching documents
        """
        matches = []
        pattern_lower = name_pattern.lower()
        
        for doc in self.documents:
            doc_name = doc.get("name", "").lower()
            
            if exact:
                if doc_name == pattern_lower:
                    matches.append({"document": doc, "score": 1.0})
            else:
                if pattern_lower in doc_name:
                    # Score by how much of the name matches
                    score = len(pattern_lower) / max(len(doc_name), 1)
                    matches.append({"document": doc, "score": score})
        
        return sorted(matches, key=lambda x: x["score"], reverse=True)

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
        # Use embeddings from Bridge class
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
            
            embeddings_list = Bridge.get_embeddings(texts)
            if not embeddings_list:
                logger.warning("No embedding model available. Vector store creation disabled.")
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