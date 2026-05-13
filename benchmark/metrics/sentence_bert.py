"""
SentenceBERT Metric Implementation
===================================

Uses Sentence-BERT to generate dense embeddings and compute cosine similarity.
Much faster than BERTScore while maintaining good semantic understanding.

Reference: https://www.sbert.net/
"""

import logging
from typing import List, Optional

from .evaluator import BaseMetric

logger = logging.getLogger("oghidra.benchmark.metrics.sentence_bert")


class SentenceBERTMetric(BaseMetric):
    """
    SentenceBERT cosine similarity metric.

    Generates sentence embeddings using Sentence-BERT and computes
    cosine similarity between candidate and reference embeddings.

    Models (speed vs quality tradeoff):
        - all-MiniLM-L6-v2: Fast, good quality (default)
        - all-mpnet-base-v2: Slower, best quality
        - paraphrase-MiniLM-L6-v2: Optimized for paraphrase detection
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        use_gpu: bool = True,
    ):
        """
        Initialize SentenceBERT metric.

        Args:
            model_name: Sentence-BERT model to use
            use_gpu: Whether to use GPU acceleration
        """
        self.model_name = model_name
        self.use_gpu = use_gpu
        self._model = None
        self._util = None

        logger.info(f"SentenceBERT initialized with model: {model_name}")

    @property
    def name(self) -> str:
        return "sbert_cosine"

    def _lazy_init(self):
        """Lazily load sentence-transformers to avoid import overhead."""
        if self._model is not None:
            return

        try:
            from sentence_transformers import SentenceTransformer, util

            device = "cuda" if self.use_gpu else "cpu"
            self._model = SentenceTransformer(self.model_name, device=device)
            self._util = util

            logger.info(f"SentenceTransformer loaded on {device}")
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for SentenceBERTMetric. Install with: pip install sentence-transformers"
            )

    def score(self, candidate: str, reference: str) -> float:
        """
        Compute cosine similarity between candidate and reference embeddings.

        Args:
            candidate: Generated summary from decompiled code
            reference: Ground truth summary from source code

        Returns:
            Cosine similarity (0-1, higher is better)
        """
        self._lazy_init()

        # Generate embeddings
        emb_candidate = self._model.encode(candidate, convert_to_tensor=True)
        emb_reference = self._model.encode(reference, convert_to_tensor=True)

        # Compute cosine similarity
        similarity = self._util.cos_sim(emb_candidate, emb_reference)

        return float(similarity[0][0])

    def batch_score(self, candidates: List[str], references: List[str]) -> List[float]:
        """
        Compute cosine similarity for multiple pairs efficiently.

        Args:
            candidates: List of generated summaries
            references: List of ground truth summaries

        Returns:
            List of cosine similarity scores
        """
        self._lazy_init()

        # Batch encode all texts
        emb_candidates = self._model.encode(candidates, convert_to_tensor=True)
        emb_references = self._model.encode(references, convert_to_tensor=True)

        # Compute pairwise cosine similarity
        similarities = []
        for i in range(len(candidates)):
            sim = self._util.cos_sim(emb_candidates[i], emb_references[i])
            similarities.append(float(sim[0][0]))

        return similarities

    def get_embedding(self, text: str) -> List[float]:
        """
        Get the embedding vector for a text.

        Useful for storing embeddings for later comparison.

        Args:
            text: Text to embed

        Returns:
            Embedding vector as list of floats
        """
        self._lazy_init()
        embedding = self._model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def batch_get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """
        Get embedding vectors for multiple texts.

        Args:
            texts: List of texts to embed

        Returns:
            List of embedding vectors
        """
        self._lazy_init()
        embeddings = self._model.encode(texts, convert_to_numpy=True)
        return [emb.tolist() for emb in embeddings]
