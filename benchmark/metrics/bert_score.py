"""
BERTScore Metric Implementation
================================

BERTScore uses contextual embeddings from BERT to compute semantic similarity.
It's particularly good at recognizing paraphrases and semantic equivalence.

Reference: https://github.com/Tiiiger/bert_score
"""

import logging
from typing import List, Optional

from .evaluator import BaseMetric

logger = logging.getLogger("oghidra.benchmark.metrics.bert_score")


class BERTScoreMetric(BaseMetric):
    """
    BERTScore metric for semantic similarity.

    Uses pre-trained BERT embeddings to compare candidate and reference texts.
    Returns F1 score (harmonic mean of precision and recall).

    Recommended model: microsoft/deberta-xlarge-mnli (best quality)
    Fallback model: roberta-large (faster, good quality)
    """

    def __init__(
        self,
        model_type: str = "roberta-large",
        use_gpu: bool = True,
        batch_size: int = 32,
    ):
        """
        Initialize BERTScore metric.

        Args:
            model_type: Transformer model to use for embeddings
            use_gpu: Whether to use GPU acceleration
            batch_size: Batch size for scoring
        """
        self.model_type = model_type
        self.use_gpu = use_gpu
        self.batch_size = batch_size
        self._scorer = None

        logger.info(f"BERTScore initialized with model: {model_type}")

    @property
    def name(self) -> str:
        return "bert_score_f1"

    def _lazy_init(self):
        """Lazily load bert_score to avoid import overhead."""
        if self._scorer is not None:
            return

        try:
            import bert_score

            self._scorer = bert_score
            logger.info("bert_score library loaded successfully")
        except ImportError:
            raise ImportError("bert_score is required for BERTScoreMetric. Install with: pip install bert-score")

    def score(self, candidate: str, reference: str) -> float:
        """
        Compute BERTScore F1 between candidate and reference.

        Args:
            candidate: Generated summary from decompiled code
            reference: Ground truth summary from source code

        Returns:
            F1 score (0-1, higher is better)
        """
        self._lazy_init()

        P, R, F1 = self._scorer.score(
            cands=[candidate],
            refs=[reference],
            model_type=self.model_type,
            lang="en",
            verbose=False,
            device="cuda" if self.use_gpu else "cpu",
        )

        return float(F1[0])

    def batch_score(self, candidates: List[str], references: List[str]) -> List[float]:
        """
        Compute BERTScore for multiple pairs efficiently.

        Args:
            candidates: List of generated summaries
            references: List of ground truth summaries

        Returns:
            List of F1 scores
        """
        self._lazy_init()

        P, R, F1 = self._scorer.score(
            cands=candidates,
            refs=references,
            model_type=self.model_type,
            lang="en",
            verbose=False,
            batch_size=self.batch_size,
            device="cuda" if self.use_gpu else "cpu",
        )

        return [float(f) for f in F1]

    def detailed_score(self, candidate: str, reference: str) -> dict:
        """
        Get detailed BERTScore with precision, recall, and F1.

        Returns:
            Dict with 'precision', 'recall', 'f1' keys
        """
        self._lazy_init()

        P, R, F1 = self._scorer.score(
            cands=[candidate],
            refs=[reference],
            model_type=self.model_type,
            lang="en",
            verbose=False,
            device="cuda" if self.use_gpu else "cpu",
        )

        return {
            "precision": float(P[0]),
            "recall": float(R[0]),
            "f1": float(F1[0]),
        }
