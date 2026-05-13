"""
ROUGE Metric Implementation
============================

ROUGE (Recall-Oriented Understudy for Gisting Evaluation) measures
n-gram overlap between candidate and reference texts.

Used as a baseline metric - lower correlation with human judgment
than embedding-based metrics, but useful for content coverage.
"""

import logging
from typing import Dict, List

from .evaluator import BaseMetric

logger = logging.getLogger("oghidra.benchmark.metrics.rouge")


class RougeMetric(BaseMetric):
    """
    ROUGE metric for content overlap measurement.

    Computes ROUGE-1, ROUGE-2, and ROUGE-L scores.
    Primary score returned is ROUGE-L F-measure.

    ROUGE-L uses longest common subsequence (LCS) which is good
    for measuring structural similarity in summaries.
    """

    def __init__(self, use_stemmer: bool = True):
        """
        Initialize ROUGE metric.

        Args:
            use_stemmer: Whether to use Porter stemmer for normalization
        """
        self.use_stemmer = use_stemmer
        self._scorer = None

        logger.info(f"ROUGE initialized (stemmer: {use_stemmer})")

    @property
    def name(self) -> str:
        return "rouge_l"

    def _lazy_init(self):
        """Lazily load rouge_score to avoid import overhead."""
        if self._scorer is not None:
            return

        try:
            from rouge_score import rouge_scorer

            self._scorer = rouge_scorer.RougeScorer(
                ["rouge1", "rouge2", "rougeL"],
                use_stemmer=self.use_stemmer,
            )
            logger.info("rouge_score library loaded successfully")
        except ImportError:
            raise ImportError("rouge-score is required for RougeMetric. Install with: pip install rouge-score")

    def score(self, candidate: str, reference: str) -> float:
        """
        Compute ROUGE-L F-measure between candidate and reference.

        Args:
            candidate: Generated summary from decompiled code
            reference: Ground truth summary from source code

        Returns:
            ROUGE-L F-measure (0-1, higher is better)
        """
        self._lazy_init()

        scores = self._scorer.score(reference, candidate)
        return scores["rougeL"].fmeasure

    def detailed_score(self, candidate: str, reference: str) -> Dict[str, Dict[str, float]]:
        """
        Get detailed ROUGE scores including precision, recall, and F-measure.

        Returns:
            Dict with 'rouge1', 'rouge2', 'rougeL' keys, each containing
            'precision', 'recall', 'fmeasure' sub-keys
        """
        self._lazy_init()

        scores = self._scorer.score(reference, candidate)

        return {
            "rouge1": {
                "precision": scores["rouge1"].precision,
                "recall": scores["rouge1"].recall,
                "fmeasure": scores["rouge1"].fmeasure,
            },
            "rouge2": {
                "precision": scores["rouge2"].precision,
                "recall": scores["rouge2"].recall,
                "fmeasure": scores["rouge2"].fmeasure,
            },
            "rougeL": {
                "precision": scores["rougeL"].precision,
                "recall": scores["rougeL"].recall,
                "fmeasure": scores["rougeL"].fmeasure,
            },
        }

    def batch_score(self, candidates: List[str], references: List[str]) -> List[float]:
        """
        Compute ROUGE-L for multiple pairs.

        Args:
            candidates: List of generated summaries
            references: List of ground truth summaries

        Returns:
            List of ROUGE-L F-measure scores
        """
        self._lazy_init()

        scores = []
        for candidate, reference in zip(candidates, references):
            result = self._scorer.score(reference, candidate)
            scores.append(result["rougeL"].fmeasure)

        return scores
