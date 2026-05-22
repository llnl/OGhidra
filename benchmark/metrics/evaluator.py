"""
Core Semantic Evaluator
========================

Unified interface for all semantic similarity metrics. This is the main
entry point for evaluating OGhidra's function summary quality.

Usage:
    evaluator = SemanticEvaluator()
    scores = evaluator.evaluate(
        generated="This function encrypts data using AES-128",
        reference="Encrypts a single 16-byte block with AES encryption"
    )
    print(scores)
    # {'bert_score_f1': 0.89, 'sbert_cosine': 0.85, 'rouge_l': 0.42, 'combined': 0.72}
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("oghidra.benchmark.evaluator")


@dataclass
class EvaluationResult:
    """Container for evaluation results with metadata."""

    function_id: str
    generated_summary: str
    reference_summary: str
    scores: Dict[str, float]
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def combined_score(self) -> float:
        """Weighted combination of all metrics."""
        weights = {
            "bert_score_f1": 0.35,
            "sbert_cosine": 0.35,
            "rouge_l": 0.15,
            "llm_judge": 0.15,
        }

        total_weight = 0
        weighted_sum = 0

        for metric, weight in weights.items():
            if metric in self.scores and self.scores[metric] is not None:
                weighted_sum += self.scores[metric] * weight
                total_weight += weight

        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "function_id": self.function_id,
            "generated_summary": self.generated_summary,
            "reference_summary": self.reference_summary,
            "scores": self.scores,
            "combined_score": self.combined_score,
            "metadata": self.metadata,
        }


class BaseMetric(ABC):
    """Abstract base class for all metrics."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Metric name for reporting."""
        pass

    @abstractmethod
    def score(self, candidate: str, reference: str) -> float:
        """Compute similarity score between candidate and reference."""
        pass

    def batch_score(self, candidates: List[str], references: List[str]) -> List[float]:
        """Score multiple pairs. Override for batch-optimized implementations."""
        return [self.score(c, r) for c, r in zip(candidates, references)]


class SemanticEvaluator:
    """
    Unified semantic similarity evaluator combining multiple metrics.

    This class orchestrates BERTScore, SentenceBERT, ROUGE, and optionally
    LLM-as-Judge to provide comprehensive evaluation of summary quality.

    Attributes:
        metrics: Dict of metric name -> metric instance
        use_gpu: Whether to use GPU acceleration
        batch_size: Batch size for vectorized operations
    """

    def __init__(
        self,
        use_gpu: bool = True,
        batch_size: int = 32,
        include_llm_judge: bool = False,
        llm_client: Optional[Any] = None,
    ):
        """
        Initialize the evaluator with selected metrics.

        Args:
            use_gpu: Use GPU for transformer-based metrics
            batch_size: Batch size for efficient processing
            include_llm_judge: Whether to include LLM-as-Judge (slower but more nuanced)
            llm_client: OllamaClient instance for LLM-as-Judge
        """
        self.use_gpu = use_gpu
        self.batch_size = batch_size
        self.metrics: Dict[str, BaseMetric] = {}
        self._initialized = False
        self._llm_embedding_client = llm_client
        self._include_llm_judge = include_llm_judge

        logger.info(f"SemanticEvaluator initialized (GPU: {use_gpu}, batch_size: {batch_size})")

    def _lazy_init(self):
        """Lazily initialize metrics on first use to avoid import overhead."""
        if self._initialized:
            return

        # Import and initialize metrics
        try:
            from .bert_score import BERTScoreMetric

            self.metrics["bert_score_f1"] = BERTScoreMetric(use_gpu=self.use_gpu)
            logger.info("BERTScore metric loaded")
        except ImportError as e:
            logger.warning(f"BERTScore not available: {e}. Install with: pip install bert-score")

        try:
            from .sentence_bert import SentenceBERTMetric

            self.metrics["sbert_cosine"] = SentenceBERTMetric(use_gpu=self.use_gpu)
            logger.info("SentenceBERT metric loaded")
        except ImportError as e:
            logger.warning(f"SentenceBERT not available: {e}. Install with: pip install sentence-transformers")

        try:
            from .rouge import RougeMetric

            self.metrics["rouge_l"] = RougeMetric()
            logger.info("ROUGE metric loaded")
        except ImportError as e:
            logger.warning(f"ROUGE not available: {e}. Install with: pip install rouge-score")

        if self._include_llm_judge and self._llm_embedding_client:
            try:
                from .llm_judge import LLMJudgeMetric

                self.metrics["llm_judge"] = LLMJudgeMetric(ollama_client=self._ollama_client)
                logger.info("LLM-as-Judge metric loaded")
            except Exception as e:
                logger.warning(f"LLM-as-Judge not available: {e}")

        self._initialized = True

        if not self.metrics:
            raise RuntimeError("No metrics available. Install at least one of: bert-score, sentence-transformers, rouge-score")

    def evaluate(
        self,
        generated: str,
        reference: str,
        function_id: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> EvaluationResult:
        """
        Evaluate a single generated summary against its reference.

        Args:
            generated: AI-generated summary from decompiled code
            reference: Ground truth summary from source code
            function_id: Identifier for the function being evaluated
            metadata: Additional metadata to include in results

        Returns:
            EvaluationResult with all metric scores
        """
        self._lazy_init()

        scores = {}
        for name, metric in self.metrics.items():
            try:
                scores[name] = metric.score(generated, reference)
            except Exception as e:
                logger.error(f"Error computing {name}: {e}")
                scores[name] = None

        return EvaluationResult(
            function_id=function_id,
            generated_summary=generated,
            reference_summary=reference,
            scores=scores,
            metadata=metadata or {},
        )

    def batch_evaluate(
        self,
        generated: List[str],
        references: List[str],
        function_ids: Optional[List[str]] = None,
        metadata: Optional[List[Dict[str, Any]]] = None,
    ) -> List[EvaluationResult]:
        """
        Evaluate multiple generated summaries in batch for efficiency.

        Args:
            generated: List of AI-generated summaries
            references: List of ground truth summaries
            function_ids: List of function identifiers
            metadata: List of metadata dicts

        Returns:
            List of EvaluationResult objects
        """
        self._lazy_init()

        n = len(generated)
        if function_ids is None:
            function_ids = [f"func_{i}" for i in range(n)]
        if metadata is None:
            metadata = [{} for _ in range(n)]

        # Compute all metrics in batch
        all_scores: Dict[str, List[float]] = {}
        for name, metric in self.metrics.items():
            try:
                all_scores[name] = metric.batch_score(generated, references)
            except Exception as e:
                logger.error(f"Error in batch {name}: {e}")
                all_scores[name] = [None] * n

        # Assemble results
        results = []
        for i in range(n):
            scores = {name: all_scores[name][i] for name in self.metrics}
            results.append(
                EvaluationResult(
                    function_id=function_ids[i],
                    generated_summary=generated[i],
                    reference_summary=references[i],
                    scores=scores,
                    metadata=metadata[i],
                )
            )

        return results

    def compute_corpus_statistics(
        self,
        results: List[EvaluationResult],
    ) -> Dict[str, Any]:
        """
        Compute aggregate statistics over a corpus of evaluation results.

        Args:
            results: List of EvaluationResult from batch_evaluate

        Returns:
            Dict with mean, std, median, min, max for each metric
        """
        stats = {}

        # Collect scores per metric
        metric_scores: Dict[str, List[float]] = {}
        for result in results:
            for metric, score in result.scores.items():
                if score is not None:
                    if metric not in metric_scores:
                        metric_scores[metric] = []
                    metric_scores[metric].append(score)

        # Compute statistics
        for metric, scores in metric_scores.items():
            arr = np.array(scores)
            stats[metric] = {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "median": float(np.median(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "count": len(scores),
            }

        # Combined score statistics
        combined_scores = [r.combined_score for r in results]
        arr = np.array(combined_scores)
        stats["combined"] = {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "median": float(np.median(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "count": len(combined_scores),
        }

        return stats

    def get_available_metrics(self) -> List[str]:
        """Return list of available metric names."""
        self._lazy_init()
        return list(self.metrics.keys())
