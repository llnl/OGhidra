"""
Semantic Similarity Metrics for OGhidra Benchmark
==================================================

This module provides multiple metrics for comparing AI-generated function
summaries from decompiled code against ground truth from source code.

Metric Hierarchy:
    Layer 1 (Primary): BERTScore F1, SentenceBERT Cosine
    Layer 2 (Secondary): ROUGE-L, BLEU-4
    Layer 3 (Advanced): LLM-as-Judge
"""

from .evaluator import SemanticEvaluator
from .bert_score import BERTScoreMetric
from .sentence_bert import SentenceBERTMetric
from .rouge import RougeMetric
from .llm_judge import LLMJudgeMetric

__all__ = [
    "SemanticEvaluator",
    "BERTScoreMetric",
    "SentenceBERTMetric",
    "RougeMetric",
    "LLMJudgeMetric",
]
