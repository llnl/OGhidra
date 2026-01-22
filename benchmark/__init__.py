"""
OGhidra Semantic Similarity Benchmark Framework
================================================

This framework measures how accurately OGhidra's AI can understand decompiled code
by comparing AI-generated function summaries against ground truth from source code.

Key Research Question:
    "Can an agentic AI, iteratively exploring a binary through Ghidra,
     achieve semantic understanding comparable to having the source code?"

Metrics:
    - BERTScore: Semantic similarity using contextual embeddings
    - SentenceBERT Cosine: Fast embedding-based comparison
    - ROUGE-L: Content coverage baseline
    - LLM-as-Judge: Human-aligned quality assessment

Usage:
    from benchmark import SemanticBenchmark

    bench = SemanticBenchmark()
    results = bench.run(corpus_path="benchmark/corpora/test_corpus")
    bench.generate_report(results, output_path="benchmark/reports/")
"""

__version__ = "0.1.0"

from .metrics.evaluator import SemanticEvaluator
from .runners.benchmark_runner import BenchmarkRunner
from .ground_truth.extractor import GroundTruthExtractor

__all__ = [
    "SemanticEvaluator",
    "BenchmarkRunner",
    "GroundTruthExtractor",
]
