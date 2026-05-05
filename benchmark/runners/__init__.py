"""
Benchmark Runners Module
=========================

Orchestrates benchmark execution, integrating OGhidra with ground truth
and evaluation metrics.
"""

from .benchmark_runner import BenchmarkRunner, BenchmarkConfig
from .oghidra_runner import OGhidraRunner

__all__ = [
    "BenchmarkRunner",
    "BenchmarkConfig",
    "OGhidraRunner",
]
