"""
Benchmark Runners Module
=========================

Orchestrates benchmark execution, integrating OGhidra with ground truth
and evaluation metrics.
"""

from .benchmark_runner import BenchmarkConfig, BenchmarkRunner
from .oghidra_runner import OGhidraRunner

__all__ = [
    "BenchmarkRunner",
    "BenchmarkConfig",
    "OGhidraRunner",
]
