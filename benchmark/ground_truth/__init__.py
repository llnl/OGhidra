"""
Ground Truth Generation Module
===============================

Extracts function signatures, docstrings, and generates AI summaries
from source code to serve as ground truth for benchmark evaluation.
"""

from .extractor import GroundTruthExtractor
from .source_parser import SourceCodeParser
from .summary_generator import SourceSummaryGenerator

__all__ = [
    "GroundTruthExtractor",
    "SourceCodeParser",
    "SourceSummaryGenerator",
]
