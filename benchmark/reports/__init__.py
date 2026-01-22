"""
Report Generation Module
=========================

Generates comprehensive reports from benchmark results in multiple formats.
"""

from .report_generator import ReportGenerator
from .visualizations import BenchmarkVisualizer

__all__ = [
    "ReportGenerator",
    "BenchmarkVisualizer",
]
