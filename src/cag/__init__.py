"""
Cache-Augmented Generation (CAG) module for the Ollama-GhidraMCP Bridge

This module provides tools for implementing CAG for Ghidra analysis, allowing
the model to leverage persistent knowledge and session history without real-time retrieval.
"""

from .knowledge_cache import AnalysisRule, BinaryPattern, FunctionSignature, GhidraKnowledgeCache
from .manager import CAGManager

__version__ = "0.1.0"
__all__ = ["AnalysisRule", "BinaryPattern", "CAGManager", "FunctionSignature", "GhidraKnowledgeCache"]
