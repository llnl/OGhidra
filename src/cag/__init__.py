"""
Cache-Augmented Generation (CAG) module for the Ollama-GhidraMCP Bridge

This module provides tools for implementing CAG for Ghidra analysis, allowing
the model to leverage persistent knowledge and session history without real-time retrieval.
"""

from .knowledge_cache import GhidraKnowledgeCache, FunctionSignature, BinaryPattern, AnalysisRule
from .manager import CAGManager

__version__ = "0.1.0"
__all__ = ["CAGManager", "GhidraKnowledgeCache", "FunctionSignature", "BinaryPattern", "AnalysisRule"]
