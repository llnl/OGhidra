"""DSPy-based agent runtime and extension API for OGhidra."""

from .plugins import (
    AddressOrderPlugin,
    AnalysisPlugin,
    FunctionRAGPlugin,
    PluginContext,
    PluginHook,
    PluginManager,
    PluginPhase,
)
from .program import DSPyCompletionClient, FunctionAnalysis, OGhidraAgent, OGhidraDSPyProgram

__all__ = [
    "AddressOrderPlugin",
    "AnalysisPlugin",
    "DSPyCompletionClient",
    "FunctionAnalysis",
    "FunctionRAGPlugin",
    "OGhidraAgent",
    "OGhidraDSPyProgram",
    "PluginContext",
    "PluginHook",
    "PluginManager",
    "PluginPhase",
]
