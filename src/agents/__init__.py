"""
Sub-agent architecture for OGhidra.

This package implements the orchestrator/worker pattern:
- WorkerAgent: Generic task executor that runs a mini execution loop
- WorkerTask: Task specification created by the orchestrator
- AgentResult: Structured result returned by a worker
"""

from src.agents.base import WorkerTask, AgentResult
from src.agents.worker_agent import WorkerAgent

__all__ = [
    "WorkerAgent",
    "WorkerTask",
    "AgentResult",
]
