"""
Base data structures for the sub-agent architecture.

WorkerTask: Describes a specific task for a worker to execute.
AgentResult: Structured result returned by a worker to the orchestrator.
SubAgentRegistry: Thread-safe state tracker for the UI sub-agent tree panel.

These are the interface contracts between the Orchestrator and WorkerAgent.
"""

import copy
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


@dataclass
class WorkerTask:
    """
    Task specification created by the orchestrator for a worker.

    The orchestrator decides WHAT needs to be investigated and packages it
    as a WorkerTask. The generic WorkerAgent executes the task without needing
    to know the investigation strategy or agent type.

    Attributes:
        goal: The specific task goal for this worker
            (e.g., "Decompile FUN_00405b60 and analyze its CreateProcessW arguments")
        strategy_hint: Additional context to guide the worker's analysis
            (e.g., "Check for lpApplicationName=NULL and unquoted paths")
        focus_addresses: Specific function/data addresses to investigate
        focus_areas: Coverage areas this task should fill (e.g., ["process_creation"])
        suggested_tools: Tools the orchestrator recommends for this task
        max_steps: Safety ceiling — hard stop for worker steps
        include_sections: Which SystemContextBuilder sections to include in
            this worker's system prompt context
        task_id: Unique identifier for tracking (auto-generated if not provided)
        metadata: Arbitrary metadata for orchestrator bookkeeping
    """
    goal: str
    strategy_hint: str = ""
    focus_addresses: List[str] = field(default_factory=list)
    focus_areas: List[str] = field(default_factory=list)
    suggested_tools: List[str] = field(default_factory=list)
    max_steps: int = 20          # Safety ceiling (hard stop)
    include_sections: List[str] = field(default_factory=lambda: [
        "scope", "knowledge", "analysis_state", "function_registry", "discovery"
    ])
    task_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Recipe mode — deterministic data gathering (Session 10)
    recipe: Optional[str] = None           # e.g. "trace_import_callers"
    recipe_params: Optional[Dict] = None   # e.g. {"api_names": ["CreateProcessW"]}
    analysis_focus: Optional[str] = None   # e.g. "Check for NULL lpApplicationName..."

    def __post_init__(self):
        if not self.task_id:
            self.task_id = f"task_{datetime.now().strftime('%H%M%S')}_{id(self) % 10000}"

    def format_for_prompt(self) -> str:
        """Format the task assignment for inclusion in the worker's system prompt."""
        lines = [f"## Your Task\n{self.goal}"]
        if self.strategy_hint:
            lines.append(f"\n**Strategy guidance:** {self.strategy_hint}")
        if self.focus_addresses:
            lines.append(f"\n**Focus targets:** {', '.join(self.focus_addresses)}")
        if self.suggested_tools:
            lines.append(f"\n**Recommended tools:** {', '.join(self.suggested_tools)}")
        if self.focus_areas:
            lines.append(f"\n**Coverage areas to fill:** {', '.join(self.focus_areas)}")
        if self.recipe:
            lines.append(f"\n**Recipe mode:** {self.recipe}")
            if self.recipe_params:
                lines.append(f"**Recipe parameters:** {self.recipe_params}")
        if self.analysis_focus:
            lines.append(f"\n**Analysis focus:** {self.analysis_focus}")
        return "\n".join(lines)


@dataclass
class AgentResult:
    """
    Structured result returned by a worker to the orchestrator.

    The orchestrator uses this to update the blackboard (investigation notebook,
    function registry, lead tracker, etc.).

    Attributes:
        task_id: ID of the WorkerTask that produced this result
        findings_summary: Human-readable summary of what the worker accomplished
        exec_results: Raw ExecutionPhaseResults from the worker's execution loop
            (optional — set to None to avoid circular import; type checked at runtime)
        tool_executions_count: Number of tools executed
        final_response: If the worker produced a final user-facing response
        new_leads: New investigation leads discovered during execution
        function_analyses: Structured function analysis data to register
        notebook_entries: New findings for the investigation notebook
        is_complete: Whether the worker achieved its assigned task goal
        error: Error message if the worker failed
        exit_reason: Why the worker stopped — "llm_complete", "hard_ceiling",
            "budget_warned_complete", "doom_loop", "abort", or "error"
    """
    task_id: str = ""
    findings_summary: str = ""
    exec_results: Any = None  # ExecutionPhaseResults (avoiding circular import)
    tool_executions_count: int = 0
    final_response: Optional[str] = None
    new_leads: List[Dict[str, str]] = field(default_factory=list)
    function_analyses: List[Dict[str, Any]] = field(default_factory=list)
    notebook_entries: List[Dict[str, Any]] = field(default_factory=list)
    is_complete: bool = False
    error: Optional[str] = None
    exit_reason: str = ""  # "llm_complete", "hard_ceiling", "budget_warned_complete", "doom_loop", "abort", "error"


# ──────────────────────────────────────────────────────────────────────
# Sub-Agent Tree Panel — State tracking for UI visualization
# ──────────────────────────────────────────────────────────────────────


@dataclass
class SubAgentState:
    """Snapshot of a single worker's state in the tree panel."""
    task_id: str
    worker_number: int          # 1-based index within this orchestrator run
    goal: str
    status: str = "pending"     # "pending", "running", "complete", "error"
    current_step: int = 0       # LLM call iteration (loop counter)
    max_steps: int = 20
    soft_limit: int = 8
    exit_reason: str = ""
    tool_count: int = 0         # Total ToolExecution records (includes <no_command>)
    real_tool_count: int = 0    # Actual Ghidra tool executions only
    recipe: str = ""            # Recipe name (e.g. "trace_import_callers") or "" for LLM workers
    phase: str = ""             # Current recipe phase ("gathering", "analyzing", "follow_up") or ""


@dataclass
class OrchestratorState:
    """Snapshot of the orchestrator's state for the tree panel."""
    active: bool = False
    cycle: int = 0
    max_cycles: int = 15
    soft_limit: int = 5
    coverage_ratio: float = 0.0
    strategy: str = ""
    workers: List[SubAgentState] = field(default_factory=list)
    exit_reason: str = ""
    functions_analyzed: int = 0
    functions_total: int = 0           # 0 = not yet enumerated


class SubAgentRegistry:
    """Thread-safe registry tracking orchestrator and worker states.

    Updated from the background orchestrator thread via EventEmitter callbacks.
    Read by the UI panel on the main thread via frame.after() polling.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._state = OrchestratorState()
        self._dirty = False

    def get_state(self) -> OrchestratorState:
        """Return a snapshot of current state (called from UI thread)."""
        with self._lock:
            self._dirty = False
            return copy.deepcopy(self._state)

    @property
    def is_dirty(self) -> bool:
        with self._lock:
            return self._dirty

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self._state.active

    def on_orchestrator_start(self, max_cycles: int, soft_limit: int, strategy: str):
        with self._lock:
            self._state = OrchestratorState(
                active=True, max_cycles=max_cycles,
                soft_limit=soft_limit, strategy=strategy,
            )
            self._dirty = True

    def on_cycle_start(self, cycle: int, coverage_ratio: float,
                       functions_analyzed: int = 0, functions_total: int = 0):
        with self._lock:
            self._state.cycle = cycle
            self._state.coverage_ratio = coverage_ratio
            self._state.functions_analyzed = functions_analyzed
            self._state.functions_total = functions_total
            self._dirty = True

    def on_worker_dispatch(self, task_id: str, goal: str, max_steps: int, soft_limit: int,
                           recipe: str = ""):
        with self._lock:
            worker_num = len(self._state.workers) + 1
            self._state.workers.append(SubAgentState(
                task_id=task_id, worker_number=worker_num,
                goal=goal, status="running",
                max_steps=max_steps, soft_limit=soft_limit,
                recipe=recipe,
            ))
            self._dirty = True

    def on_worker_step(self, task_id: str, step: int, tool_count: int,
                       real_tool_count: int = 0, phase: str = ""):
        with self._lock:
            for w in self._state.workers:
                if w.task_id == task_id:
                    w.current_step = step
                    w.tool_count = tool_count
                    w.real_tool_count = real_tool_count
                    if phase:
                        w.phase = phase
                    self._dirty = True
                    break

    def on_worker_complete(self, task_id: str, exit_reason: str, tool_count: int,
                           real_tool_count: int = 0):
        with self._lock:
            for w in self._state.workers:
                if w.task_id == task_id:
                    w.status = "complete" if exit_reason != "error" else "error"
                    w.exit_reason = exit_reason
                    w.tool_count = tool_count
                    w.real_tool_count = real_tool_count
                    self._dirty = True
                    break

    def on_orchestrator_complete(self, exit_reason: str, coverage_ratio: float,
                                 functions_analyzed: int = 0, functions_total: int = 0):
        with self._lock:
            self._state.active = False
            self._state.exit_reason = exit_reason
            self._state.coverage_ratio = coverage_ratio
            self._state.functions_analyzed = functions_analyzed
            self._state.functions_total = functions_total
            self._dirty = True

    def reset(self):
        with self._lock:
            self._state = OrchestratorState()
            self._dirty = True
