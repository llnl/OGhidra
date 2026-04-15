"""
EventEmitter — Centralized event emission for the OGhidra orchestration system.

Extracted from Bridge to enable sub-agents and the orchestrator to emit
chain-of-thought (CoT) updates, execution gate events, and user questions
through a single shared interface.

The UI sets callbacks on this object; all components (Bridge, Orchestrator,
WorkerAgent, ToolExecutor) hold a reference to the same EventEmitter instance.
"""

import logging
from typing import Optional, Callable, Any

from src.models.memory import ExecutionGate


class EventEmitter:
    """
    Centralized event emission for CoT updates, gate events, and user questions.

    Usage:
        emitter = EventEmitter()
        # UI sets callbacks:
        emitter.set_cot_callback(my_cot_handler)
        emitter.set_gate_callback(my_gate_handler)
        emitter.set_question_callback(my_question_handler)

        # Components emit events:
        emitter.emit_cot("Phase", "Starting execution phase")
        emitter.emit_gate(some_gate_event)
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self._ui_cot_callback: Optional[Callable] = None
        self._ui_gate_callback: Optional[Callable] = None
        self._ui_question_callback: Optional[Callable] = None
        self._ui_agent_callback: Optional[Callable] = None

    def set_cot_callback(self, callback: Callable):
        """Set the UI callback for chain-of-thought updates."""
        self._ui_cot_callback = callback

    def set_gate_callback(self, callback: Callable):
        """Set the UI callback for execution gate events."""
        self._ui_gate_callback = callback

    def set_question_callback(self, callback: Callable):
        """Set the UI callback for user question display."""
        self._ui_question_callback = callback

    def set_agent_callback(self, callback: Callable):
        """Set the UI callback for structured sub-agent tree events."""
        self._ui_agent_callback = callback

    def emit_cot(self, update_type: str, content: str, also_print: bool = True):
        """
        Emit a chain of thought update to both terminal and UI.

        Provides live visibility into the AI agent's reasoning during
        the agentic loop, mirroring output to both console and UI.

        Args:
            update_type: Type of update ('Cycle', 'Phase', 'Reasoning', 'Tool', 'Status')
            content: The update content to display
            also_print: Whether to also print to terminal (default True)
        """
        if also_print:
            if update_type.upper() == 'REASONING':
                pass  # Don't double print reasoning as it's often long
            else:
                print(f"[{update_type}] {content}")

        # Send to UI callback if registered
        if self._ui_cot_callback:
            self._ui_cot_callback(update_type, content)

    def emit_gate(self, gate: ExecutionGate):
        """Emit a gate event to terminal and UI."""
        self.emit_cot("Gate", f"\u26a0\ufe0f ARTIFACT DETECTED: {gate.reason} [trigger={gate.trigger}]")
        if self._ui_gate_callback:
            self._ui_gate_callback(gate)

    def emit_agent_event(self, event_type: str, data: dict):
        """Emit a structured sub-agent event for the tree panel.

        Args:
            event_type: Event type (e.g. "orchestrator_start", "worker_dispatch").
            data: Structured event data (varies by event_type).
        """
        if self._ui_agent_callback:
            try:
                self._ui_agent_callback(event_type, data)
            except Exception as e:
                self.logger.warning(f"Agent event callback error: {e}")

    # --- Backward compatibility aliases (for Bridge delegation) ---

    @property
    def cot_callback(self) -> Optional[Callable]:
        return self._ui_cot_callback

    @cot_callback.setter
    def cot_callback(self, value: Callable):
        self._ui_cot_callback = value

    @property
    def gate_callback(self) -> Optional[Callable]:
        return self._ui_gate_callback

    @gate_callback.setter
    def gate_callback(self, value: Callable):
        self._ui_gate_callback = value

    @property
    def question_callback(self) -> Optional[Callable]:
        return self._ui_question_callback

    @question_callback.setter
    def question_callback(self, value: Callable):
        self._ui_question_callback = value

    @property
    def agent_callback(self) -> Optional[Callable]:
        return self._ui_agent_callback

    @agent_callback.setter
    def agent_callback(self, value: Callable):
        self._ui_agent_callback = value
