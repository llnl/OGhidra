"""
Execution Gatekeeper — Interactive execution loop control.

Inspired by OpenCode's PermissionNext.ask()/reply() system and doom-loop detection,
this module monitors the execution loop and triggers pause signals when critical
events occur — giving the user a chance to review, redirect, or abort.

Integration Points:
    - Bridge._execution_loop: gate checks before/after each tool execution
    - Bridge.process_query_with_agentic_loop: handles gate-paused results
    - UI: _ui_gate_callback for surfacing gate events to the user
"""

import re
import logging
from typing import Optional, List, Dict, Any
from collections import defaultdict

from src.models.memory import ExecutionSignal, ExecutionGate, ToolExecution


class ExecutionGatekeeper:
    """
    Monitors the execution loop and triggers pause signals
    when critical events occur.
    
    Inspired by OpenCode's PermissionNext system where the processor
    can block on user approval before continuing tool execution.
    
    Gate Triggers:
        artifact   — Critical security finding in tool result text
        repetition — Doom-loop: N identical tool calls in a row
        high_risk  — Destructive tool about to execute (rename, etc.)
    """
    
    # Tools that modify state and may need user approval
    HIGH_RISK_TOOLS = {
        'rename_function',
        'rename_function_by_address',
    }
    
    # Patterns that indicate critical artifacts worth pausing for.
    # These are checked against stringified tool results.
    CRITICAL_ARTIFACT_PATTERNS = [
        # Privilege escalation indicators
        (r'SeTakeOwnershipPrivilege', 'Privilege escalation: SeTakeOwnershipPrivilege'),
        (r'SeDebugPrivilege', 'Privilege escalation: SeDebugPrivilege'),
        (r'SeImpersonatePrivilege', 'Privilege escalation: SeImpersonatePrivilege'),
        (r'SeLoadDriverPrivilege', 'Privilege escalation: SeLoadDriverPrivilege'),
        (r'AdjustTokenPrivileges', 'Token manipulation: AdjustTokenPrivileges'),
        (r'OpenProcessToken', 'Token manipulation: OpenProcessToken'),
        
        # Crypto / credential patterns
        (r'(?i)CryptEncrypt|CryptDecrypt|BCryptEncrypt|BCryptDecrypt', 'Cryptographic operation detected'),
        (r'(?i)(?:password|passwd|credential|secret)\s*[:=]', 'Possible hardcoded credential'),
        (r'(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Embedded private key'),
        
        # C2 / network indicators
        (r'(?:https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'Hardcoded IP URL (possible C2)'),
        
        # Shellcode / injection patterns
        (r'VirtualAlloc.*PAGE_EXECUTE', 'Executable memory allocation (possible shellcode)'),
        (r'WriteProcessMemory', 'Process memory write (possible injection)'),
        (r'NtCreateThreadEx|RtlCreateUserThread', 'Remote thread creation'),
        
        # Service path issues
        (r'(?i)Unquoted\s+(?:Service\s+)?Path', 'Unquoted service path vulnerability'),
        (r'StartServiceCtrlDispatcher', 'Windows service entry point'),
        
        # Anti-analysis
        (r'IsDebuggerPresent|NtQueryInformationProcess', 'Anti-debugging technique'),
    ]
    
    def __init__(self, config):
        """Initialize gatekeeper from LLM config.
        
        Args:
            config: OllamaConfig or ExternalConfig with gate_* fields.
        """
        self.logger = logging.getLogger("execution-gate")
        
        # Feature flags from config
        self.enabled = getattr(config, 'execution_gate_enabled', True)
        self.gate_on_artifact = getattr(config, 'gate_on_artifact', True)
        self.gate_on_repetition = getattr(config, 'gate_on_repetition', True)
        self.gate_on_high_risk = getattr(config, 'gate_on_high_risk_tool', False)
        self.repetition_threshold = getattr(config, 'gate_repetition_threshold', 3)
        self.auto_resume_timeout = getattr(config, 'gate_auto_resume_timeout', 0)
        
        # Internal state
        self._repetition_tracker: Dict[str, int] = defaultdict(int)
        self._last_gate: Optional[ExecutionGate] = None
        self._pending_feedback: Optional[str] = None
        
        # Compile patterns once
        self._compiled_patterns = [
            (re.compile(pattern), description)
            for pattern, description in self.CRITICAL_ARTIFACT_PATTERNS
        ]
        
        self.logger.info(
            f"ExecutionGatekeeper initialized: enabled={self.enabled}, "
            f"artifact={self.gate_on_artifact}, repetition={self.gate_on_repetition}, "
            f"high_risk={self.gate_on_high_risk}"
        )
    
    def check_before_execution(
        self,
        cmd_name: str,
        cmd_params: Dict[str, Any],
        exec_history: List[ToolExecution]
    ) -> ExecutionSignal:
        """Check BEFORE a tool runs. Returns signal controlling loop flow.
        
        Checks performed:
            1. High-risk tool gate (if gate_on_high_risk_tool)
            2. Repetition/doom-loop gate (if gate_on_repetition)
        
        Args:
            cmd_name: Name of the tool about to execute
            cmd_params: Parameters for the tool
            exec_history: List of tool executions so far in this loop
            
        Returns:
            ExecutionSignal.CONTINUE if ok to proceed,
            ExecutionSignal.PAUSE if the loop should pause
        """
        if not self.enabled:
            return ExecutionSignal.CONTINUE
        
        # --- High-risk tool check ---
        if self.gate_on_high_risk and cmd_name in self.HIGH_RISK_TOOLS:
            self._last_gate = ExecutionGate(
                reason=f"High-risk tool '{cmd_name}' requires approval before execution",
                signal=ExecutionSignal.PAUSE,
                trigger="high_risk",
                context={
                    "tool": cmd_name,
                    "params": cmd_params,
                }
            )
            self.logger.warning(f"🚧 GATE [high_risk]: {self._last_gate.reason}")
            return ExecutionSignal.PAUSE
        
        # --- Repetition / doom-loop check ---
        if self.gate_on_repetition:
            param_sig = str(sorted(cmd_params.items())) if cmd_params else ""
            cmd_signature = f"{cmd_name}:{param_sig}"
            self._repetition_tracker[cmd_signature] += 1
            
            if self._repetition_tracker[cmd_signature] >= self.repetition_threshold:
                self._last_gate = ExecutionGate(
                    reason=(
                        f"Doom-loop detected: '{cmd_name}' called {self._repetition_tracker[cmd_signature]} times "
                        f"with identical parameters (threshold={self.repetition_threshold})"
                    ),
                    signal=ExecutionSignal.PAUSE,
                    trigger="repetition",
                    context={
                        "tool": cmd_name,
                        "params": cmd_params,
                        "call_count": self._repetition_tracker[cmd_signature],
                        "threshold": self.repetition_threshold,
                    }
                )
                self.logger.warning(f"🚧 GATE [repetition]: {self._last_gate.reason}")
                return ExecutionSignal.PAUSE
        
        return ExecutionSignal.CONTINUE
    
    def check_after_execution(
        self,
        cmd_name: str,
        result: str,
        exec_history: List[ToolExecution]
    ) -> ExecutionSignal:
        """Check AFTER a tool runs. Returns signal if critical artifact found.
        
        Scans the tool result text for patterns indicating critical security
        findings that warrant user attention before the loop continues.
        
        Args:
            cmd_name: Name of the tool that just executed
            result: String result from the tool execution
            exec_history: List of tool executions so far
            
        Returns:
            ExecutionSignal.CONTINUE if no critical findings,
            ExecutionSignal.PAUSE if a critical artifact was detected
        """
        if not self.enabled or not self.gate_on_artifact:
            return ExecutionSignal.CONTINUE
        
        if not result:
            return ExecutionSignal.CONTINUE
        
        # Scan for critical artifact patterns
        matched_artifacts = []
        for compiled_pattern, description in self._compiled_patterns:
            match = compiled_pattern.search(result)
            if match:
                matched_artifacts.append({
                    "pattern": description,
                    "match": match.group(0)[:100],  # Truncate long matches
                    "tool": cmd_name,
                })
        
        if matched_artifacts:
            artifact_summary = "; ".join(a["pattern"] for a in matched_artifacts[:3])
            if len(matched_artifacts) > 3:
                artifact_summary += f" (+{len(matched_artifacts) - 3} more)"
            
            self._last_gate = ExecutionGate(
                reason=f"Critical artifact(s) found: {artifact_summary}",
                signal=ExecutionSignal.PAUSE,
                trigger="artifact",
                context={
                    "tool": cmd_name,
                    "artifacts": matched_artifacts,
                    "total_matches": len(matched_artifacts),
                }
            )
            self.logger.warning(f"🚧 GATE [artifact]: {self._last_gate.reason}")
            return ExecutionSignal.PAUSE
        
        return ExecutionSignal.CONTINUE
    
    def get_gate_reason(self) -> Optional[ExecutionGate]:
        """Return the most recent gate event, or None if no gate was triggered."""
        return self._last_gate
    
    def inject_feedback(self, feedback: str):
        """Store user feedback to be injected into the next prompt iteration.
        
        This mirrors OpenCode's CorrectedError pattern where the user can
        reject a tool call but provide guidance for the next attempt.
        
        Args:
            feedback: User's text feedback / correction
        """
        self._pending_feedback = feedback
        self.logger.info(f"User feedback injected: {feedback[:100]}...")
    
    def consume_feedback(self) -> Optional[str]:
        """Consume and return pending user feedback (if any).
        
        Returns:
            The feedback string, or None if no feedback pending.
            Feedback is cleared after consumption.
        """
        feedback = self._pending_feedback
        self._pending_feedback = None
        return feedback
    
    def reset(self):
        """Reset all internal state for a new execution loop."""
        self._repetition_tracker.clear()
        self._last_gate = None
        self._pending_feedback = None
        self.logger.debug("Gatekeeper state reset")
