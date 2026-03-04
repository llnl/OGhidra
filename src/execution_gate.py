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
    
    # Investigation tools that should be exempt from doom-loop detection
    # These are read-only tools that analysts legitimately need to call many times
    # with different parameters during deep analysis
    INVESTIGATION_TOOLS = {
        'get_xrefs_to',
        'get_xrefs_from',
        'get_function_xrefs',
        'decompile_function',
        'decompile_function_by_address',
        'disassemble_function',
        'list_strings',
        'list_imports',
        'list_exports',
        'list_functions',
        'get_function_by_address',
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
            # Skip doom-loop detection for investigation tools (xrefs, decompile, etc.)
            # These tools are meant to be called many times with different addresses/parameters
            # during legitimate deep analysis
            if cmd_name not in self.INVESTIGATION_TOOLS:
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
        exec_history: List[ToolExecution],
        session=None
    ) -> ExecutionSignal:
        """Check AFTER a tool runs. Returns signal if critical artifact found.
        
        Scans the tool result text for patterns indicating critical security
        findings that warrant user attention before the loop continues.
        
        When critical findings are detected, automatically extracts and saves
        structured artifacts to the session knowledge base.
        
        Args:
            cmd_name: Name of the tool that just executed
            result: String result from the tool execution
            exec_history: List of tool executions so far
            session: Optional session memory for auto-populating artifacts
            
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
            # Auto-extract and save artifacts to knowledge base
            if session:
                auto_artifacts = self._extract_artifacts_from_findings(result, matched_artifacts)
                for artifact in auto_artifacts:
                    category = artifact.get("category", "security")
                    key = artifact.get("key", "finding")
                    value = artifact.get("value", "")
                    session.add_knowledge(key, value, category)
                    self.logger.info(f"💾 Auto-saved artifact: [{category}] {key} = {value[:100]}")
            
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
    
    def _extract_artifacts_from_findings(
        self,
        result_text: str,
        matched_artifacts: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Extract structured artifacts from tool results based on matched patterns.
        
        Converts raw security findings into structured knowledge artifacts
        that can be stored in the session knowledge base.
        
        Args:
            result_text: Full tool result text
            matched_artifacts: List of pattern matches with metadata
            
        Returns:
            List of artifact dicts with {category, key, value} fields
        """
        artifacts = []
        
        # Extract addresses mentioned in the result
        address_pattern = r'\b(?:0x)?[0-9a-fA-F]{6,8}\b'
        addresses = re.findall(address_pattern, result_text)
        
        for matched in matched_artifacts:
            pattern_desc = matched["pattern"]
            match_text = matched["match"]
            
            # Categorize based on pattern type
            if "privilege" in pattern_desc.lower() or "token" in pattern_desc.lower():
                category = "privilege_escalation"
                key = f"Privilege_API_{match_text[:30]}"
                value = f"{pattern_desc}: {match_text}"
                
            elif "crypto" in pattern_desc.lower() or "credential" in pattern_desc.lower():
                category = "crypto"
                key = f"Crypto_Finding_{match_text[:30]}"
                value = f"{pattern_desc}: {match_text}"
                
            elif "c2" in pattern_desc.lower() or "ip" in pattern_desc.lower() or "url" in pattern_desc.lower():
                category = "network"
                key = f"Network_IOC"
                value = match_text
                
            elif "shellcode" in pattern_desc.lower() or "injection" in pattern_desc.lower():
                category = "code_injection"
                key = f"Injection_API_{match_text[:30]}"
                value = f"{pattern_desc}: {match_text}"
                
            elif "service" in pattern_desc.lower():
                category = "persistence"
                key = f"Service_Finding_{match_text[:30]}"
                value = f"{pattern_desc}: {match_text}"
                
            elif "debug" in pattern_desc.lower():
                category = "anti_analysis"
                key = f"AntiDebug_API_{match_text[:30]}"
                value = f"{pattern_desc}: {match_text}"
                
            else:
                category = "security"
                key = f"Security_Finding_{match_text[:30]}"
                value = f"{pattern_desc}: {match_text}"
            
            # Add associated addresses if found
            if addresses:
                value += f" | Addresses: {', '.join(addresses[:5])}"
            
            artifacts.append({
                "category": category,
                "key": key,
                "value": value
            })
        
        return artifacts
    
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
